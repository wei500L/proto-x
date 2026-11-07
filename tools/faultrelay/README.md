# Local UDP fault relay

A standard-library-only Go fixture for forwarding one local UDP client to an
owned test endpoint. It injects either a bidirectional blackout or a change to
the upstream socket's source port. It does not parse or modify QUIC payloads.
No root privileges, firewall changes, or network administration capabilities are
required. Only the primary project agent operates remote test hosts.

```sh
go build -trimpath -o bin/faultrelay ./tools/faultrelay
go test -race -count=1 -v ./tools/faultrelay

bin/faultrelay \
  -listen 127.0.0.1:16660 \
  -target test-endpoint.example:33287 \
  -fault blackhole -after 6s -for 8s -duration 25s \
  -events results/fault-example/blackhole.jsonl
```

Set the test client's UDP endpoint to `127.0.0.1:16660`. Preserve its original
server identity, TLS certificate pin, and authentication configuration. Start
the client after the relay's `start` event appears. The target address above is a
placeholder; use only a test endpoint you control or are authorized to test.

For an upstream socket change, use `-fault rebind` with the other flags unchanged.
`-for` is ignored for this mode. The client-facing listener stays open while the
relay opens a replacement connected UDP socket, switches forwarding, and closes
the old socket. Opening the replacement first ensures a different local source
port. The endpoint's observed external port can additionally depend on NAT; this
fixture does not simulate an IP address change, a new route, or server failure.

For `blackhole`, packets arriving in **both directions** are discarded during the
window and normal forwarding resumes afterward. There is no packet replay or
userspace traffic queue. The blackout begins after `-after`, measured from ready;
its restore timer starts when injection actually begins. The event timestamps
record actual transitions, including scheduling delays. `-duration` caps the
overall lifetime, so a late or interrupted blackout can end at shutdown.

## Bounds and client behavior

- The listener must use a numeric loopback address. Wildcard addresses, hostnames,
  and public bind addresses are rejected. Port `0` requests an ephemeral port,
  reported as `listen_port` in the start event.
- The first eligible client datagram binds a single client IP. A new source port
  from that **same IP** replaces the sole current client address and emits
  `client_switched`; this allows local QUIC reconnection. A different client IP
  is dropped. There is no multi-client address table or connection-ID routing.
  Two simultaneous clients sharing the same loopback IP would repeatedly take
  over one another's return traffic: dedicate the relay port to one experiment.
- The upstream socket is connected to the chosen target, so the kernel accepts
  replies only from that endpoint. Target DNS is resolved at startup; rebinding
  uses that same resolved address.
- `-max-datagram` defaults to 2048 bytes and accepts `1..65507`. Larger payloads
  are discarded without forwarding a truncated prefix. Each receive goroutine
  has one 64 KiB buffer to count complete ordinary UDP payloads; a truncated
  datagram is always dropped. One additional receive buffer can briefly exist
  while replacing the old socket. Socket buffers are requested at 64 KiB;
  actual kernel allocation can differ. Writes have a 100 ms deadline.
- A blackhole must fit within the requested lifetime. Durations and limits are
  validated before sockets are created. Both `SIGTERM` and `SIGINT` close all
  relay sockets, join receive loops, write the final counters, and sync/close the
  event file. Natural duration expiry follows the same cleanup path. No system
  network state is changed, so the fault does not survive process exit.

## Events and evidence

`-events PATH` creates a **new** JSONL file and refuses to overwrite existing
evidence. Parent directories are created as needed. The file mode is `0600`.
Use `-events -` (the default) for stdout. Events are written directly without a
userspace buffer; a file is synced on orderly shutdown. I/O failures return a
nonzero exit code using fixed error categories instead of network error strings.

Events are `start`, `client_bound`, `client_switched`, `fault_start`, `fault_end`,
and `end`. Every event includes `elapsed_ns` from Go's monotonic elapsed clock,
`upstream_generation`, and a counter snapshot. A rebind event also records the
previous and new **local source ports**. Neither target addresses, client IPs,
credentials, nor packet contents are logged.

`counters.up` means client → target; `counters.down` means target → client. Each
direction has `received`, `forwarded`, and `dropped` packet/byte totals. Drop
reasons are disjoint: `blackhole`, `oversize`, `foreign_client`, `no_client`,
`stale_socket`, and `write_error`. `read_errors` counts socket read failures.
`truncated_packets` identifies any incomplete kernel receive; if nonzero, byte
counts for those received/dropped datagrams are lower bounds. Ordinary UDP
datagrams fit in the receive buffer and have exact payload-byte counts. Header
overhead, remote packet delivery, and losses before the relay are not measured.

An interrupted blackhole emits `fault_end` with
`reason: "shutdown_before_restore"`; this means the relay closed, **not** that a
usable forwarding path was restored. A normal `end` reports either `duration` or
`context_cancelled` (including SIGTERM/SIGINT). A forced kill cannot flush final
state. Preserve the absence of a complete `end` event as an incomplete run.

For UDP-to-TCP fallback experiments, leave the independent TCP path outside this
relay and separately record which transport carries the application stream.
Forcing UDP loss alone does not prove that a session resumed correctly. This
fixture also adds forwarding and socket overhead: use it consistently for the
protocols being compared, and measure that overhead before attributing a small
latency difference to a protocol.

## Local verification

`main_test.go` exercises owned UDP echo endpoints: exact datagram preservation
(including zero-length payloads), same-IP client-port handoff, timed bidirectional
blackhole and recovery, source-port change observed by the origin, oversize drops
in both directions, lifetime cleanup, option validation, and a real subprocess
SIGTERM during a blackout with complete final counters. It checks monotonic
events, packet/byte conservation, and absence of target addresses in the logs.

The different-source-IP test requires a second usable loopback source address.
It explicitly skips when the host cannot bind `127.0.0.2`, as on the development
Mac; it does not report that case as a pass. An initial 16 KiB oversize test was
rejected by macOS before reaching the relay (`EMSGSIZE`); its payload was reduced
to 4096 bytes, still larger than the tested 1200-byte limit and the default.
These checks validate the fixture. They are not WAN measurements or evidence of
PROTO-X's recovery performance.
