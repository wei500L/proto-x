# CC extension on quic-go v0.65.0

This isolated `research/cc65` prototype keeps upstream quic-go v0.65.0 and adds
an external congestion-controller factory. It imports the same Hysteria
v2.13.0 BBR/Brutal algorithms as the frozen old-fork comparison, while keeping
v0.65's loss adaptation, MTU fallback, native migration, connection-ID, and QUIC
v2 key-update changes. It is an experimental dependency extension, not an
upstream-supported API or a demonstrated performance improvement.

The PROTO-X starting revision is `5d80253d057b5004a3fad77d50ea4ed315eb0b85`.
Application framing, authentication, session replay, scheduler, receive-window
defaults and JSON configuration are unchanged. The main deployment and frozen
old-fork binaries are not replaced by this branch.

## Build and replay

```sh
# In a checkout of research/cc65, with Python 3, Git and Go available:
python3 scripts/research/prepare_cc65.py
go mod download
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags=-X=main.version=0.1.0-research-cc65 -o bin/protox-cc65-darwin-arm64 ./cmd/protox
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags=-X=main.version=0.1.0-research-cc65 -o bin/protox-cc65-linux-arm64 ./cmd/protox
```

Recorded builds used Go 1.27.1, `CGO_ENABLED=0`, and ARM64 v8.0. Unlike the older
frozen comparison, these builds explicitly disable embedded VCS metadata.
The main module's `go.mod` replaces quic-go with `.local/quic-go-v0.65.0`.
Run the preparation script before building a fresh checkout; an unprepared
checkout cannot resolve the experimental API.

The preparation script clones the exact upstream tag, verifies its full commit,
checks the patch SHA-256, applies it, and verifies every modified/added source
file. Re-running is idempotent. It refuses a different base or unrelated local
changes. A fresh clone and a subsequent idempotent run both completed here.
No patch application to a running service is involved.

For an independent source export, the parent source commit is sufficient for
the application patch; the dependency patch is already included in the branch:

```sh
git format-patch --stdout 5d80253d057b5004a3fad77d50ea4ed315eb0b85..research/cc65 > protox-cc65.patch
git archive --format=tar.gz --prefix=protox-cc65/ research/cc65 > protox-cc65-source.tar.gz
```

The source archive excludes executable files, generated dependencies, private
configuration and `.git`. Its extracted directory can run the same preparation
and build commands above; no pre-existing private working copy is needed.

| Artifact | SHA-256 |
|---|---|
| `patches/quic-go-v0.65.0-cc.patch` | `fd0175fc63d7dbe455bf0dcd34d3475fe7776767a0f0bb8aae88c66841cf9125` |
| `bin/protox-cc65-darwin-arm64` | `3b9640e863fb5e3d8d6c6a50bf2c35e55dcf068376c380b3af27770730464faa` |
| `bin/protox-cc65-linux-arm64` | `61e9036c1acb9aee3843e5a0e964c00a8949bc5809b4b8ef162a62ab7888b2f6` |

The executables are 11,146,786 and 10,886,592 bytes respectively. The Darwin
executable ran its version command. Linux was cross-compiled, not executed by
this agent. Runtime memory, CPU and network performance remain unmeasured for
this branch. Executables and private configuration are ignored by Git.

The independent dependency patch applies to upstream commit
`aa265c3fc6489e3bfa8071b333be95e0e887a51d` (v0.65.0). Its pristine module checksum
is `h1:BJQSjdTvLPLmWtaCupUphRbgxgpZhdO/GMpr9Eoe3B4=`. The patch touches 11 files,
including two new test files and a regenerated mock; it does not import the old
fork's general transport changes. Provenance and per-file hashes are in
[`cc65-evidence/dependency-manifest.json`](cc65-evidence/dependency-manifest.json).

## Running experiments

Use the existing private PROTO-X JSON configuration:

```sh
PROTOX_CC=hy-brutal PROTOX_CC_BRUTAL_MBPS=6 \
  bin/protox-cc65-linux-arm64 server -config .local/test/server.json
PROTOX_CC=hy-brutal PROTOX_CC_BRUTAL_MBPS=1.5 \
  bin/protox-cc65-darwin-arm64 client -config .local/test/client.json
```

`PROTOX_CC` accepts `reno` (default), `hy-bbr-standard`,
`hy-bbr-conservative`, `hy-bbr-aggressive`, and `hy-brutal`.
`PROTOX_CC_DISABLE_LOSS_COMPENSATION=true` optionally disables Brutal's original
compensation. The Brutal Mbps value is a local sender target: server for
download, client for upload. The JSON `rate_mbps` remains a separate application
scheduler budget. It is not an exact IP-byte rate limit. Preserve both rate
settings, stream/connection receive windows, workload, and actual outer bytes
when comparing with Hysteria or the frozen old-fork branch.

The hook executes after PROTO-X authentication. Invalid settings fail the QUIC
carrier. If the serialized controller installation fails, `Link.Start()` closes
the link before starting its receiver goroutines. Each custom factory invocation
logs a generation and current datagram size; the initial successful installation
also logs the mode. An outer reconnect invokes the hook on its new connection.

## Controller lifecycle and feedback

`Conn.SetCongestionControlFactory` has a one-entry request queue. Public callers
wait until the connection's existing event loop applies their request or the
connection closes. The loop checks the queue even during continuous traffic,
and processes at most one request per iteration. Packet callbacks, RTT updates,
controller construction and installation therefore execute on the same goroutine.
The extension does not add a controller-pointer mutex around some callbacks.

Both native migration call sites retain the upstream transport reset, then call
the retained factory to construct a fresh selected controller. A reset failure
closes the connection instead of continuing on default Reno. A decrease in
permitted datagram size also creates a fresh controller: the unchanged Hysteria
BBR implementation panics if its existing instance receives a size decrease.
Normal MTU increases use its ordinary setter. The factory receives QUIC's
current safe size, including the server's early 1200-byte limit.

A factory and all controller callbacks must be quick and nonblocking. They must
not synchronously call connection methods, share a controller across connections,
or access retained RTT providers/callback slices from another goroutine. The
API validates nil factories, returned errors, nil interfaces and typed nil
controllers. It does not sandbox arbitrary controller code or catch its panics.

ACK/loss batches include each newly acknowledged in-flight packet and each
transport-declared loss once per nonempty event. They are delivered after RTT
updates and before spurious-loss notifications, including timer-only loss and
loss detected while processing an ACK that acknowledges no outstanding packet.
Numeric ACK data is copied before packet objects are returned to the pool.
Duplicate ACKs, invalid ACKs and stale timers do not repeat accounting. Borrowed
batch slices must not be retained. Public congestion-window statistics are
updated for the external controller as well as qlog's existing observations.

The extension preserves ordinary per-packet callbacks too. Batch algorithms
must avoid counting bytes through both interfaces. Hysteria BBR and Brutal have
stubs for the ordinary ACK/loss callbacks and use the aggregate callback.

### Explicit differences and limits

- **Default Reno:** no external controller is installed, outgoing ECN and
  upstream callbacks remain active, and no batch is allocated. Upstream Reno
  equations and reset code are unchanged. Extra unused queue checks are not a
  claim of byte-identical CPU cost.
- **ECN:** installing any external controller disables outgoing ECN in this
  prototype. The imported algorithms do not respond to CE marks. The peer's
  incoming ECN reporting is not changed. This differs from the older fork's
  interface, which could leave marking enabled with these algorithms.
- **Spurious loss:** v0.65's transport detects spurious loss and adapts its loss
  thresholds. The new optional `SpuriousLossAware` interface forwards rollback
  notifications when implemented. Imported Hysteria BBR/Brutal do not implement
  it, so their congestion state does not receive Reno's rollback behavior.
- **Probes:** PMTU-probe losses are included in batch accounting and carry an
  `IsMTUProbe` marker, but never invoke the ordinary loss callback. This preserves
  the older Hysteria bridge's aggregate accounting. The imported algorithms
  ignore that new marker and can treat such losses as loss samples. Path
  validation probes and ACK-only packets are excluded from in-flight batches.
- **Discarded packets:** key discard, Retry, and packets retired to generate PTO
  probes retain upstream semantics; the extension does not invent congestion
  loss events for them. A batch is an ACK/loss event, not a promise that every
  lifetime packet retirement appears as either an ACK or a congestion loss.
- **Clock and sampling:** monotonic aliases share upstream's actual clock.
  `ReceivedTime` is the local ACK receipt time, not the remote packet arrival
  time. The imported algorithms do not inspect that field. The exported 1 ms
  pacing floor preserves the original algorithm's constant after its upstream
  definition moved in v0.64.
- **Protocol identity:** the wire format, TLS, crypto and supported QUIC
  versions remain v0.65's defaults. There is no new fingerprint or censorship
  resistance claim. BBR here means the pinned Hysteria implementation, not
  equivalence to Linux BBR, BBRv2 or BBRv3.

Eleven Hysteria algorithm/test files are literal import-prefix transformations
from `app/v2.13.0`, commit `ca8fbd874fd6ca82413948de6dc5924405e103e1`.
The twelfth file, `utils.go`, is explicitly replaced with PROTO-X factory glue.
[`internal/hycc/SOURCE.json`](../../internal/hycc/SOURCE.json) records both original
and transformed hashes. Hysteria and quic-go MIT notices are retained; notices
for all five compiled dependency modules and Go are indexed in
`cc65-evidence/dependency-licenses.json`.

## Verification performed

| Check | Observed result |
|---|---|
| Upstream root, ackhandler and congestion packages, `-race -count=1` | 475 top-level tests passed; three existing Linux/GSO-specific tests skipped on macOS |
| Upstream native migration, NAT rebinding, repeated rebinding, PMTU and DATAGRAM MTU tests, `-race` | All five passed |
| PROTO-X full suite, `-race -count=1` | 31 top-level tests passed; includes imported algorithm tests |
| Real QUIC native migration with default Reno, three BBR profiles and Brutal | Each preserved the original bidirectional stream across two path switches and echoed exactly 786,432 bytes; custom modes constructed three controllers on each endpoint |
| Concurrent controller updates during real QUIC traffic | 64 updates and an exact 512 KiB echo passed under the race detector |
| Factory failure on native migration | Both client-side and server-side failure tests closed the connection |
| Authenticated PROTO-X QUIC→TLS recovery, each custom mode, `-race` | All four passed: exact 512 KiB, half-close and a single original target socket |
| Vet | PROTO-X all packages and the modified upstream packages passed |
| Dependency reconstruction | Pristine clone patch application, hashes and a second idempotent run passed |

These are local correctness checks, not a weak-network benchmark. Native
migration tests use actual QUIC streams with instrumented factories; the separate
application recovery tests exercise PROTO-X authentication and target sockets.
No long run, deployment on the VPS, Linux execution, performance comparison or
adversarial transport audit was performed for this branch by this agent.

The first batch-test run contained one failed assertion comparing an empty ACK
slice with nil in the timer-only case. Callback bytes and timing matched; the
test was corrected to assert emptiness. The initial failure is retained in
`cc65-evidence/tests/extension-first.jsonl`, alongside subsequent passing data.
Raw Go build-info output retains its original trailing tab characters.

Commands to repeat the relevant checks:

```sh
go test -race -count=1 ./...
PROTOX_CC=hy-brutal PROTOX_CC_BRUTAL_MBPS=6 go test -race -count=1 ./internal/app -run '^TestQUICToTLSRetainsOriginAndBytes$'
# Repeat that application check with each hy-bbr-* mode.
cd .local/quic-go-v0.65.0
go test -race -count=1 . ./internal/ackhandler ./internal/congestion
go test -race -count=1 ./integrationtests/self -run 'Test.*(Migration|Rebinding|MTU)'
```

All test JSONL, summaries, binary metadata, licenses and patch provenance are in
`cc65-evidence/`. The next useful experiment is a controlled v0.65 Reno versus
v0.65 BBR/Brutal comparison with identical receive windows and rate budgets.
Do not combine old-fork and v0.65 results as if only the congestion algorithm
changed: transport fixes, lifecycle, ECN treatment and MTU feedback differ.
