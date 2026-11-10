# Recovery laboratory

This fixture runs actual PROTO-X H2/H3 clients and servers. It never replays
unknown HTTP requests to hide a transport failure. HTTP uses the benchmark's
side-effect-free POST, echo retains one socket until an actual failure, and SSE
checks per-source sequence numbers. The instrumented origin additionally logs
target connection IDs, so a client reconnect cannot be mistaken for same-target
continuity. Credentials and raw proxy logs remain under `.local/`.

## Two measurement scopes

- `recoverybench` on macOS uses a UDP datagram relay and a TCP **byte-chunk**
  relay. UDP delays/drop are real datagrams, but TCP read chunks are not IP
  packets. This mode provides one-process fixture/injection timestamps and
  simple application continuity checks. It is not a wire-rate experiment.
- `scripts/lab/run-v03-matrix.py` stages frozen binaries into the project-owned
  Lima VM. Linux namespaces and `tc netem` apply propagation, bandwidth, queue,
  and loss to actual shared IP traffic. Every variant uses the same workload,
  instrumented origin, and external link. The harness records hashes, actual
  veth qdisc frame bytes, fault counters, CPU/RSS, and startup/warmup separately.

The old `netlab.py block-udp` uses an OUTPUT firewall hook, which can report a
local `EPERM` to UDP senders. That is useful only as a local send-error test; it
does **not** represent a silent path blackhole. The v0.3 matrix therefore installs
its own **INPUT** drop on the receiving namespace. For an upload-only blackhole,
only server INPUT is blocked; both-sided tests block both receivers. Cleanup
touches only the task-owned `protox_fault` tables. Dropped packet counters are
saved before removal. SSH and host network configuration are not involved.

## Reproduce the packet experiment

Build a fixed fixture and freeze both protocol executables before beginning.
Record source hashes and toolchain alongside binary hashes; the candidate must
not be rebuilt midway through a matrix.

```sh
mkdir -p .local/recovery-example
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -ldflags='-s -w' -o .local/recovery-example/recoverybench-linux-arm64 \
  ./tools/recoverybench

python3 scripts/lab/run-v03-matrix.py \
  --baseline .local/v03/baseline/protox-linux-arm64 \
  --candidate .local/v03-20261110/causal-candidate/protox-linux-arm64 \
  --fixture .local/recovery-example/recoverybench-linux-arm64 \
  --run-id recovery-example \
  -- --seeds 501 502 503 --variants v02 joint causal probe-only fixed \
  --profiles healthy high-rtt blackhole up-blackhole pulse \
  --duration 16 --warmup 3 --fault-after 5 --fault-for 6

python3 tools/recoverybench/analyze_net.py results/recovery-example \
  --out results/recovery-example/analysis.json
```

`fixed` is the candidate in legacy recovery mode with 100 ms heartbeat / 400 ms
dead interval; `v02` is the genuine frozen old binary with 500 / 2000 ms settings.
`no-prepare` keeps the adaptive detector and removes the prepared alternate.
This ablation does not hold sampled RTT histories identical, so individual
trial differences cannot by themselves attribute a benefit to preparation.
`age` and `count` compare time-aged versus count-history RTT samples, while
`age-no-prepare` removes preparation from the aging policy. `causal` and
`probe-only` both use count history, padding127, and ACK coalescing off; only
`probe-only` disables causal DATA/OPEN delivery evidence. `joint` combines
count-history adaptive recovery, causal evidence, TLS preparation, ACK coalescing
and padding0, so its comparison to `v02` measures the entire bundle. Configurations
and source/binary hashes are recorded in each trial and manifest. Delivery-proof
traces add events to the causal variant; their instrumentation cost was not
separately ablated.
The `xray-vision` and `hy-bbr-standard` references use the same HTTPS workload;
Hysteria has no TCP standby here, so blackhole comparisons have unequal fallback
capability and must be reported as such.

The fixture's standalone mode can be used without a proxy for inspection:

```sh
go run ./tools/recoverybench -fixture -fixture-http 127.0.0.1:18443 \
  -fixture-echo 127.0.0.1:18081 -fixture-log .local/target-events.jsonl
```

Add `-fixture-cert` and `-fixture-key` for HTTPS. Terminate with SIGTERM to close
all owned target sockets and flush logs.

## Interpreting the evidence

`proxy-events.json` records sanitized client/server log receipt with the VM's
absolute monotonic clock. Firewall events use that same clock, so fault →
suspect → prepare → commit → attach does not need cross-host clock correction.
Receipt timestamps remain upper bounds on the internal event; session-local
`mono_ns` is retained for within-process intervals. Do not add overlapping
preparation and confirmation waits twice.

Application events retain their own benchmark monotonic epoch. The analyzer
accepts a wall/monotonic bridge only when both measured offset spreads and the
epoch check are small. If a VM wall clock steps, it marks the bridge invalid and
omits fault-to-application-success arithmetic. Application receipt gaps,
timeouts, target IDs, and the proxy critical path remain independently valid.
Go's RFC3339 nanosecond fractions are parsed without epoch-size float rounding.
New matrix runs also bracket the benchmark epoch directly: it must begin after
process launch and before the first persisted `run_start` event is observed,
minus that event's recorded monotonic elapsed time. Bounds narrower than 20 ms
permit fault→application receipt **intervals** despite wall-clock steps, without
modifying the common frozen workload. A new POST is guaranteed to start after
the fault only if even the lower epoch bound plus its fixed-rate sequence
schedule is later than injection. Queueing can delay that request, never advance
it. Bounds and uncertainty are kept in the result rather than collapsed to an
apparently exact timestamp.

The first reply after fault injection may have already been in flight. The
analyzer therefore labels receipts after attachment and records the largest
nearby gap; it never calls the first surviving packet recovery time. Success
percentiles exclude failed operations, but timeout/failure/censoring counts
remain beside them. SSE terminal gaps are censored, not silently discarded.

Each trial is one independently restarted proxy session. Tokens or HTTP requests
within the same session do not create independent recovery repetitions.
Short windows and a few seeds cannot establish population p99, rare false
switch rates, mobile energy cost, or resistance to deployed DPI.

Calibrate byte-counter interpretation only while the owned namespaces are idle:

```sh
scripts/lab/vm.sh copy tools/recoverybench/counter_audit.py \
  protox-lab:/tmp/protox-counter-audit-v03.py
scripts/lab/vm.sh shell sudo python3 /tmp/protox-counter-audit-v03.py
```

The expected one-packet result in each direction is 142 qdisc bytes for a
100-byte UDP payload: IPv4+UDP adds28 and the Ethernet header adds14. Extra
traffic makes this tiny calibration inconclusive. Once results are copied out,
inspect `ip netns pids` for each owned namespace and stop the dedicated VM with
`scripts/lab/vm.sh stop`; the ignored staging directory remains available.
