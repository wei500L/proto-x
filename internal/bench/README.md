# pxbench: controlled application workloads

This standard-library Go tool creates controlled target services and drives them
through an **explicit SOCKS5 endpoint**. It does not use macOS system proxy
settings, environment proxy variables, external websites or local target DNS.
`-proxy direct` exists for fixture self-tests and must be labelled as direct.

```sh
go build -o bin/pxbench ./cmd/pxbench
bin/pxbench serve -http 127.0.0.1:18080 -echo 127.0.0.1:18081
bin/pxbench run -proxy 127.0.0.1:1080 \
  -http-target http://127.0.0.1:18080 -echo-target 127.0.0.1:18081 \
  -duration 30s -rps 5 -background 1 -uploads 0 \
  -run-id example-run -output .local/results/example-run.jsonl
```

Targets are interpreted from the **proxy server**, not from the benchmark
client. In a namespace lab, put the fixtures behind the server side of the
impaired link. Keep workload traffic separate from the SSH management path.
Fixtures bind loopback by default; bind a lab address explicitly when needed.

For HTTPS (useful to exercise VLESS Vision with real inner TLS traffic):

```sh
bin/pxbench serve -http '' -https 127.0.0.1:18443 \
  -cert .local/fixture.crt -key .local/fixture.key -echo 127.0.0.1:18081
bin/pxbench run -proxy 127.0.0.1:1080 \
  -http-target https://127.0.0.1:18443 -ca .local/fixture.crt \
  -duration 30s -run-id https-example -output .local/results/https-example.jsonl
```

The fixture certificate must include the target IP/name in its SAN. The optional
`-insecure-tls` flag is explicit and recorded; prefer the trusted fixture CA.
Clients use HTTP/1.1 so different HTTP connection pools cannot silently change
the transport experiment. A service prefix in `-http-target` is supported only
when a controlled reverse proxy forwards that prefix to these fixtures.

## Workloads and interpretation

- Small HTTP requests arrive on an open-loop schedule. Defaults are 5 requests/s,
  1024-byte verified responses, a 3-second deadline and a 64-request concurrency
  cap. Scheduling delay and scheduled-to-completion latency are retained. Cap
  rejections are recorded instead of silently shedding load. `-cold-http` disables
  keepalive to include connection establishment on every request.
- The small fixture defaults to **POST with no side effects**. Go's HTTP client
  will not replay this method after request bytes were written. A connection can
  still be retried if zero bytes were written. `-http-method GET` enables a webpage
  style workload and normal idempotent retries; raw `http_connection` and
  `http_write` events and per-operation attempt counts expose both modes.
- Echo sends a sequence-tagged, verified 64-byte payload on one persistent TCP
  stream. It has at most one outstanding operation and is explicitly **closed
  loop**. `-echo-interval 100ms` sets the minimum start interval. A failure ends
  the old socket; the next operation creates and records a new socket. It never
  silently resends a failed echo request. This stream tests whether a proxy can
  preserve the original socket across outer-carrier interruption.
- SSE has a default 50-ms source schedule. Each token contains a per-connection
  sequence, scheduled time, actual production time and deterministic payload.
  Both scheduled and actual times also include monotonic elapsed nanoseconds
  relative to that source connection; source gaps and production delay use
  these elapsed fields, so NTP/wall-clock changes cannot become false stalls.
  A dedicated producer is independent of response writes for up to 256 tokens;
  overflow is an explicit source error. Client receipt gaps, source production
  gaps and positive excess gaps are retained. Differences of timestamps within
  each host's monotonic clock do not need synchronization; **one-way delivery latency is not
  inferred**. A new source after reconnection restarts at sequence 0, and the
  cross-connection receipt gap is annotated. The timeout also serves as SSE
  inactivity timeout.
- `-background N` opens N unlimited downloads with a fixed, validated byte
  pattern. `-uploads N` adds repeated uploads (default 256 KiB each), verified
  by the source. Upload goodput counts only server-confirmed completed chunks;
  the final unacknowledged chunk is excluded and reported as unfinished. These
  figures are application bytes, not encrypted outer-wire bytes.

`-background-mbps 6` requests source-side pacing at 6 Mbps **per download worker**.
The source uses 4 KiB chunks, flushes each chunk, and does not accumulate credits
during blocked writes. The first chunk can be sent immediately. Apply the same
setting to every protocol when measuring the generic benefit of reducing bulk
load. This is not a cap on proxy wire traffic: interactive traffic, acknowledgments,
encryption, retransmission and other overhead are outside this source budget.
Multiple background workers each get the specified rate; `-background-mbps 0`
leaves the source unlimited. The actual delivered rate can be lower because of
timer granularity, application backpressure or network capacity.

Set `-rps 0`, `-echo-interval 0`, `-stream-interval 0`, `-background 0` or
`-uploads 0` to disable a workload independently. Use the same workload settings
for every protocol and keep all source/proxy versions fixed in the run manifest.

## Evidence and limits

Every run writes `name.jsonl` and `name.summary.json` (or `-summary path`) with
mode 0600 and refuses to overwrite an existing file. JSONL retains run metadata,
each HTTP/echo result, SSE token and connection events, per-second download
counts, per-transfer completion and final run tail. Output locations should be
private until endpoint metadata has been redacted.

Each operation has one status: `success`, `failure`, `timeout`, `censored` (the
overall run ended) or `rejected` (the generator cap). Success distributions use
nearest rank `ceil(p*N)` and include their sample count; the status denominator
always includes every recorded request. p99 from ten samples is simply the
maximum and must not be presented as statistically stable tail evidence.

Censoring and next-operation scheduling check the run's monotonic deadline in
addition to `ctx.Err()`: a socket deadline can expire before Go publishes context
cancellation. Every raw event also has `recorded_elapsed_ns` from a monotonic
clock. Wall-clock jumps therefore do not create false request timeouts, trigger
extra requests after the run, or enter SSE source-gap calculations.

SSE receipt gaps above 250 ms/1000 ms are counted. Per-connection terminal gaps
and the final run-wide tail (`sse.run_tail_gap_ms`, including failed reconnects)
are right-censored and reported separately. Do not add completed and terminal
gap counts as though they were independent events. A successful idle token
cannot remove a preceding failure from the raw log. Source errors and sequence
errors must invalidate claims of reliable delivery.

This tool does **not** shape IP packets, emulate TCP packet loss, measure outer
wire overhead, prove DPI resistance, or independently capture proxy RSS/CPU.
Use the namespace/netem lab and external packet/resource counters for those
measurements. Direct fixture smoke tests prove only harness operation.

Tests cover RFC 1928 address encoding, rejection of unsupported authentication,
byte-pattern corruption, upload integrity, SSE schedule/sequence, failure and
censoring denominators, no-overwrite evidence, and a mixed-workload run whose
HTTP/SSE/upload/download/echo connections are verified through a test SOCKS5
server. Run `go test -race ./internal/bench ./cmd/pxbench`.
