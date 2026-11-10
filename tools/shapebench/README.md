# Shape, cost and detector experiments

This harness collects **real encrypted HTTP/3 UDP datagrams** through an owned
loopback relay. The relay adds 20 ms propagation in each direction and serializes
egress at 8/2 Mbps including 28 IPv4+UDP header bytes per datagram. It records
direction, length and relative time, never ciphertext contents or endpoint
identities. It is controlled network emulation, not a host pcap or a real-DPI test.

`native` is a scripted Go/quic-go H3 application using the same fixture workload
and TLS/QUIC settings. It is not Chrome or a browser population. Proxy modes use
the real SOCKS client and retained virtual streams to reach an HTTP origin.
Each session combines HTTP POSTs, one SSE stream and background download. Each
paired group shares its workload seed; whole groups stay in one data split.

## Recompute existing evidence

Python 3.9+ and NumPy are required. Matplotlib is optional for the plot.

```sh
python3 -m unittest discover -s tools/shapebench
python3 tools/shapebench/analyze.py results/shaping-v03-20261107
python3 tools/shapebench/audit.py results/shaping-v03-20261107
python3 tools/shapebench/plot.py results/shaping-v03-20261107
```

`analyze.py` checks raw file hashes and clock alignment, extracts business-window
features, fits train-only normalized L2=1 logistic regression and evaluates the
held-out groups. It retains application failures/censoring. Full, size-only and
timing/count-only feature sets are fixed. It tests both a p0-trained frozen model
and a separately trained model for each proxy mode. The classification threshold
is above the largest native training score; that is **empirical training FPR=0**,
not a calibrated 1% operating point. Reports include held-out FPR/TPR, Wilson
intervals, paired-group bootstrap AUC and raw held-out scores. With 16 negatives,
zero false positives still has a Wilson upper bound of 19.36%.

`audit.py` adds descriptive paired cost intervals, per-session packet features,
first/subsequent HTTP latencies and process/evidence checks. These diagnostics do
not tune the registered detector. `plot.py` reads these outputs without refitting.
`transfer.py SOURCE TARGET` fits only the source batch's original p0 training
groups and evaluates all target groups without target fitting or normalization.
That cross-batch result is labeled post-hoc and remains separate from the
preregistered within-batch evaluation.

## Collect a new batch

Build local executables without replacing the running client:

```sh
mkdir -p .local/shapebench-bin
go build -trimpath -buildvcs=false -o .local/shapebench-bin/helper ./tools/shapebench
go build -trimpath -buildvcs=false -o .local/shapebench-bin/recognition ./tools/recognition
go build -trimpath -buildvcs=false -o .local/shapebench-bin/pxbench ./cmd/pxbench
```

Provide an independently frozen PROTO-X binary and its expected SHA256. The
script checks that hash and copies all programs into its private run directory
before generating identities or starting trials. It writes the analysis
registration and source hashes before the first trial. The source relationship
of the supplied binary is audited separately; its filename is not proof.

```sh
python3 tools/shapebench/run.py \
  --protox .local/FROZEN-PROTOX --protox-sha256 EXPECTED-SHA256 \
  --proxy-source-commit SOURCE-REVISION \
  --source-manifest .local/PUBLIC-SOURCE-HASH-MANIFEST.json \
  --pxbench .local/shapebench-bin/pxbench \
  --helper .local/shapebench-bin/helper \
  --recognition .local/shapebench-bin/recognition \
  --private .local/shapebench/NEW-RUN --out results/shaping-NEW-RUN \
  --train-groups 24 --heldout-groups 16 --duration 3 --seed-base 20261110 \
  --modes native,p0,ack-p0,ack-p127
```

The default modes remain `native,p0,p63,p127,p255` and do not send new config
fields to historical binaries. `ack-*` modes require a binary that implements
the boolean `ack_coalesce` option; within that batch p0 explicitly disables it.
The same binary, workload, rate and path are otherwise used. Change `seed-base`
for a genuinely new workload family. Group order is sequential train then
held-out; conditions inside each group are deterministically shuffled.

Private CA, token, ECH key, exact configs, local addresses and process logs remain
under ignored `.local/`. Public raw events contain no identifying values. A failed
trial is retained with an error and is excluded from the detector together with
its entire incomplete matched group; the exclusion count remains visible.

## Cost and interpretation

The primary numerator is all observed UDP payload bytes, including handshake,
readiness, application traffic, transport ACKs/retransmissions and closure. The
IPv4 estimate adds 28 bytes per actual datagram. It excludes Ethernet/NIC overhead.
The denominator is received HTTP body + SSE token payload + download content;
HTTP/download content is byte-checked. The helper used for both formal batches
only checked SSE JSON/sequence and counted payload lengths; it did not compare
the payload string. The subsequent helper emits `payload_valid` after checking
the exact fixture payload, and explicitly invalid bytes are excluded. Old data
is marked as unchecked for that property, without retroactive validation. The
denominator excludes requests and inner HTTP/SSE syntax. A normalized cost ratio
must not be called pure protocol overhead. Packet features use only business
start +200 ms through configured end -100 ms. All app outcomes remain in the
latency/failure report; the classifier window is not a filter for successes.

Three-second sessions cannot establish long-run throughput, idle cost or stable
p99 under congestion. Fresh stream opening affects aggregate p99, so the audit
also shows later requests without silently removing startup from the main result.
Native and proxy use different application transport semantics by design. These
results address that explicit comparison only; no VLESS/Hysteria2 or general
browser/DPI conclusion follows.
