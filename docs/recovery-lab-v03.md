# v0.3 recovery laboratory: dated evidence

2026-11-10. These are controlled Linux packet experiments, not measurements of a
Russian access network or deployed DPI. The first frozen recovery candidate is
based on `e4c93d9` plus the adaptive path monitor, prepare/activate split,
and monotonic resume-attempt fence. Its Linux arm64 SHA256 is
`ca01adda919df5a0670b9510152d7557b792e735bb0b956166cf7c17f3a701e1`;
the genuine v0.2 baseline is
`a5855444ee5c45bd667cc4c9f8fd69f83dc648166199809d2b63ae5d70351679`.
Source hashes, a source tarball, and matching local binaries are retained in
`.local/v03-20261110/candidate/`. This candidate predates later version-label,
default-padding, ACK, and diagnostic-accounting changes. Discovery experiments
explicitly set padding127; the final `joint` bundle below uses padding0 and ACK
coalescing. Later frozen build hashes are stated with their experiments. No
results are silently relabelled as a later build.

## An invalid older blackhole experiment was found

The inherited `net-v03-v02-pilot-20261107` trace detached H3 approximately 49 ms
after the fault-install command began. Its firewall used local OUTPUT DROP.
Linux can return a send error (`EPERM`) for such locally dropped UDP, so this
experiment does not establish silent network-blackhole recovery latency. It is
retained as historical evidence, not included in the following comparison.

The new runner drops at the **receiving INPUT hook**. Bidirectional faults use
both receivers; an upload-only fault uses server INPUT. Sender UDP writes are
not directly failed by a local firewall rule. Real nft packet/byte counters are
saved before cleanup; every silent pilot actually dropped traffic in the
specified direction. The shared `tc netem` link still sees and budgets those
packets. This distinction prevents local send errors from looking like a fast
failure detector.

## Measurement conditions

The project-owned Lima VM runs two Linux network namespaces and a shared veth
link. Offloads are disabled. The link is 8 Mbps down / 2 Mbps up with a nominal
75 ms queue allowance and 100 ms RTT in blackhole/pulse tests, 60 ms in healthy
tests, 500 ms with 20 ms per-direction jitter in high-RTT tests. See each profile
for actual `tc` commands and seed support.

All variants use the same frozen workload binary and instrumented HTTPS origin:
5 cold POSTs/s, 100 ms persistent echo, 50 ms SSE, a 2 Mbps source-paced background
download, and a 3 s application timeout. Each trial independently starts client,
server, and target, warms up for 3 s, then measures for 16 s. Fault installation
starts 5 s into measurement and lasts 6 s; a pulse lasts 200 ms. Firewall command
completion brackets add a measured installation/removal interval and are not an
exact single-packet onset timestamp. All padding, probes, standby traffic,
retransmissions, and workloads share the same actual external link. Warmup and
startup are recorded separately.

- `v02`: frozen original, heartbeat500 / dead2000 ms.
- `fixed`: candidate in legacy mode, heartbeat100 / dead400 ms.
- `adaptive`: bounded RTT history, matched-PONG bidirectional evidence,
  demand-sensitive probing, prepare a TLS/ECH-validated alternate when suspect,
  and commit only after the second threshold and alternate readiness.
- `no-prepare`: same adaptive detector, but discard the old path before a cold
  alternate dial. Actual sampled histories can differ, so one trial is not a
  paired deterministic ablation of preparation alone.

Target-side connection IDs supplement client-side counts. A same-stream SSE
result requires one client connection, one target request/socket, positive
received tokens, and zero sequence/source errors or unexpected ends. Echo also
requires one target accept and no timeout/failure. Termination tails are
censored; generated events after test shutdown are not claimed delivered.

## First silent-blackhole pilot

[Raw run](../results/net-v03-silent-pilot-20261110/manifest.json),
[audited analysis](../results/net-v03-silent-pilot-20261110/analysis-final.json).
Each cell below is **one session**, not a population percentile.

| Variant | Fault→client attach | SSE largest gap | HTTP success/total | HTTP timeout / censored | Same SSE target | Same echo target |
|---|---:|---:|---:|---:|---|---|
| v02 | 2882 ms | 3619 ms | 75/80 | 3 / 1 | no | no |
| adaptive | 1459 ms | 1643 ms | 78/80 | 0 / 2 | yes | yes |
| fixed400 | 873 ms | 1260 ms | 78/80 | 0 / 2 | yes | yes |
| no-prepare | 819 ms | 1009 ms | 79/80 | 0 / 1 | yes | yes |

The v0.2 client detached 2461 ms after the installation began and reattached
421 ms later. This is consistent with fixed silence detection/tick phase plus
the manager wait and cold H2 establishment. It does not identify the older VPS
3.23 s result as a QUIC PTO. The pilot records ordinary HTTP timeouts and SSE
application reconnection when transport recovery misses the application deadline.

The adaptive timeline separates concurrent and serial work:

| Event | Milliseconds from fault install begin |
|---|---:|
| Suspect, 26 RTT samples, threshold 620.36 ms | 730.83 |
| Begin TLS/ECH preparation | 730.93 |
| Prepared alternate ready | 945.21 |
| Second-threshold confirmation; commit | 1355.11 |
| HELLO/WELCOME activation ready | 1458.37 |
| Client attached | 1458.76 |

Preparation's 214 ms overlaps the confirmation wait. It must not be added on
top of the full fault→commit interval. Every observed prepared/activated TLS
connection in this candidate reports accepted ECH; the raw trace retains ALPN,
TLS version, and acceptance booleans from the actual carrier connection.

## A limitation exposed by the pilot

Adaptive was slower than fixed400 and no-prepare in this single trial. Its
26-sample history was mostly 101–107 ms, but contained earlier 205.6, 210.0, and
332.0 ms queue/transport samples. The last approximately 3.9 s before the fault
had no such slow samples. The rule `p90 + 4*(p90-p50)` still produced a 620 ms
threshold. A larger threshold also slows probing, so old samples are forgotten
more slowly. No-prepare happened to have 32 samples and a 204 ms threshold.

This is a measurable stale-history/feedback limitation, not evidence that TLS
preparation intrinsically costs more than cold dialing. A time-limited or
decaying history and longer warmup are natural next controlled comparisons.
The current result alone does not justify claiming an algorithmic win from
preparation. The high-RTT test is needed to evaluate the cost of simply using
400 ms everywhere.

## Healthy, high-RTT, short-pulse, and one-direction pilot

[Raw run](../results/net-v03-discrimination-pilot-20261110/manifest.json),
[analysis](../results/net-v03-discrimination-pilot-20261110/analysis-final.json).
Again there is one session per cell. With a 60 ms healthy RTT, all four variants
completed 79/80 POSTs (one run-end censored, zero failures/timeouts), kept the
same SSE and echo targets, and never switched. SSE maximum gaps were 55–59 ms.

| 500 ms RTT, no injected outage | HTTP success/80 | Timeout / failure / censored | Carrier switches | SSE same target |
|---|---:|---:|---:|---|
| v02 | 72 | 0 / 0 / 8 | 0 | yes |
| adaptive | 70 | 0 / 0 / 10 | 0 | yes |
| no-prepare | 71 | 0 / 0 / 9 | 0 | yes |
| fixed400 | 0 | 7 / 73 / 0 | 6 | no successful SSE |

Shortening every timeout to 400 ms is therefore not an equivalent robust
replacement for RTT adaptation. The fixed setting cannot maintain this healthy
long-RTT path. The application-level censored operations in the other rows were
in flight when the fixed 16 s measurement ended and are not silently counted as
successes. This does not establish that the adaptive policy has the best normal
tail latency; it establishes a failure mode in the simplistic timeout baseline.

| 200 ms UDP loss pulse | Carrier switches | Prepare / canceled | SSE largest gap | HTTP success/80 |
|---|---:|---:|---:|---:|
| v02 | 0 | 0 / 0 | 395 ms | 79 |
| fixed400 | 0 | 0 / 0 | 395 ms | 79 |
| adaptive | 1 | 4 / 3 | 437 ms | 79 |
| no-prepare | 1 | 0 / 0 | 975 ms | 79 |

All pulse rows had zero HTTP timeout/failure and one run-end censored operation,
and retained the same SSE/echo target sockets. The adaptive policies nevertheless
switched unnecessarily on this brief disturbance. A 200 ms loss pulse can cause
a longer reliable-transport recovery, so a 300 ms confirmation criterion can
still be too eager. Preparation limited the interruption in this trial but
opened multiple short-lived TLS alternates. That traffic and the false switch
are costs, not hidden successes. Additional repetitions are required before
comparing rates of such events.

In the upload-only blackhole, v02 had 75/80 HTTP successes (three timeouts, two
censored) while adaptive/fixed/no-prepare each had 79/80 (only one censored).
All kept the same target SSE and echo connections. SSE maximum gaps were 806 ms
(v02), 265 ms (adaptive), 757 ms (fixed), and 588 ms (no-prepare). Downstream data
can continue while uplink requests/ACK progress is broken; a single `lastRX`
timer is therefore not sufficient evidence of bidirectional health. This also
shows that HTTP timeout and SSE interruption need not move together.

## Repeated old-policy blackholes

Two additional sessions per variant were run with independent process restart
and schedules. The [combined n=3 analysis](../results/net-v03-silent-repeat-20261110/analysis-final.json)
includes the pilot rather than quietly replacing it.

| Variant | Attach median [range], ms | Per-session SSE maximum gap median [range], ms | HTTP success / timeout / failure / censored, total240 | SSE same target |
|---|---:|---:|---:|---:|
| v02 | 2865 [2865–2882] | 3619 [3604–3619] | 224 / 10 / 2 / 4 | 0/3 |
| count-history adaptive | 1448 [505–1459] | 1643 [696–1649] | 235 / 0 / 0 / 5 | 3/3 |
| fixed400 | 873 [864–965] | 1149 [1048–1260] | 235 / 0 / 0 / 5 | 3/3 |
| no-prepare | 819 [643–1570] | 1009 [827–1792] | 237 / 0 / 0 / 3 | 3/3 |

Echo kept the same target in 3/3 of each candidate configuration and 0/3 of
v0.2. This confirms a transport-continuity improvement under the tested
blackhole, but it does not establish a superiority of preparation over cold
dialing: threshold histories are visibly variable. The sample is too small for
credible population p99 or a narrow false-switch confidence interval.

## Time-aged history: same-binary ablation did not show a clear win

The next frozen candidate (`4d2efb2ecd3cf856a94bb87ac351a174a999b243b68c46c1fe8a1e58e948a9c8`,
Linux arm64) made RTT aging an explicit experimental variable. The age window is
`max(2 s, 8×historical median RTT)`, anchored at the latest matched reply; it
retains at least three samples. Silence cannot itself clear history or lower a
threshold. `count` uses the original last32-samples history on that same binary.
[Raw run](../results/net-v03-age-ablation-20261110/manifest.json) and
[analysis](../results/net-v03-age-ablation-20261110/analysis-final.json) cover two
independent sessions for each of three settings and three profiles (18 trials).

| Same binary | H3 blackhole attach, ms | H3 blackhole SSE max gap, ms | 200 ms pulse switches | 500 ms healthy RTT switches |
|---|---|---|---:|---:|
| age + prepare | 476 / 1668 | 556 / 1880 | 1/2 | 0/2 |
| count + prepare | 529 / 1453 | 724 / 1513 | 0/2 | 0/2 |
| age without prepare | 756 in the only exposed trial | 1069 in that trial | 1/2 | 0/2 |

All 18 trials had zero HTTP failure/timeout, with end-of-window censoring retained,
and kept the same target SSE/echo socket. However, one age-without-prepare trial
switched to H2 **before** the planned blackhole. Only one of its two trials was
actually exposed on H3; its 557 ms maximum gap is not a blackhole recovery result.
The analysis reports `carrier_at_fault`, pre-fault switches, and the exposed
denominator so this cannot be counted as a fast recovery.

The age policy's slow blackhole trial received fresh evidence of a roughly
200 ms control-path delay just around injection, making its threshold 669 ms.
Retaining genuinely recent congestion evidence is appropriate; the result is
not a reason to force every threshold downward. Across this small end-to-end
ablation, age has no demonstrated overall advantage over count and incurred one
pulse switch versus none for count. It remains a useful experimental mechanism,
not a supported universal default improvement.

The pre-fault false switch produced a more informative next hypothesis. A PING
sent 303.6 ms before commit had no timely matching PONG, but echo seq28 completed
103.9–111.9 ms before commit with a 106.8 ms RTT, entirely after that oldest PING
was sent. A POST also completed 107.8–115.8 ms before commit, after suspicion had
begun. SSE continued until 24.2–32.2 ms before commit. Thus live application
roundtrips were available while the control stream alone looked stalled.
ACK/OPENED progress can potentially supply causal path evidence, provided it
confirms bytes or OPEN sent after the pending probe in the same carrier
generation; old in-flight ACKs and ordinary downstream DATA are insufficient.

## Causal DATA/OPEN evidence: final same-binary experiment

The final core adds bounded, generation-aware send markers. An advancing ACK
or first OPENED may establish a lower bound on a real send time, rather than
pretending its receive time proves a fresh roundtrip. Cross-generation replay
and previously sent ranges are excluded. This can limit apparent probe age
without inventing RTT samples. A stale proof cannot cancel a pending preparation
and restart its cooldown. `recovery_probe_only=true` disables this evidence for
the comparison; both variants explicitly retain count-based RTT history,
padding127, and ACK coalescing off.

The frozen Linux binary is
`00d7ed43943d53e58554ac01fa6b138e3117d078ed8f51a4c49c59e0ae7ecea4`.
[Manifest](../results/net-v03-causal-final-20261110/manifest.json),
[final analysis](../results/net-v03-causal-final-20261110/analysis-final.json)
cover 20 trials: two settings × five profiles × two independently restarted
sessions. Both variants had zero HTTP failure/timeout and retained the same
target SSE and echo sockets in **10/10 sessions each**. Causal traces contained
2429 delivery-proof events, including warmup, so the integration was exercised.
Neither variant switched before fault injection; every UDP-fault trial was
actually using H3 at injection.

The causal variant also writes those extra diagnostic events. The runtime cost
of proof tracking versus proof-event logging was not separately ablated, so the
resource samples do not estimate the isolated cost of the causal mechanism.

| Profile, 2 sessions each | Causal HTTP success / censored (160 total) | Probe-only success / censored | Causal switches / probe-only switches |
|---|---:|---:|---:|
| healthy60ms | 158 / 2 | 158 / 2 | 0 / 0 |
| healthy500ms | 141 / 19 | 141 / 19 | 0 / 0 |
| both-direction blackhole | 156 / 4 | 158 / 2 | 2 / 2 |
| upload-only blackhole | 157 / 3 | 157 / 3 | 2 / 2 |
| 200ms pulse | 156 / 4 | 157 / 3 | 2 / 0 |

The result **does not prove a lower false-switch rate**. Both causal pulse
trials switched, while both probe-only trials waited through the disturbance.
Causal SSE gaps were 382–397 ms versus 417–452 ms for probe-only, so the extra
switch did not produce a larger application stall in these two trials, but its
connection churn remains a cost. Healthy60ms had zero preparations for both;
healthy500ms had zero for causal and one canceled preparation for probe-only.
That small difference is not a rare-event rate estimate.

Both-direction blackhole attachment took 1105/1642 ms with causal evidence and
519/1000 ms with probe-only. The reconstructed pre-fault thresholds were
419/674 ms and 150/405 ms respectively; the actual suspicion/commit thresholds
are retained per trial. Preparing H2 took about 214 ms in all four, and
commit→attach took 104–109 ms. Thus threshold histories are a visible source of
the difference. A closed-loop algorithm changes its future observations; this
small experiment cannot isolate every cause or claim causal evidence is faster.

Upload-only blackholes still triggered real H3→H2 recovery in both causal
trials (569/1491 ms); continued downstream DATA and old ACKs did not keep the
broken uplink alive indefinitely. The corresponding SSE maximum gaps were
233/248 ms with causal and 249/459 ms with probe-only. This supports the tested
directional safety/continuity semantics, not a universal optimal detector.

Deterministic session tests cover the control-only-stall counterfactual. The
network harness cannot selectively drop encrypted PONGs while passing every
other flow, and does not claim to have done so. Time aging and causal progress
remain explicit research mechanisms with negative findings preserved; adaptive
recovery remains opt-in pending stronger evidence.

## Final joint bundle versus frozen v0.2

The final Linux binary above was also tested with count-history adaptive recovery,
causal DATA/OPEN evidence, TLS preparation, ACK coalescing, and padding0 (`joint`).
The genuine `e4c93d9` baseline uses its original padding127 and heartbeat500 /
dead2000 policy. This is an end-to-end **bundle** comparison, not attribution of
the gain to any one mechanism. Both use the same 8/2 Mbps link budget, workload,
frozen origin and benchmark, and independent process restarts.

[Blackhole manifest](../results/net-v03-joint-blackhole-20261110/manifest.json),
[healthy manifest](../results/net-v03-joint-healthy-20261110/manifest.json), and
[combined final analysis](../results/net-v03-joint-healthy-20261110/analysis-final.json)
cover three blackhole sessions and one healthy session per setting. The final
[source manifest](../results/net-v03-joint-healthy-20261110/candidate-source-manifest.json)
records the frozen code. Every blackhole trial began on H3, with no prior switch.

| Blackhole, n=3 each | Joint | v0.2 |
|---|---:|---:|
| Fault→attach median [range], ms | 459 [436–504] | 2859 [2851–2862] |
| Per-session SSE max gap median [range], ms | 579 [505–660] | 3612 [3611–3620] |
| HTTP success / timeout / failure / censored, total240 | 237 / 0 / 0 / 3 | 223 / 12 / 0 / 5 |
| Same target SSE / echo | 3/3 / 3/3 | 0/3 / 0/3 |
| Echo success / timeout / failure / censored | 432 / 0 / 0 / 3 | 286 / 1 / 2 / 3 |
| Per-trial successful HTTP p95 median, ms | 615 | 2303 |
| Qdisc frame bytes median | 5,726,779 | 6,101,976 |
| Background goodput median, Mbps | 1.872 | 1.860 |

Joint retained the original target SSE and echo sockets, with zero SSE sequence
or source errors and no application reconnect. v0.2 required application-level
reconnection; zero sequence errors within each new SSE source cannot establish
continuity across those sources. Finite-window tails remain censored. These
echo results are not newly measured SSH sessions, and the historical VPS 3.23 s
pause cannot be decomposed exactly from these laboratory traces.

The joint critical path is directly logged (all values from fault-install begin):

| Phase | Three-session range, ms | Interpretation |
|---|---:|---|
| Fault→suspect | 115–185 | 150 ms threshold, 32 recent matched-PONG samples |
| Prepare start→TLS/ECH ready | 213–215 | Overlaps the second-threshold wait |
| Commit→client attach | 105–106 | Prepared carrier activation and HELLO/WELCOME |
| Attach→first new carrier progress | 102–103 | Subsequent receive progress |
| Fault→first new carrier progress | 538–607 | Whole observed interval, not a sum of overlapping phases |

The firewall command itself had a 38–51 ms installation bracket. Probe age
predates injection and is not equivalent to fault duration. In all three trials,
TLS preparation took longer than the remaining confirmation wait, so commitment
followed alternate readiness immediately. Every observed preparation and
activation reported ECH accepted. The earliest completed POST provably scheduled
after injection was in 980–988, 1007–1015, and 1055–1064 ms intervals. Request
creation, destination TLS, and application processing add work beyond carrier
attachment; these completion bounds must not be called transport recovery time.

The one healthy60ms trial per setting provides a limited regression check:

| Healthy, n=1 each | Joint | v0.2 |
|---|---:|---:|
| HTTP success / timeout / failure / censored, total80 | 79 / 0 / 0 / 1 | 79 / 0 / 0 / 1 |
| Successful HTTP p95, ms | 209 | 211 |
| SSE max gap, ms | 65 | 57 |
| Echo success/total | 159/159 | 159/159 |
| Qdisc frame bytes | 5,653,993 | 6,448,407 |
| Background goodput, Mbps | 1.882 | 1.888 |
| Client / server CPU, % of one core | 5.31 / 4.93 | 4.87 / 5.37 |
| Client / server sampled peak RSS, MiB | 15.96 / 18.20 | 16.11 / 16.30 |

Both retained the same target sockets, with zero preparation or switch. The
joint bundle used 12.3% fewer measured frame bytes in this healthy trial, but
healthy tail-latency improvement is not established. Resource samples include
diagnostics, and one 16 s window cannot establish long-term RAM or CPU costs.
The joint bundle still needs the pulse/high-RTT matrix itself repeated: the
causal-only matrix above demonstrates that unnecessary switches remain a real
limitation, not something the strong blackhole result erases.

## External protocol references under the same link budget

[Reference run](../results/net-v03-reference-20261110/manifest.json),
[analysis](../results/net-v03-reference-20261110/analysis-final.json): one trial per
protocol/profile, same fixture and link, Xray 26.10.31 REALITY + Vision and
Hysteria2 2.13.0 BBR standard. HTTPS payloads actually traverse the tunnel;
REALITY's owned TLS destination and Hysteria's CA validation are configured.

| Reference/profile | HTTP success / timeout / failure / censored (80 total) | SSE max gap | SSE same target | Qdisc frame bytes during workload |
|---|---:|---:|---|---:|
| Hysteria, healthy | 79 / 0 / 0 / 1 | 91 ms | yes | 4,845,861 |
| Xray, healthy | 79 / 0 / 0 / 1 | 55 ms | yes | 5,257,496 |
| Hysteria, UDP blackhole | 43 / 20 / 15 / 2 | 9916 ms | no | 3,549,474 |
| Xray, UDP blackhole | 78 / 0 / 0 / 2 | 55 ms | yes | 5,227,152 |

Hysteria in these configurations has **no H2 standby**, while Xray uses TCP and
is unaffected by a UDP-only block. These are capability/context comparisons,
not equal-fallback evidence or a general claim that PROTO-X outperforms either
protocol. Lower Hysteria bytes during failure reflect lost application service
and do not imply better efficiency. Successful-only latency, failures, goodput,
resources, target counts, and startup costs are all retained in the analysis.

## Counter-layer correction

A direct calibration on the otherwise idle namespaces sent one 100-byte UDP
payload each direction. Each qdisc counted exactly one packet and **142 bytes**:
100 payload + 8 UDP + 20 IPv4 + 14 Ethernet header. Thus these veth qdisc counters
measure Ethernet-frame bytes without FCS, not pure IP bytes. The separate 24-byte
per-packet `netem rate` overhead affects shaping and is not included in the
reported byte counter. [Calibration](../results/recovery-counter-audit-20261110/audit.json)
and [reproduction tool](../tools/recoverybench/counter_audit.py) retain this check.
The executable tool was then run independently on the idle namespaces and
[passed the same calibration](../results/recovery-counter-audit-20261110/audit-script-validation.json).

Earlier analyses' `per_trial_wire_ip_bytes` key and “IP bytes” notes were an
incorrect layer label. The underlying counters and comparisons are unchanged;
corrected analyses use `per_trial_qdisc_frame_bytes`. Do not combine these
counters with payload-only relay bytes without converting to the same layer.

## Clock and interpretation limits

Proxy log receipt and firewall events use the same VM absolute monotonic clock.
Their critical-path intervals above are therefore valid without a wall-clock
bridge; log receipt is an upper bound on the emitting event. Session-local
monotonic timestamps are retained separately.

The VM wall clock stepped during these experiments (about 136 ms at a time).
The analyzer correctly rejected the global wall/monotonic bridge for the pilot,
so it does **not** report fabricated fault→first-application-success durations.
Application gap/timeout statistics use the workload's own monotonic clock and
remain valid, as do target connection identity and proxy-stage durations. A
first reply just after fault installation can also be an already-in-flight
reply; it must not be labelled recovery even with synchronized clocks.

The first `analysis.json` records a Python 3.9 parser failure on Go's 9-digit
RFC3339 fraction. The fixed parser preserves exact nanoseconds and timezone
offsets; the successful initial analysis is `analysis-v2.json`. Both are retained.
`analysis-final.json` additionally corrects counter-layer labels and adds
exposure/proof fields while preserving measured values.

Starting with the age ablation, the harness also brackets the workload's epoch
using process launch and the first persisted monotonic event. All 18 age-trial
bounds were 6.7–9.0 ms wide. They do not depend on the wall clock and permit
fault→application timing intervals. For example, the 476 ms-attach age trial
received its first post-attach SSE event at 574–582 ms and completed its first
POST provably scheduled after injection at 1041–1049 ms. The slower 1668 ms-attach
trial had the corresponding intervals 1898–1906 ms and 2282–2290 ms. These are
application observation intervals, not additional serialized transport phases.

TLS preparation does not send speculative HELLO or replace the original
Session. Activation does: the server can attach the candidate before the client
receives WELCOME. Consequently activation failure is not a guarantee that the
old carrier remains usable. Monotonic resume attempts prevent delayed old
candidates from rolling the server back; byte offsets and target sockets provide
transport continuity while that live server Session still exists.

Tool entry points and full reproduction commands are in
[tools/recoverybench/README.md](../tools/recoverybench/README.md). These short
trials do not establish rare false-switch rates, mobile energy cost, long-term
resource behavior, or resistance to real DPI.

## Cleanup and retained state

All result directories above were copied back to the workspace. The final
namespace inspection found no PIDs in either `px-client` or `px-server`.
`scripts/lab/vm.sh stop` completed, and `status` reported the project-owned
`protox-lab` VM stopped on 2026-11-10 at 12:41 Moscow time. Frozen binaries,
source manifests, private configuration and raw logs remain in ignored staging
for reproduction; no VPS or production service was changed by this laboratory.
