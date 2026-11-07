# PROTO-X research log

## 2026-11-07 — initial scope

Goal: improve interactive and streaming delivery under a constrained, varying link, with explicit tradeoffs and fair VLESS / Hysteria2 baselines. The repository initially contained no source files or commits.

Working hypotheses (not yet validated): bounded per-flow queues, a shared pacing budget with interactive scheduling, and resumable application sockets across outer-transport replacement may improve experience. Standard TLS / QUIC are preferred cryptographic building blocks. No claim of indistinguishability or general superiority is made.

Deployment secrets and private inventory belong in `.local/`. No production-server changes are planned.

## 2026-11-07 — runnable v0.1 and actual evidence

- Stable implementation commit `5d80253`: resumable session sockets over official quic-go v0.65.0 / TLS 1.3; bounded sparse scheduler. The default quic-go sender selects **Reno**, not CUBIC.
- Authorized small VPS deployed as `protox.service`, with both transports. Existing SSH and reference services preserved; production server not used. Private SSH alias/config/key and deployment files live under `.local/`; see `docs/deployment.md` for entry points.
- Actual QUIC workload, real SSH, 8-second UDP blackhole (same SSH stream, max gap2.77s), and source-port rebind (same QUIC connection and SSH, max gap356ms) completed. Server-restart counterexample also completed: old SSH fails; HTTP147/150, three explicit failures, new requests recover, SSE reconnects. Paths: `results/vps-*20261107/`.
- Completed600s cold-HTTP/SSE/download observation: HTTP3000/3000, echo5610/5610;11995SSE tokens/one connection,53 gaps>250ms, none>1s; no process restart. Core v0.1 only; not day-long stability.
-60-second no-application idle observation: UDP payload978B/s, estimated IPv4+UDP1373B/s across both directions, including startup/shutdown. This motivates removing redundant default server-initiated probes while preserving client probe/server reply and failure thresholds. Changes are not yet included in the completed evidence.
- Parser fuzz completed60s, two workers,14,080,954 executions, no failure (`results/verification-20261107/wire-fuzz.json`).

## Baselines and mechanism results

- Official pinned Xray26.10.31 VLESS/REALITY/Vision and Hysteria2.13.0 (BBR standard/conservative; Brutal8/2 and6/1.5), hashes and controlled fixtures available.
- First complete matrix plus repair: `results/discovery-20261106T224522Z/`. Hy Brutal6 is an important counterexample: weak-link HTTP/echo/SSE tails and goodput better than v0.1 PX. No overall superiority claim.
-19-run source-pacing/multi-background ablation: `results/mechanism-ab-v01-20261106/`. Priority improves some HTTP/echo p95 values under six downloads, but HTTPp99/SSE can regress. Source pacing alone explains part of the apparent latency gains.
- Old Hy QUIC fork CC study: branch `research/cc`, commit `a7a33341984ac60354aca6425c561d3b902e9c63`; archived patch `research/patches/cc-hy-fork.patch`. Do not deploy this old fork as the stable transport. It differs in72files from its base and lacks140 later upstream commits; it also resets custom CC on migration.
- CC seeds211/223: `results/cc-screening-20261106/`. BBR/Brutal improve PX goodput but not interactive tails. Window diagnostic seed227:64/128/256KiB gives3.634/5.165/5.505Mbps with Brutal6, no p95 improvement. Default window unchanged.
- Sparse-copy study: branch `research/hints`, commit `9b60c69f28c675576a5f61af31669cdc58519448`; archived patch `research/patches/sparse-copies.patch`. Official quic-go0.65; optional delayed DATAGRAM copies, same total pacing budget, separate limited receive queue. Reliable originals, byte offsets and ACKs remain authoritative.
- Sparse-copy correctness: race/vet suite, actual QUIC datagram path, active-copy QUIC→TLS recovery, and deterministic hint-first ACK/retained-socket/half-close test passed.40ms is pre-submission age only; upstream DATAGRAM queues have no hard expiry. Client shutdown counter logs may be missing in frozen builds.
- Hint training seeds311/313: unpaced results are mixed, not a stable win. Source2.5Mbps311 has local echo/SSE improvements with equal goodput;313 is pending. A5%loss/1Mbps source scenario seed317 is predeclared and pending. Seed307 remains reserved for independent validation.

## Earlier coordination checkpoint (superseded below)

- Primary owns main source, VPS, README/report/research archive. Current stable deployment has private targets disabled; temporary fixture has now been stopped. Test clients can be restarted from `.local/vps/client.json`; don't publish `.local`.
- `network_lab` owns VM/network profiles and matrix wrappers during ongoing experiments. It is finishing hint source-pacing311/313, then predeclaredloss5 seed317, and will coordinate holdout307. Do not disturb its VM or frozen binaries.
- `baselines` owns `.local/cc65-prototype`: small public CC bridge on official v0.65, controller factory retained across native migration, serialized updates, stock Reno path preserved; integration checks and replay packaging ongoing. No VPS changes.
- `workloads` finished protocol/deployment/measurement docs and independent hint review/testing. No active shared-file changes now.
- Main docs are `README.md`, `docs/PROTOCOL.md`, `docs/RESULTS.md`, `docs/deployment.md`, `docs/workloads.md`, `docs/security-review.md`.
- Before final delivery: complete chosen held-out checks, finish source/patch/data index and confidentiality scan, run appropriate final checks, commit remaining public files, verify service/client usability and update the exact deployment state. No claims of anti-DPI, multi-day stability, or recovery of sockets from a dead server process.

## 2026-11-07 — completed experiments and current handoff

- Deployed mainline version is now `0.1.1-experimental`, with client-led heartbeats, server probes after half a failure window of silence, and active server RTT probes when adaptive is enabled. This preserves the original failure threshold while reducing ordinary idle exchanges. Client shutdown now cancels pending HELLO/WELCOME I/O, waits for the management loop, and closes the final published session before returning. It does not join every SOCKS handler or immediately discard the remote retained session.
- Full race suite and vet passed for this revision; actual TLS cancellation tests also passed 10 repetitions. Overlaying only the old client implementation reproduced the pending-handshake leak at the return boundary. Idle liveness, either silent direction and unequal heartbeat settings have focused session tests. Evidence: `results/verification-v011-20261107/`.
- Mainline idle follow-up completed60.214s: one QUIC carrier, zero application flows,425 packets,37931UDP payload bytes. Estimated IPv4+UDP827.57B/s versus prior1373.45B/s (39.7% lower); this includes startup/shutdown and is not mobile energy or a repeated-path statistical study.
- New mainline blackhole recovery completed: original SSH220/220 lines, maxgap2708.73ms; HTTP150/150; echo257/258 with one end censor; SSE598tokens/one connection, maximum2608.97ms, onegap>1s. `results/vps-blackhole-v011-repair-20261107/`. The earlier attempt's incorrect test-harness SSH key alias prevented authentication; all original data and the reason remain in `results/vps-blackhole-v011-20261107/`. The helper now derives the trusted management key name and checks it before running, with strict verification.
- Hint discovery finished15trials. The predeclared307 holdout completed exactly three90s measurements at5%bidirectional random loss,60ms nominalRTT,8/2Mbps and common1Mbps background source budget. On versus off: HTTPp95−18.3%, echop95−21.6%, outerbytes+11.4%, goodput−1.2%. On versusHy: echop95−16.4%, HTTPp95 only−1.5%; median latency, SSE tails and outer cost remain worse. HTTP1350/1350; echo776/777,838/839,819/820, all differences end censoring. **307 is consumed**, not available as an unseen seed again.
- Complete source/patch/replay index: `research/README.md`. Hints, old-fork CC and official0.65CC bridge all have source archives and independently reproduced frozen LinuxARM64 hashes. CC65's Linux binary has not been executed or performance-tested; its correctness checks ran on macOS. No research patch has been merged into the deployed core. No .local directory is needed to reconstruct public sources.
- Final public SOCKS HEAD to `https://example.com/` returned200. Client listens at127.0.0.1:1088 and is attached by QUIC; start/stop and private config are in `docs/deployment.md`. The exact deployed server/client hashes, point-in-time resource values, final service state and probe are in `results/deployment-v011-20261107/final-state.json`.
- Test VPS has private targets disabled, no temporary pxbench fixture, and protox/xr/sb active. Management SSH and production server were preserved. Pre-v0.1.1 rollback backup: `/opt/proto-x/backups/20261106T235030Z`; complete private deployment record: `.local/vps/deployment-v011.json`. The local client PID/log live in `.local/vps/`; validate the PID's command before stopping it.
- The dedicated Lima lab VM has been stopped after all data were copied back; no experiment is still running. `scripts/lab/vm.sh start` plus the namespace init workflow in `docs/lab.md` restores the lab. Source worktrees remain under `.local/`; public branches and archives preserve them independently.
- Next useful research: hard expiry or nonblocking admission inside QUIC's DATAGRAM queue; reduce redundancy cost while retaining the observed sparse-response benefit; examine burst loss/capacity changes and common whole-system byte budgets with new held-out seeds. Combining v0.1.1 with hints/CC requires new checks and measurements. Multi-day use, real Russian mobile paths and anti-identification remain unverified.

Public results preserve failed configurations, adverse measurements, censoring and source identities. Earliest v0.1 builds lack a Git revision; their recorded hashes and source summaries remain authoritative. Do not rewrite them as exact builds of the later baseline commit or relabel old measurements as v0.1.1.

## 2026-11-07 — delivery verification

- Added `docs/vps-experiments.md` with runnable idle, soak and fault workflows, fixture prerequisites, trusted SSH host-key handling and cleanup. The document is linked from the README and deployment guide. Its commands were checked statically; writing it did not run another VPS experiment.
- Strengthened the restart harness to require a nonempty, correct SSH prefix with output before the restart request and a successful restart command. Offline replay found 54 lines before the historical restart request (56 lines in total); nine counterexamples were rejected. Evidence: `results/verification-v011-20261107/fault-evidence-check.json`. New-request recovery still requires separate application-event inspection. Historical measurements and their source hashes were not rewritten.
- Final packaging checks cover Python/Shell syntax, local Markdown links, whitespace and sensitive-data scanning of public files plus unpacked source archives. Exact scope and results are in `results/verification-v011-20261107/delivery-checks.json`. The scan checks known private values and key/credential patterns; it is not a security audit of the protocol.
- This delivery includes the v0.1.1 source fixes and all completed comparative measurements. Deployed binaries were built before this final Git commit from the recorded working-tree sources; use their recorded SHA-256 values rather than assuming a clean post-commit build has identical embedded VCS metadata. No external Git push is part of this delivery.
