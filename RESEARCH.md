# PROTO-X research log

## 2026-11-07 — initial scope

Goal: improve interactive and streaming delivery under a constrained, varying link, with explicit tradeoffs and fair VLESS / Hysteria2 baselines. The repository initially contained no source files or commits.

Working hypotheses (not yet validated): bounded per-flow queues, a shared pacing budget with interactive scheduling, and resumable application sockets across outer-transport replacement may improve experience. Standard TLS / QUIC are preferred cryptographic building blocks. No claim of indistinguishability or general superiority is made.

Deployment secrets and private inventory belong in `.local/`. No production-server changes are planned.
