# Security boundary evidence — 2026-11-07 Moscow time

All checks used isolated macOS arm64 loopback servers. No VPS, production service, or external target received test traffic. JSON files contain no authentication material or deployment addresses.

| Artifact | UTC execution time | Meaning |
| --- | --- | --- |
| `initial-checks.json` | 2026-11-06T22:32:19Z | Original 10/10 independent checks, before packaging the reusable tool. |
| `initial-source-sha256.json` | Associated with the original check | Full SHA-256 values recorded for the six reviewed source files; these identify the observed files, not a Git commit or reproducible build. |
| `tool-source-checks.json` | 2026-11-06T22:41:12Z | Reusable tool, in-process current-source mode; 10/10. Includes its observed source hashes. |
| `tool-binary-checks.json` | 2026-11-06T22:42:10Z | Reusable tool against a separately built Darwin arm64 server executable; 10/10. Includes the tested binary SHA-256 and source observations. |

The external binary was built with:

```sh
go build -trimpath -o .local/securitycheck/protox ./cmd/protox
go run ./tools/securitycheck \
  -binary .local/securitycheck/protox \
  -private-dir .local/securitycheck \
  -out results/security-20261107/tool-binary-checks.json
```

Its SHA-256 was `05d334d472885777698fb051f33a7d533b814876a72af229ff72b1da0c6a58af`. This is a locally built executable, not necessarily the VPS-deployed binary. The source tool command and flags are in [`tools/securitycheck/README.md`](../../tools/securitycheck/README.md).

These are the same ten scenarios across three executions, not thirty independent security properties or a statistical reliability study. Negative authentication tests in the reusable tool require remote closure; a timeout is a failure. The initial temporary harness used the broader condition “read returned an error” for some authentication negatives. Its original results are retained unchanged, and the stronger tool checks are reported separately.

The source tree evolved during development. Keep each result with its own recorded hashes; do not assign later clock/recovery changes to the original execution. Source hashes alone cannot retrieve an older uncommitted source snapshot, and checking arbitrary external binaries does not establish their source provenance. No full historical source snapshot or independent reproducible build was archived for the original temporary harness.

No latency comparison, long-run stability, active-probe camouflage or DoS resistance follows from these boundary checks.
