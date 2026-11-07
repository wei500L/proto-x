# Recognition tooling: local fixture verification

Date: 2026-11-07. This is a real macOS loopback experiment with an ordinary H2/H3 website and a user-space forwarding relay. **No candidate proxy traffic was used.** It validates the observation path, not recognition resistance or Russian-network performance.

The ordinary server uses `cover.Site` directly with the candidate's exported TLS/QUIC options and matching HTTP listener/window limits. The client validates a generated local CA, expected name and an additional leaf pin. No trust-store change is made. Private names, certificates, keys, pins, binary copies, commands, topology mappings and observed bytes remain under `.local/recognition/`.

| Completed run | HTTP responses H2 | HTTP responses H3 | Decoded ClientHellos | Tool outcome |
|---|---:|---:|---:|---|
| `recognition-smoke-20261107-01` | 22/22 | 21/22 | 52/52 | One H3 timeout; 10 Initial AEAD failures on that flow |
| `recognition-smoke-20261107-02` | 22/22 | 22/22 | 52/52 | Passed after explicit UDP backend bind |
| `recognition-smoke-20261107-03` | 44/44 | 44/44 | 104/104 | Passed; four rounds and explicit topology/reflection checks |

All runs also attempted two legacy cases per round and transport. In run 03, the eight deliberately offered old custom-ALPN handshakes were rejected; eight old bare-record attempts over standard ALPN produced zero response bytes and connection/stream termination. These deliberately invalid requests are retained separately from the ordinary HTTP response denominator. The old-ALPN offers appear in the capture by design, not because a new native client sent them.

Run 03 completed 97 fixture checks. All 88 HTTP cases returned the expected ordinary-site status, completed within the configured deadline and had a verified certificate chain. All 104 ClientHellos decoded. There was no captured-prefix truncation, no Initial inspection error and no byte-identical server UDP data reflected into the observed client direction. All 52 backend UDP local ports were distinct. This is short functional evidence, not a long-running reliability result.

In run 01, observed server Initial payloads reappeared byte-for-byte in the client direction on the timed-out flow. The parser correctly refused to authenticate those packets with client Initial keys. The controlled relay was changed from implicit UDP local allocation to an explicit bind, and subsequent runs added private topology mappings. The anomaly did not recur in runs 02/03. Port allocation/reflection in the all-loopback relay remains the suspected explanation; a passing follow-up alone does not establish its exact operating-system cause. The failed run has not been deleted or folded into the successful counts.

Eleven Python checks passed after run 03: six parser checks, including published RFC 9001 and RFC 9369 keys/Initial packets, and five comparison checks. They cover AEAD failure, truncated data, TLS fragmentation, CRYPTO range reassembly/conflicts, missing and duplicate sample indices, retained failures and body differences. Published vectors are marked separately from live socket observations in `tools/recognition/testdata/SOURCES.json`.

The Go probe build records its actual runtime/module versions and executable SHA in each observation report. `smoke.json` records the binary SHA and all check results. `source-manifest.json` records the tooling source at the end of this run; later tool edits can be distinguished from these executed observations. Runtime binary copies and exact commands are preserved privately.

Next evidence needed: run identical active cases on the real candidate and the same ordinary fixture; capture successful native proxy traffic separately; test genuine ECH acceptance separately from extension presence; then use diverse cover traffic and independent evaluation before making a broader identification claim.
