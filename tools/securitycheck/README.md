# Local security boundary checks

Run from the repository root:

```sh
go run ./tools/securitycheck \
  -private-dir .local/securitycheck \
  -out results/security-new/checks.json
```

The tool generates fresh credentials and starts its own server on numeric loopback addresses. It never connects to configured production or VPS endpoints. The private directory must have owner-only permissions; certificates, tokens, generated configs, and optional server logs stay there. The output JSON contains test outcomes, timings, limits and hashes, without credentials or server addresses.

To exercise a separately built executable:

```sh
go build -trimpath -o .local/protox-security ./cmd/protox
go run ./tools/securitycheck \
  -binary .local/protox-security \
  -private-dir .local/securitycheck \
  -out results/security-binary/checks.json
```

`-binary` changes only the isolated server implementation. Client and record parsing still use the checked-out source. Its SHA-256 identifies the tested executable; observed source hashes do not prove which source produced an arbitrary binary. Run with `-source-root ''` if source files are unavailable at runtime, and retain the binary hash/build provenance separately.

There are 10 checks: certificate pin rejection, invalid token/version/window/session ID rejection, unknown/known session recovery identification, new session creation, oversized HELLO rejection, and the pre-authentication QUIC slot boundary. The negative authentication cases require connection closure; a timeout is a failure. The slot check defaults to 8 retained connections and prompt rejection of the 9th, with a 500 ms deadline. Flags can change the expected slot count and timeouts.

A nonzero exit indicates a failed check or setup error. Successful handshakes do not establish that application bytes survive reconnection. Nine local connections are not a DoS workload. Results are not proof of resistance to passive classification, active probing, production load, or Russian-network interference.

Use a new output path for each run; an explicitly repeated `-out` path is overwritten. The default output path includes a unique UTC timestamp. Temporary private configs remain available for diagnosis; remove only the tool's generated `run-*` directories when they are no longer needed.
