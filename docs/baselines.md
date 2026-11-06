# Reproducible reference protocols

The first PROTO-X baseline fixtures use official release binaries and real SOCKS5 traffic. They are not reimplementations or substitutes for the reference protocols. The version check and loopback interoperability checks below were performed on 2026-11-07 local time (Europe/Moscow).

| Baseline | Pinned version | Release commit / date | Configurations |
| --- | --- | --- | --- |
| Xray-core, VLESS + REALITY + Vision | `v26.10.31` | `a4a3dff`, 2026-10-31 | RAW/TCP, Chrome uTLS fingerprint, Vision, no mux |
| Hysteria2 | `app/v2.13.0` | `ca8fbd874fd6ca82413948de6dc5924405e103e1`, 2026-10-05 | BBR standard, BBR conservative, Brutal |

Official binaries for Darwin arm64, Linux amd64, and Linux arm64 were downloaded and checked against the SHA-256 digests in the official GitHub release API. The pinned URLs, archive hashes, binary hashes, and sizes are in [`versions-20261107.json`](../scripts/baselines/evidence/versions-20261107.json). This proves consistency with the published release assets; it is not an independent reproducible-build audit. Geo databases are not extracted because these fixtures use no GeoIP/GeoSite rules.

## Fetch and configure

Run from the repository root:

```sh
python3 scripts/baselines/download.py
python3 scripts/baselines/configure.py \
  --server 192.0.2.10 \
  --xray-port 33400 --hysteria-port 33401 \
  --socks-xray 10801 --socks-hysteria 10802 \
  --server-directory /opt/proto-x/baselines \
  --out .local/baselines/config
```

`--server` is the client's destination. `--listen` is the server bind address. They can differ. The example address is reserved documentation space. Ports must match authorized mappings. `--platform linux-arm64` can restrict the download.

The generator creates random VLESS credentials, a REALITY X25519 key pair and short ID, Hysteria authentication, and an ECDSA TLS certificate. All generated material is restricted to an ignored `.local` directory with private file permissions. It reuses existing credentials so repeating configuration does not invalidate a deployed pair. Use a new output directory when changing the certificate SNI. The Hysteria client verifies the generated certificate through `tls.ca`; no insecure TLS bypass is used. Copy only the needed server JSON, `tls-cert.pem`, and `tls-key.pem` to the private server directory. The client JSON and CA certificate stay with the client.

The default REALITY target is `www.cloudflare.com:443`. A controlled experiment should normally replace it with an owned TLS endpoint so target reachability and target handshake behavior are documented:

```sh
go build -o .local/baselines/tlscover scripts/baselines/tlscover.go
.local/baselines/tlscover \
  -listen 127.0.0.1:39443 \
  -cert .local/baselines/config/tls-cert.pem \
  -key .local/baselines/config/tls-key.pem
```

Generate with `--reality-target 127.0.0.1:39443 --reality-sni protox-baseline.test` for that target. The cover helper is a genuine Go HTTPS server with TLS 1.3 and X25519. It is an experimental fixture, not evidence of traffic indistinguishability. Cross-compile it with `GOOS=linux GOARCH=arm64 go build ...` for the lab VM or `GOARCH=amd64` for the test VPS.

Run one server/client pair at a time on the small VPS:

```sh
xray run -test -c xray-server.json
xray run -c xray-server.json
xray run -c xray-client.json

hysteria server --disable-update-check -c hysteria-server-bbr-standard.json
hysteria client --disable-update-check -c hysteria-client-bbr-standard.json
```

Replace `bbr-standard` with `bbr-conservative` or `brutal` for the other pairs. The filenames are JSON; the upstream config loader supports JSON as well as YAML. BBR and Brutal cannot be selected by merely changing the name of the file: both server and client must load the intended matching configuration.

For localhost or private experimental origins, explicitly add a precise allowed range:

```sh
python3 scripts/baselines/configure.py \
  --server 10.203.0.2 --out .local/baselines/lab \
  --allow-test-cidr 127.0.0.1/32
```

Xray `v26.10.31` has default `freedom` final rules that can blackhole private destinations for 30–90 seconds. The generator's `--allow-test-cidr` option adds a TCP `finalRules` allow for the supplied range; it is repeatable. These explicit exceptions are for owned test origins. Do not mistake the default destination block for congestion, DPI, or a protocol failure. General deployment configs leave upstream defaults intact.

## Congestion-controller interpretation

The exact v2.13.0 source was inspected, not inferred from older documentation:

- `congestion.type` accepts `bbr` and `reno`. BBR profiles are `standard` (default), `conservative`, and `aggressive`.
- Nonzero negotiated bandwidth activates **Brutal**, overriding the BBR choice for that sending direction. Merely setting `congestion.type: bbr` beside `bandwidth` does not ensure BBR is in use.
- The generated BBR pairs omit `bandwidth`; the server also sets `ignoreClientBandwidth: true`. Thus both directions use the selected BBR profile. A shared external limiter is needed for a common bandwidth budget.
- The generated Brutal pair specifies client upload/download and the inverse server limits. Initial values are 2/8 Mbps. `--up` and `--down` change them. Loss compensation is enabled by default; `--disable-loss-compensation` supplies a separate diagnostic configuration.
- Brutal's configured application budget is not a hard outer-byte cap: protocol headers and loss compensation consume additional wire traffic. Report goodput and outer bytes separately, and enforce any claimed common wire budget outside the proxies.
- Kernel `tcp_congestion_control=bbr` changes TCP, not Hysteria's userspace QUIC congestion control. The reference BBR label here means Hysteria's pinned implementation, not a claim that it is equivalent to every other BBR version.

Hysteria fast open is disabled in these fixtures so a failed target connection is observable before application writes are accepted. TCP-only SOCKS5 operation matches the initial PROTO-X scope. UDP proxying, obfuscation, padding, realm traversal, and extra mimic modes are outside this first controlled comparison. Default QUIC receive windows and MTU discovery are retained. A later small-memory tuning group should record every window change and compare it separately rather than silently weakening the reference.

## Fair comparison requirements

1. Use the same kernel namespace path, bottleneck, delay, queue, MTU, loss process, controlled origins, workload seeds, and measurement intervals. Run the protocols sequentially and rotate their order across repeated seeds. The VPS is too small for a concurrent benchmark contest.
2. Include ordinary reference configs and reference configs with the same useful generic pacing/bandwidth/queue limits. A constrained physical link is not by itself an equal offered-load or equal outer-byte budget. Record actual qdisc counters and transmitted bytes.
3. Keep the response timeout and stream lifetime identical; report every offered request, success, timeout, and interruption. Tail quantiles from successes alone need accompanying failure counts. Record stalls using source production timestamps so intentional token pacing is distinguishable from transport stalls.
4. Separate fresh connection establishment, a warm persistent session, and recovery of an already open application connection. Xray starts a separate outer TCP connection per application flow in this configuration; Hysteria multiplexes independent streams in a QUIC connection. PROTO-X connection pooling and session retention are mechanisms with different resource and failure costs, not automatically unfair configuration choices.
5. No throughput, latency, anti-detection, or Russian-network superiority follows from the interoperability smoke test below.

## Executed validation and fixture corrections

```sh
python3 scripts/baselines/smoke.py
```

The script starts a controlled 8192-byte HTTP origin, an owned TLS 1.3 REALITY target, and each actual client/server pair on loopback. Every curl request is forced through the relevant SOCKS5 listener with `--noproxy ''`; responses are checked byte for byte. Each pair is stopped before the next runs. Xray server and client JSON also passed the binary's `run -test` command.

| Configuration | Exact responses / offered requests |
| --- | --- |
| Xray VLESS + REALITY + Vision | 3 / 3 |
| Hysteria BBR standard | 3 / 3 |
| Hysteria BBR conservative | 3 / 3 |
| Hysteria Brutal, 2/8 Mbps | 3 / 3 |

The source events, response hashes and elapsed times are retained in [`loopback-smoke-20261107.json`](../scripts/baselines/evidence/loopback-smoke-20261107.json). Elapsed times include launching curl; this short loopback check is only evidence of configuration interoperability and delivery correctness.

Initial fixture attempts did fail and were corrected: macOS system Python's LibreSSL rejected a TLS 1.3 server; OpenSSL `s_server` did not complete the tested REALITY handshakes; after using a public TLS target, Xray's debug log exposed its default private-destination block. The committed smoke fixture uses Go TLS 1.3 and the explicit loopback allow rule. These were setup failures, not discarded performance samples. No comparative performance run was used to tune these fixture corrections.

## Primary sources

- [Xray v26.10.31 release](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31)
- [Xray REALITY config parser](https://github.com/XTLS/Xray-core/blob/v26.10.31/infra/conf/transport_security.go)
- [Xray freedom default/final rules](https://github.com/XTLS/Xray-core/blob/v26.10.31/proxy/freedom/freedom.go)
- [Xray final-rules config parser](https://github.com/XTLS/Xray-core/blob/v26.10.31/infra/conf/freedom.go)
- [Hysteria v2.13.0 release](https://github.com/HyNetworks/hysteria/releases/tag/app/v2.13.0)
- [Hysteria congestion config parser](https://github.com/HyNetworks/hysteria/blob/app/v2.13.0/app/cmd/congestion.go)
- [Hysteria client bandwidth negotiation](https://github.com/HyNetworks/hysteria/blob/app/v2.13.0/core/client/client.go)
- [Hysteria server bandwidth negotiation](https://github.com/HyNetworks/hysteria/blob/app/v2.13.0/core/server/server.go)
- [Hysteria client configuration](https://v2.hysteria.network/docs/advanced/Full-Client-Config/)
- [Hysteria server configuration](https://v2.hysteria.network/docs/advanced/Full-Server-Config/)

The hosted client documentation initially timed out during retrieval. Version-specific claims above come from the successfully retrieved tagged source files.
