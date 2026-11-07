# Frozen congestion-control comparison prototype

This isolated research worktree starts at PROTO-X commit `5d80253`. It retains
the existing application session, byte-offset replay, scheduler, authentication,
and QUIC→TLS recovery. Its QUIC dependency and installed congestion controller
are the experimental variables. No throughput or latency advantage has yet been
established for this variant. The parent agent runs the network matrix separately.

## Source replay and export

The `research/cc` branch archives this prototype's code, source evidence, and
licenses. Its parent is `5d80253d057b5004a3fad77d50ea4ed315eb0b85`.
Export the branch change with:

```sh
git format-patch --stdout 5d80253d057b5004a3fad77d50ea4ed315eb0b85..research/cc > old-fork-cc.patch
```

For the original frozen binary metadata, apply that patch with `git apply` to
an **uncommitted** detached worktree at the parent, then use Go 1.27.1 and the
build commands in `cc-source-evidence/prototype-manifest.json`. The original
binaries record the parent revision with `vcs.modified=true`; a clean checkout
at the archive commit will have different embedded VCS metadata and therefore
different hashes, even with identical Go sources. Do not overwrite the frozen
binaries in the comparison worktree while replaying.

```sh
git worktree add --detach /tmp/protox-oldcc-replay 5d80253d057b5004a3fad77d50ea4ed315eb0b85
git -C /tmp/protox-oldcc-replay apply /absolute/path/old-fork-cc.patch
cd /tmp/protox-oldcc-replay
go mod download
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags=-X=main.version=0.1.0-research-hycc -o bin/protox-cc-linux-arm64 ./cmd/protox
go test -race -count=1 ./...
```

Dependencies are fetched by version and verified using `go.sum`. Private
configuration, certificates, executables, and experiment host inventory are
excluded from the source commit and patch.

## Running the frozen binaries

Both binaries are in this worktree's `bin/` directory. Their build metadata and
all relevant source hashes are in
[`cc-source-evidence/prototype-manifest.json`](cc-source-evidence/prototype-manifest.json).

| Binary | SHA-256 |
|---|---|
| `protox-cc-linux-arm64` | `46b55aa58073753d2a3fa16d76c117ce86692eaca57a2b05e355e52700c45819` |
| `protox-cc-darwin-arm64` | `af557f02ff97d5a5964a2b670b62a2068eccabda7e2b7b4a363256aad433c41e` |

Use the existing private PROTO-X JSON configurations. Select the controller in
each process's environment:

```sh
PROTOX_CC=hy-brutal PROTOX_CC_BRUTAL_MBPS=6 \
  bin/protox-cc-linux-arm64 server -config .local/test/server.json

PROTOX_CC=hy-brutal PROTOX_CC_BRUTAL_MBPS=1.5 \
  bin/protox-cc-darwin-arm64 client -config .local/test/client.json
```

`PROTOX_CC` supports `reno` (also the default), `hy-bbr-standard`,
`hy-bbr-conservative`, `hy-bbr-aggressive`, and `hy-brutal`.
`PROTOX_CC_BRUTAL_MBPS` is required only for Brutal. Optional
`PROTOX_CC_DISABLE_LOSS_COMPENSATION=true` disables its loss compensation; default
is false. Invalid selections fail the QUIC carrier instead of silently choosing
a different controller. Each authenticated QUIC link emits an
`experimental QUIC controller installed` log containing its selected mode.

The selected rate is the local **QUIC sender's** target, so configure upload on
the client and download on the server. The JSON `rate_mbps` remains a separate
application scheduler budget. Record both controls in experiments: setting one
does not set the other, and neither value is an exact outer IP-byte budget.

All modes use QUIC v1 explicitly. This avoids the pinned fork's missing QUIC v2
key-update-label fix. TLS fallback still uses the existing TLS 1.3 carrier.
Controllers are installed by `Link.Start()` after PROTO-X authentication;
handshake traffic initially uses the fork's default Reno, as Hysteria also
replaces its controller after application authentication.

## Exact source provenance

- Hysteria tag `app/v2.13.0` resolves to commit
  `ca8fbd874fd6ca82413948de6dc5924405e103e1`.
- Its `core/go.mod` pins `github.com/apernet/quic-go`
  `v0.63.1-0.20261004180939-a10df75c260c`, commit
  `a10df75c260cee8161f3261d63a37bd125a6bb2a`, module checksum
  `h1:cxK8qTA0YCsj68A7zLYDCfPgMTOyt3ePkHh+oXEmYU0=`.
- Twelve Go source/test files under Hysteria's `core/internal/congestion` are
  copied into `internal/hycc`. The only transformation replaces that internal
  package-path prefix with `proto-x/internal/hycc`. Controller equations,
  constants, profiles, clocks, pacer, and upstream tests are unchanged. Per-file
  original and transformed hashes are in `internal/hycc/SOURCE.json`.
- The copied Hysteria core code is MIT licensed, copyright 2023 Toby. The QUIC
  fork carries the quic-go authors and Google MIT notice. Both notices are
  included in `internal/hycc/`; compiled dependency notices are collected under
  `cc-source-evidence/licenses/` and indexed by `dependency-licenses.json`.
- Compiled fork dependencies including `x/exp`, Brotli, `compress`, and `x/net`
  were aligned to versions reported by the pinned official Hysteria executable,
  rather than taking newly discovered module versions.

This is **Hysteria v2.13.0's particular BBR implementation**, not a claim of
equivalence to Linux BBR, BBRv2, BBRv3, or every QUIC BBR port. Standard BBR uses
the upstream profile constants, including a 2.885 startup pacing gain and the
1.25/0.75/1/... probing cycle. The conservative and aggressive profiles retain
their upstream parameter differences. Hysteria's `InitialPacketSize()` seed logic
is also retained to avoid seeding a controller above QUIC's actual initial MTU.

Brutal uses the original five time slots of ACK/loss samples, a 50-sample minimum,
and an ACK-rate floor of 0.8. With compensation enabled, its internal pacing
target can rise to 1.25 times the configured rate, before separately accounting
for IP overhead. It does not infer a safe bottleneck capacity from that setting;
loss and capacity-collapse tests remain necessary.

The official Hysteria binary reports Go 1.26.8 and `vcs.modified=true`. These
prototype binaries use Go 1.27.1. Module checksums establish the same QUIC module,
and source hashes establish our exact controller-copy transformation. They do
not prove that every internal Hysteria byte in the official executable came
from the unmodified release tag. A stricter future comparison can rebuild both
applications from recorded source using one compiler.

## Differences and risks relative to stable quic-go v0.65.0

The pinned fork's common ancestor with current upstream is exactly the v0.63.0
commit `9d085cc690f7c96451e8ae5659eb0e64671da47a`. Upstream v0.65.0 is
`aa265c3fc6489e3bfa8071b333be95e0e887a51d`, with 140 subsequent upstream commits.
The fork's main modifications already span 72 files and 3713 added lines before
the module rename. They include more than a congestion API. Therefore compare
the fork's default Reno against its BBR/Brutal modes to separate controller
effects; a stable-v0.65 versus fork comparison alone does not isolate CC.

Both the frozen stable v0.1 dependency **and the Hysteria fork default to Reno**:
their `NewCubicSender` calls pass `true /* use Reno */`. The constructor name is
not evidence that CUBIC was active. Existing results labelled CUBIC need that
correction without changing their measured values.

Newer upstream fixes absent from this base include:

| Area | Examples |
|---|---|
| Reordering/loss recovery | Adaptive loss-time thresholds, disabling packet-threshold detection after spurious loss, restoring Reno state after spurious loss; PRs 5905, 5923, 5925 |
| MTU | Restarting PMTU discovery after path changes; falling back to 1200-byte Initial packets on `EMSGSIZE`; PRs 5887, 5911 |
| Path validation | Retrying server challenges and responding on the challenged client path; PRs 5930, 5980 |
| Repeated NAT rebinding | Selecting/retiring connection IDs correctly, including reordered/retransmitted NEW_CONNECTION_ID; PRs 6007, 6009, 6015 |
| QUIC v2 | Correct `quicv2 ku` key-update label; PR 5973; this prototype instead uses v1 |
| Packet bounds | Rejecting oversized packets before serialization; PR 5937 |

Exact commit IDs, upstream release notes, and the retrieved public security
advisories are preserved under `cc-source-evidence/`. The public quic-go advisory
list retrieved on 2026-11-06 UTC has no listed patched version later than
v0.59.1; the shared v0.63.0 base postdates those fixes. This is a limited source
and advisory review, not a claim that the fork is vulnerability-free. A module
rename can also prevent vulnerability tools from associating an upstream
advisory with its fork. No vulnerability scanner pass is claimed here.

**Native QUIC path migration resets the custom controller to Reno in this
fork.** Its `sentPacketHandler.MigratedPath` constructs a new Reno controller,
without preserving the installed BBR/Brutal selection. We leave that code
unchanged to preserve this comparison's source identity. Consequently an
initial controller-installation log does not prove that the same controller
remains active after migration. Rebuilding an outer carrier does run the hook
again; QUIC→TLS session recovery is a separate mechanism and was tested.

The fork also compiles uTLS and compression dependencies that the stable
prototype does not require. This PROTO-X variant does not enable Hysteria's
Chrome-parrot or packet-obfuscation configuration. It makes no new fingerprint
or blocking-resistance claim, and additional binary/resource cost must be
measured. The old fork is suitable for controlled comparison, not a proposed
replacement for the stable dependency.

## Checks completed

`go test -race -count=1 ./...` passed with the default fork Reno. This includes
the existing application/session correctness tests and copied upstream BBR and
Brutal tests. Each non-default controller mode separately passed the existing
real QUIC→TLS recovery test under `-race`: 512 KiB is delivered exactly, the TCP
half-close is preserved, and the origin accepts only one target connection.
Per-mode raw JSONL is in `cc-source-evidence/tests/`.

macOS execution and Linux ARM64 cross-compilation passed. This agent did not
execute the Linux binary, operate the VPS, or operate the matrix VM. Those
measurements belong to the parent/lab agent. Tests of native QUIC migration,
long-running memory, adversarial transport input, and realistic weak networks
remain outside the completed checks listed above.

## Path to a smaller maintained v0.65 extension

The next isolated prototype should retain v0.65's recovery, MTU, and migration
code, and port only a controller interface, monotonic-clock aliases, adapters,
and ACK/loss batch callbacks. Copying the entire Hysteria fork would reintroduce
unrelated changes. `OnCongestionEventEx` must receive complete ACK/loss batches;
the imported BBR and Brutal controllers do not implement their algorithm through
the single-packet ACK/loss stubs.

v0.65 additionally requires `OnSpuriousLoss`. An adapter must explicitly define
how legacy controllers handle it; silently presenting an unsupported rollback
as BBR equivalence would be misleading. Controller changes should happen on the
QUIC connection's event loop, and path migration should create a fresh instance
from the selected controller factory rather than accidentally choosing Reno.
Tests must cover ACK/loss accounting, installation/close races, and preservation
of the selection across migration before making a stability claim. This is the
planned extension boundary; a second worktree will hold any actual port, leaving
these frozen binaries available for the first comparison.
