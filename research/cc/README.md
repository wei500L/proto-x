# Congestion-control research exports

This directory makes both isolated CC prototypes reproducible without the
author's working directories. It contains complete source archives, patches,
source provenance, dependency licenses, raw correctness-test evidence, and
independent build-replay records. The binary files are **not included**; their
expected build-output hashes are in [ARTIFACTS.json](ARTIFACTS.json).

| Variant | Source snapshot | Execution and measurement status |
|---|---|---|
| Old Hysteria QUIC fork | `a7a33341984ac60354aca6425c561d3b902e9c63`, branch `research/cc` | macOS correctness tests passed; the frozen Linux ARM64 executable was also run by the network lab in the linked CC performance experiments. |
| CC65 extension | `5959fe014513311d9b5cf0e7ea9953d755ed9052`, branch `research/cc65` | macOS correctness tests passed; Linux ARM64 was cross-compiled and its hash reproduced, but has **not been executed or performance-tested**. |

Neither source snapshot includes later mainline application fixes. These are
research alternatives based on the same earlier application revision, not the
currently deployed client/server. No new latency, throughput, fingerprint, or
censorship-resistance advantage is established by the CC65 correctness tests.

## Contents and integrity

- [Old-fork source archive](sources/protox-old-fork-cc-source.tar.gz) and
  [application patch](../patches/cc-hy-fork.patch).
- [CC65 source archive](sources/protox-cc65-source.tar.gz) and
  [application patch](../patches/cc65.patch).
- [CC65 dependency-only patch](patches/quic-go-v0.65.0-cc.patch).
- [Old-fork design and provenance](old-fork/docs/research/cc-prototype.md),
  [source manifest](old-fork/docs/research/cc-source-evidence/prototype-manifest.json),
  [imported-code provenance](old-fork/internal/hycc/SOURCE.json), and
  [dependency licenses](old-fork/docs/research/cc-source-evidence/dependency-licenses.json).
- [CC65 design and lifecycle](cc65/docs/research/cc65-prototype.md),
  [source manifest](cc65/docs/research/cc65-evidence/source-manifest.json),
  [dependency manifest](cc65/docs/research/cc65-evidence/dependency-manifest.json),
  [imported-code provenance](cc65/internal/hycc/SOURCE.json), and
  [dependency licenses](cc65/docs/research/cc65-evidence/dependency-licenses.json).
- [Archive audit](audit/archive-audit.json), including complete member lists;
  [patch application check](audit/application-patch-check.json).

Run from the exported repository root:

```sh
python3 research/cc/verify_exports.py
# Optional independent checksum check on macOS (or use sha256sum -c on Linux):
shasum -a 256 -c research/cc/SHA256SUMS
```

Every delivered payload file and both application patches are indexed with a
repository-relative path, byte count, and SHA-256. `SHA256SUMS` also covers
`ARTIFACTS.json`; it excludes itself. Verification checks archive boundaries,
the source-manifest hashes, copied evidence, dependency-patch identity, and
test-event hashes. It does not run the binaries or repeat performance tests.

The exported `old-fork/` and `cc65/` trees mirror the documentation/provenance
paths of their corresponding source roots. They deliberately contain no Go
source packages; complete buildable source lives in the archives and patches.
Paths in the archived source manifests refer to the **extracted source root**.
Recorded logs retain their original paths and whitespace, including a few
historical absolute paths. Those strings are evidence, not required locations.
The frozen prototype notes also retain their original author-scoped wording:
the old note's statement that its author did not execute Linux does not exclude
the later Linux measurements by the network lab listed below.

## The two different patch bases

Both **application** patches apply directly to PROTO-X commit
`5d80253d057b5004a3fad77d50ea4ed315eb0b85`
(`Implement experimental resumable QUIC/TLS proxy and packet-level benchmark lab`).
This is the original application baseline, not a quic-go revision and not the
current mainline HEAD. Apply one application patch to a fresh checkout at that
commit; do not stack them. A clone containing this commit is needed for the
patch route. The source-archive route needs no application Git history.

The **dependency-only** patch instead applies to upstream quic-go v0.65.0,
commit `aa265c3fc6489e3bfa8071b333be95e0e887a51d`. It is already included inside
the complete CC65 application patch and source archive. The included preparation
script fetches that public upstream commit, checks the patch and all modified
file hashes, then applies it. Do not apply it to the PROTO-X repository.

## Rebuild from complete source archives

Use Python 3, Git, and Go 1.27.1 to match the recorded toolchain. Network access
is needed to fetch public dependencies; `go.sum` verifies module downloads.
Start each example at the exported repository root.

For CC65:

```sh
PROTOX_EXPORT_ROOT="$(pwd)"
PROTOX_CC_REPLAY="$(mktemp -d)"
tar -xzf "$PROTOX_EXPORT_ROOT/research/cc/sources/protox-cc65-source.tar.gz" -C "$PROTOX_CC_REPLAY"
cd "$PROTOX_CC_REPLAY/protox-cc65"
python3 scripts/research/prepare_cc65.py
go mod download
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOARM64=v8.0 go build \
  -trimpath -buildvcs=false -ldflags=-X=main.version=0.1.0-research-cc65 \
  -o bin/protox-cc65-linux-arm64 ./cmd/protox
```

The relative `go.mod` replacement `./.local/quic-go-v0.65.0` is created **inside
this newly extracted source directory** by the preparation script. It does not
refer to an original private checkout. A fresh-archive replay completed and
reproduced Linux SHA-256
`61e9036c1acb9aee3843e5a0e964c00a8949bc5809b4b8ef162a62ab7888b2f6`.
See [replay proof](cc65/replay/archive-replay-build.json) and its sibling raw
stdout/stderr files. The `-buildvcs=false` flag permits an identical build from
either archive or checkout.

For the old fork:

```sh
PROTOX_EXPORT_ROOT="$(pwd)"
PROTOX_CC_REPLAY="$(mktemp -d)"
tar -xzf "$PROTOX_EXPORT_ROOT/research/cc/sources/protox-old-fork-cc-source.tar.gz" -C "$PROTOX_CC_REPLAY"
cd "$PROTOX_CC_REPLAY/protox-old-fork-cc"
go mod download
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOARM64=v8.0 go build \
  -trimpath -buildvcs=false -ldflags=-X=main.version=0.1.0-research-hycc \
  -o bin/protox-cc-linux-arm64 ./cmd/protox
```

This builds the archived old-fork source independently. Its hash differs from
the original measured binary because that binary embeds the application base
revision and `vcs.modified=true`. Use the following patch route to reproduce
that original binary hash. An independent archive build of the old fork is not
claimed in the recorded replay evidence; that replay used the public patch.

## Rebuild from an application patch

Start at the exported repository root. Keep the patch **uncommitted** for the
old-fork build; `git am` or committing the changes alters embedded VCS metadata.

```sh
PROTOX_EXPORT_ROOT="$(pwd)"
PROTOX_CC_REPLAY="$(mktemp -d)"
git worktree add --detach "$PROTOX_CC_REPLAY/old-fork" 5d80253d057b5004a3fad77d50ea4ed315eb0b85
git -C "$PROTOX_CC_REPLAY/old-fork" apply --check "$PROTOX_EXPORT_ROOT/research/patches/cc-hy-fork.patch"
git -C "$PROTOX_CC_REPLAY/old-fork" apply "$PROTOX_EXPORT_ROOT/research/patches/cc-hy-fork.patch"
cd "$PROTOX_CC_REPLAY/old-fork"
go mod download
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOARM64=v8.0 go build \
  -trimpath -ldflags=-X=main.version=0.1.0-research-hycc \
  -o bin/protox-cc-linux-arm64 ./cmd/protox
```

The independent [old-fork replay](old-fork/replay/old-archive-replay-build.json)
used this base-plus-uncommitted-patch procedure and exactly reproduced the
measured Linux SHA-256
`46b55aa58073753d2a3fa16d76c117ce86692eaca57a2b05e355e52700c45819`.

For CC65, use a second fresh checkout at the same application base:

```sh
# Start at the exported repository root again.
PROTOX_EXPORT_ROOT="$(pwd)"
PROTOX_CC_REPLAY="$(mktemp -d)"
git worktree add --detach "$PROTOX_CC_REPLAY/cc65" 5d80253d057b5004a3fad77d50ea4ed315eb0b85
git -C "$PROTOX_CC_REPLAY/cc65" apply --check "$PROTOX_EXPORT_ROOT/research/patches/cc65.patch"
git -C "$PROTOX_CC_REPLAY/cc65" apply "$PROTOX_EXPORT_ROOT/research/patches/cc65.patch"
cd "$PROTOX_CC_REPLAY/cc65"
python3 scripts/research/prepare_cc65.py
go mod download
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOARM64=v8.0 go build \
  -trimpath -buildvcs=false -ldflags=-X=main.version=0.1.0-research-cc65 \
  -o bin/protox-cc65-linux-arm64 ./cmd/protox
```

Both public application patches were checked against the base during export.
Recorded exact binary reproduction used the old-fork patch and the CC65 source
archive respectively; it does not assert that every command variant above was
separately run. Changing the compiler, target, build flags, or source can change
the executable hash.

## Correctness checks and performance evidence

The [CC65 test index](cc65/docs/research/cc65-evidence/tests/summary.json) includes
raw JSONL for 475 passing upstream top-level tests under the race detector,
three existing Linux/GSO-specific skips on macOS, five passing upstream
migration/MTU integration tests, and 31 passing PROTO-X top-level tests. Real
native migration preserves one QUIC stream across two path changes; custom
controllers are recreated on both endpoints. Concurrent controller updates and
client/server migration-factory failures are also covered. Each custom mode
passed authenticated QUIC-to-TLS recovery with exact bytes, half-close and one
original target socket. The initial nil-versus-empty-slice test assertion
failure and subsequent passing runs are both retained.

The [old-fork mode tests](old-fork/docs/research/cc-source-evidence/tests/modes-summary.json)
retain the four custom-controller QUIC-to-TLS recovery runs. The old full-suite
pass was recorded in its source manifest from tool output; a raw full-suite
JSONL was not captured. No missing log has been recreated as if it were raw.

To rerun local tests from either rebuilt source root, use `go test -race
-count=1 ./...`. CC65's design note also lists the modified upstream-package
and migration/MTU commands. Use a native target and a working C toolchain for
the Go race detector; the `CGO_ENABLED=0` setting in the examples applies to
cross-compiling the release binaries, not to race-test execution.

The old-fork Linux performance records are elsewhere in this repository:

- [CC screening, seed 211](../../results/cc-screen-s211-20261106T231831Z/manifest.json)
  and [seed 223](../../results/cc-screen-s223-20261106T232127Z/manifest.json).
- Receive-window sweeps at
  [64 KiB](../../results/cc-window-w65536-s227-20261106T232446Z/manifest.json),
  [128 KiB](../../results/cc-window-w131072-s227-20261106T232738Z/manifest.json),
  and [256 KiB](../../results/cc-window-w262144-s227-20261106T232555Z/manifest.json).

Their manifests identify the measured old-fork binary hash above. These are
25-second trials in a local Linux ARM64 VM with real IP-packet netem emulation,
60 ms configured RTT, 1% loss and 5 ms jitter per direction, and an 8/2 Mbps
link. They are not Russian field measurements or CC65 measurements. Raw events,
status denominators, resource samples, outer-byte counters, and configurations
remain with each run. The old-fork screening did not establish superiority over
Hysteria2. The window sweeps are exploratory single-seed runs, not independent
confirmation of a tuned configuration.

Both default transport controllers are Reno. The old fork resets a custom
controller to Reno on native path migration; CC65 instead installs a fresh
selected controller through the connection event loop. CC65 external controllers
disable outgoing ECN; the imported Hysteria BBR/Brutal algorithms still lack
spurious-loss rollback and ignore the aggregate MTU-probe marker. These transport
and feedback differences prevent treating old-fork performance as CC65 results.
The next useful measurement is a CC65 Reno/BBR/Brutal comparison with matched
receive windows, application budgets, workloads, and measured outer traffic.
