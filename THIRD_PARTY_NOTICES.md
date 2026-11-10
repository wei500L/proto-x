# Third-party notices

Original PROTO-X code and documentation are distributed under the [MIT License](LICENSE).
Third-party code retains its own copyright and license. The root license does
not replace notices in copied code, research snapshots, patches, or archives.

## Runtime dependencies

The current Go dependencies are pinned in [go.mod](go.mod) and [go.sum](go.sum).
Their unmodified upstream license texts are included here for redistribution:

| Dependency | Version | License |
| --- | --- | --- |
| github.com/quic-go/quic-go | v0.65.0 | [MIT](licenses/runtime/quic-go.txt) |
| github.com/quic-go/qpack | v0.6.0 | [MIT](licenses/runtime/qpack.txt) |
| golang.org/x/crypto | v0.54.0 | [BSD-3-Clause](licenses/runtime/x-crypto.txt) |
| golang.org/x/net | v0.56.0 | [BSD-3-Clause](licenses/runtime/x-net.txt) |
| golang.org/x/sys | v0.47.0 | [BSD-3-Clause](licenses/runtime/x-sys.txt) |
| golang.org/x/text | v0.40.0 | [BSD-3-Clause](licenses/runtime/x-text.txt) |

Go downloads these modules during the build; this repository does not vendor
their full implementations into the main application.

## Archived research

The [research archive](research/README.md) includes experimental code adapted
from quic-go and Hysteria, along with source snapshots and dependency notices.
Preserve those local notices when redistributing any extracted code. In
particular, the copied congestion-control implementations retain their
[quic-go](research/cc/cc65/internal/hycc/LICENSE.quic-go) and
[Hysteria](research/cc/cc65/internal/hycc/LICENSE.hysteria) MIT notices.

Reference protocols used by the benchmark tooling are independent upstream
projects. Downloaded executable files and private deployment configurations are
excluded from this repository; their upstream licenses continue to apply.
