# PROTO-X 原型安全与可部署性独立评审

评审日期：2026-11-07（Europe/Moscow）。范围是 `internal/carrier`、`internal/app`，以及它们依赖的记录边界、会话恢复和资源回收。评审者未修改这些实现；主开发者在评审过程中修复问题，以下状态以修复后源码复核为准。

目前可以继续受控实验部署。标准 TLS 1.3、显式证书指纹、随机 bearer token 和有界输入已形成可检查的基础；本次检查没有发现认证绕过。这个结论仅限下述源码审查与 10 项小规模回环检查，**不构成生产安全审计、拒绝服务防护证明或抗 DPI 证明**。

## 已发现并复核修复的问题

严重度描述问题修复前的影响，不表示这些缺陷仍然存在。

| ID | 原严重度 / 触发条件 | 问题及影响 | 修复后检查点 |
| --- | --- | --- | --- |
| SEC-01 | 高；无需应用 token 的远端 QUIC 对端 | 原先在占用 8 个预认证槽之前，为每个完成 QUIC 握手但未打开控制流的连接创建等待 goroutine。应用 `MaxSessions` 不能限制它们，低内存服务器存在资源耗尽风险。 | [`server.go:107`](../internal/app/server.go#L107) 在 `AcceptQUIC` 前占槽；满额立即关闭连接。等待和应用认证均受该槽约束。实际回环检查中前 8 个连接保持等待，第 9 个在 500 ms 内被关闭。 |
| SEC-02 | 中；正常客户端长期创建、关闭流 | 较早版本仅在服务端接收 OPEN 时更新 `maxID`，客户端墓碑清理条件永远不能生效，完成流的元数据随使用时间增长。 | [`session.go:203`](../internal/session/session.go#L203) 本地创建流同步更新 `maxID`，与维护循环的有界墓碑裁剪配合。本次为源码复核；另有会话回收测试，本文未运行长期压力测量。 |
| SEC-03 | 中；已认证对端发送未知流 ID，或恢复时需要回答已完成流 | 原先未知流、墓碑应答直接调用 per-flow `Send`，可创建没有活跃 Flow 负责回收的 QUIC writer，并阻塞接收循环；较早实现还为应答创建 goroutine。 | [`carrier.go:198`](../internal/carrier/carrier.go#L198) 增加容量 64 的控制队列，由一个写循环发送。队列满关闭承载；[`session.go:285`](../internal/session/session.go#L285) 的墓碑/未知流应答走控制流，不分配新的 per-flow writer。入站 QUIC stream 的 EOF 与 `Forget` 也清理 `seen` 元数据。 |

修复后未保留本次已确认的高严重度缺陷。QUIC/TLS 库在应用 admission 前仍需要执行标准网络握手；8 槽限制减少了应用层积累，不能阻止链路被流量淹没或大量握手消耗 CPU。整个服务没有完成面向公网攻击者的负载/DoS 认证。

## 实际执行的边界检查

时间：`2026-11-06T22:32:19Z`。网络仅为本机 loopback；启动了独立的临时客户端和服务端，没有访问 VPS、生产环境或第三方目标。

| 检查 | 观察到的结果 |
| --- | --- |
| 错误证书 SHA-256 pin | TLS 握手明确返回 `certificate pin mismatch`。 |
| 正确 pin、错误 token | 没有收到 WELCOME，连接被关闭。 |
| 不支持的协议版本 | 没有收到 WELCOME，连接被关闭。 |
| 不兼容的流窗口 | 没有收到 WELCOME，连接被关闭。 |
| 非 128 位 hex 的 session ID | 没有收到 WELCOME，连接被关闭。 |
| 恢复不存在的 session | WELCOME 明确返回 `ok=false, error=session_lost`。 |
| 正确的新 session | WELCOME 为 `ok=true, resumed=false`。 |
| 恢复同一活进程保留的 session | WELCOME 为 `ok=true, resumed=true`。 |
| 声明 4097 字节的 HELLO payload，只发送头部 | 不等待不存在的 payload，立即 EOF；超过 4096 字节记录上限被拒绝。 |
| QUIC 预认证槽边界 | 8 个不打开控制流的连接保持等待，第 9 个及时关闭。 |

**10/10 检查通过。** 第 8 项只验证会话身份识别，未在该检查中创建应用 socket，因此不能用它替代连续字节、半关闭或实际断线恢复测试。9 个连接的边界检查也不能外推为大规模抗压结果。

原始完整结果和源码哈希已脱敏归档为 [`initial-checks.json`](../results/security-20261107/initial-checks.json) 与 [`initial-source-sha256.json`](../results/security-20261107/initial-source-sha256.json)。临时程序保留在 `.local/security-check/main.go`；生成的证书和 token 始终仅位于 `.local`。

检查现已整理为公开可复用的 [`tools/securitycheck`](../tools/securitycheck/README.md)。默认测试当前源码，也可通过 `-binary` 指定一个本地服务端可执行文件；两种模式都创建全新的回环服务和随机凭据，不读取现有部署配置：

```sh
go run ./tools/securitycheck \
  -private-dir .local/securitycheck \
  -out results/security-new/checks.json

go build -trimpath -o .local/securitycheck/protox ./cmd/protox
go run ./tools/securitycheck \
  -binary .local/securitycheck/protox \
  -private-dir .local/securitycheck \
  -out results/security-binary/checks.json
```

可复用工具的源码模式与独立二进制模式已分别运行，均为 10/10；结果及各自的哈希在 [`results/security-20261107`](../results/security-20261107/README.md)。这是相同十个场景的复跑，不是三十种独立安全保证。工具对负向认证检查要求对端关闭连接，超时计为失败；原临时程序部分检查只断言读取返回错误，原始结果未因此被重写。不要把包含私密配置的整个 `.local` 发布到代码仓库。

本次记录的源码 SHA-256 前缀如下；后续改动不自动继承本次检查结论：

| 源码 | SHA-256 前缀 |
| --- | --- |
| `internal/carrier/carrier.go` | `1f83cb4f692dac44` |
| `internal/app/server.go` | `93aa90141e2b25dd` |
| `internal/app/client.go` | `7df3eea10811a856` |
| `internal/app/config.go` | `c626e4e5a839fa02` |
| `internal/session/session.go` | `b7890dd4b05218bb` |
| `internal/wire/frame.go` | `bc1d02545261a117` |

## 加密、认证和重放边界

- [`carrier.go:49`](../internal/carrier/carrier.go#L49) 使用 Go TLS 1.3 和 quic-go，不自行设计密钥交换或 AEAD。客户端的 `InsecureSkipVerify` 后面有强制 `VerifyConnection`：验证叶证书的 SHA-256 pin，并验证 ALPN。它不是允许任意证书的“不安全 TLS 模式”。
- 这是**证书 pin 信任模型**。公共 CA 链、DNS 名匹配、证书到期时间不构成这里的额外信任判据；身份由分发的 pin 决定。证书更换会改变 pin，需协调更新客户端。尚未实现多 pin 过渡、独立凭据撤销或自动证书轮换协议。
- [`config.go:95`](../internal/app/config.go#L95) 的 session ID 使用 128 位安全随机数；token 使用 256 位安全随机数，生成文件权限为 `0600`。[`server.go:151`](../internal/app/server.go#L151) 在创建/附加 Session 前检查记录类型、版本、窗口、token 和 session ID，token 比较采用常量时间函数。
- 应用 token 是同一服务的共享 bearer 凭据；持有它的客户端属于同一信任主体。这里没有多租户隔离、独立用户配额或每用户撤销。重连还需要对应的高熵 session ID，但它不是独立于 token 的多用户授权系统。
- QUIC 配置显式 `Allow0RTT:false`。协议没有通过 0-RTT 自动重放 HTTP、SSH 或其他有副作用的应用操作。恢复依赖仍然存在的字节偏移、缓冲和目标 socket；它不是跨进程故障的应用事务“恰好一次”保证。
- 会话 ACK 确认的是对端会话层已接收的连续字节，不是目标应用已执行操作，也不是磁盘持久化。在原进程存活时可以对恢复重传去重；进程丢失后必须向应用暴露失败。

## 恢复与端点限制

现有端点列表应优先表示**同一个服务端进程/会话拥有者的不同承载**，例如同一测试服务器的 QUIC 与 TLS 入口。

原始评审版本在第一个可达端点返回 `session_lost` 时立即关闭旧 Session。后续源码已修正为：本轮先尝试所有配置的端点；只有没有端点恢复成功且观察到明确状态丢失，才关闭旧 Session、生成新 session ID。参见 [`client.go:115`](../internal/app/client.go#L115) 与 [`client.go:166`](../internal/app/client.go#L166)。这是源码复核，本页十项握手检查没有模拟多个独立服务器来验证完整选择流程。旧 TCP/SSH socket 不会被暗中重新创建，旧应用字节不会作为新连接请求自动重放。

多个独立服务器没有共享目标 socket、接收缓冲和 ACK 状态。**把相同证书、token 或 session ID 放到另一台服务器，不能恢复原来的 TCP 会话。** 一轮所有端点均未恢复成功，也不证明暂时不可达的原拥有者已经永久丢失状态；混用独立服务器时，当前策略仍可能为尽快建立新会话而放弃稍后可恢复的旧流。这是部署/恢复策略的限制。若要正式支持异机端点，应增加会话拥有者标识、在恢复窗口内的选择策略，并单独设计目标 socket 状态的存活方案。

后续源码还把心跳失联时间、PONG RTT 和调度器活跃时间改为以 `time.Now()` 保留的单调时钟基准计算 `time.Since`，避免直接依赖 Unix 墙上时钟发生跳变。本次为源码复核；本文未修改系统时钟、模拟休眠，或把上述握手复跑当作时钟跳变测试。

客户端地址/NAT 变化、承载重建与服务端进程死亡是不同故障。本文的认证检查没有测量移动网络切换、休眠唤醒、服务器崩溃或跨机恢复时间。恢复窗口到期与目标服务自行关闭连接也会结束旧应用流。

## 目标访问与本地入口

- [`client.go:33`](../internal/app/client.go#L33) 要求 SOCKS 监听地址为**数字形式的 loopback IP**，默认 `127.0.0.1:1088`。不支持把这个无认证 SOCKS 入口直接暴露给局域网/公网。SOCKS 已接受连接数有 `MaxFlows+8` 上限，握手有截止时间。
- SOCKS 只支持 CONNECT。成功响应在远端目标 socket 建立后发送；UDP ASSOCIATE、BIND、HTTP CONNECT 和 TUN 不属于当前功能。
- [`server.go:207`](../internal/app/server.go#L207) 验证目标端口，解析域名后检查具体 IP，再直接连接已检查的 IP；不会在检查与连接之间重新按域名解析。这避免了常见的 DNS 重绑定检查/使用分离。
- 默认拒绝 RFC1918/ULA、loopback、链路本地、多播与 unspecified 地址，IPv4-mapped IPv6 会先 `Unmap`。这个规则不是全部特殊用途网段的允许清单，例如 CGNAT `100.64.0.0/10` 不属于 Go `IsPrivate` 定义。若部署要求“只允许公网目的地”，还需明确特殊用途网段和运营商内网的策略。
- `allow_private_targets:true` 会整体关闭上述私网检查；它适合受控基准访问 loopback fixture。公网部署如果不需要内部目标，应使用默认值。不要把“用于实验允许 loopback”误写成“已实现逐端口内部访问授权”。
- 本地其他进程可以使用无认证 loopback SOCKS，这符合单用户客户端模型；它没有建立同一机器上不同用户之间的授权隔离。

## 资源与长期运行边界

记录头先验证长度再分配 payload，单记录上限 4096 字节；入站记录队列容量 128，控制队列容量 64。QUIC 上限为 1 个入站双向控制流、128 个入站单向流，连接接收窗口最大 4 MiB。应用会话数、活跃流数、每流缓存窗口与恢复 TTL 另有边界。这些限制作用于不同层，不能只观察其中一个就声称总资源恒定。

默认 `2 sessions × 32 flows × 64 KiB × 2 directions` 对应约 **8 MiB 的应用有效缓存容量**。这不是 RSS 上限：切片容量、在途拷贝、QUIC/TLS、socket 缓冲、栈、元数据和运行时开销还需额外计入。高级配置允许更大的窗口/会话组合；它们不适合直接套用到 128 MiB 服务器。

`GOMEMLIMIT=32MiB` 是 Go 的软内存目标，`GOGC=50` 是 GC 策略，不是操作系统强制内存上限。应以实际 RSS、GC/CPU、swap、文件描述符及失败率确定该 VPS 的部署容量。附加的标准握手 CPU 成本、连接洪泛与长期资源泄漏仍需专门测量。

TLS 承载把应用流复用在一个 TCP 连接里，仍有 TCP 丢包造成的跨流队头阻塞。QUIC 独立流减少这种跨流等待，但共享连接拥塞控制、连接窗口、CPU 和线路；它也不是任意后台负载下的隔离保证。控制记录和加密重传的外层成本应进入实际字节测量，不能把配置的应用速率视为硬 wire-rate 上限。

## 抗识别结论

当前原型**容易被规则识别**，没有合理依据宣称优于 REALITY 或 Hysteria 的抗识别能力：

- ALPN 固定为 `proto-x/1`，默认 SNI 是 `proto-x.local`。没有 ECH；TLS ClientHello 信息以及可解码 QUIC Initial 中的 TLS ClientHello 可用于分类。
- 服务端使用本项目生成的证书。TLS 1.3 证书并非普通被动旁观者直接可读，但主动 TLS 客户端可获取它。未认证连接等待协议 HELLO 后关闭，并没有真实网站回落行为。
- 没有实现 HTTP/3/WebTransport 网站承载、流量形态训练、填充策略或主动探测回落，也没有执行检测器数据集评测。

在 UDP 不可用而 TCP 可用时切换 TLS，是**承载可达性适应**。它不证明对端无法识别协议，更不能外推为所有俄罗斯运营商的封锁规避效果。

## v0.1.1：客户端退出与心跳回归

2026-11-07 的增量复核覆盖客户端退出时序和空闲心跳。`RunClient` 现在使用子 context，在返回路径先取消并等待 `manage` 完成，再读取、同步关闭当前 Session，避免管理循环在清理快照之后继续发布一个未关闭的会话。应用 HELLO/WELCOME 握手期间的 context 取消会关闭尚未附加的承载；成功握手会先停止该关闭回调，已经触发回调的承载不会继续 Attach。这也避免了同步等待管理循环退化成等待完整的应用握手超时。

保证范围是**管理循环停止和当前客户端会话的同步清理**。它没有等待全部 SOCKS 处理协程退出；仍在本地 SOCKS 握手中的连接受既有 10 秒截止时间约束。客户端返回也不意味着服务端保留的目标 socket 立即关闭，服务端仍按恢复 TTL 管理失联会话。首次发布与取消的窄竞态、非取消原因的监听器 `Accept` 失败已检查代码顺序，但没有在新增退出测试中单独注入。

[`client_shutdown_test.go`](../internal/app/client_shutdown_test.go) 使用真实回环 TLS 和真实 `RunClient`，分别通过扣住 WELCOME、等待已附加会话的 PONG 来建立阶段屏障。两项 race 测试各重复 10 次通过；仅通过 Go overlay 换回 `5d80253` 的旧 `client.go` 后，同一未完成握手用例实际失败：客户端已经返回，握手承载却仍然打开。实际命令、输出、源码哈希及可移植的负向重跑方法见 [`shutdown-regression.md`](../results/verification-v011-20261107/shutdown-regression.md)。对端 EOF 观察留有 300 毫秒的本机调度/传送窗口；这两项测试没有覆盖 QUIC 握手取消。

心跳调整保留双端失联检查：默认客户端主动 PING、服务端回复 PONG；非自适应服务端通常不再重复探测。但若服务端接收方向的静默已达到 `DeadAfter/2`、尚未超过 `DeadAfter`，维护 tick 会补发 PING，直至收到对端流量或判定失联。这样，客户端合法配置的心跳间隔即使大于服务端失联阈值，也可由服务端补位保活。`adaptive=true` 的服务端仍主动探测以采集本地 RTT 样本。这些阈值经过维护 tick 和网络处理才生效，不构成硬实时恢复承诺。

主线已执行全套 race 测试与 `go vet`，均通过。其中 [`heartbeat_test.go`](../internal/session/heartbeat_test.go) 覆盖默认/自适应两种空闲行为、任一方向静默后的双端脱离，以及客户端 5 秒心跳与服务端 100 毫秒心跳、500 毫秒失联阈值的不等配置。心跳用例使用 `net.Pipe` 和记录级静默注入；`AcceptTLS` 在这些用例中只是封装，并没有执行真实 TLS 或 QUIC 网络握手。

以上是 v0.1.1 的增量回归证据，**不会自动继承前文十项安全边界检查的 10/10 结论**。那十项检查绑定原先记录的源码版本；要宣称它们对 v0.1.1 仍通过，需要针对本版另外重跑并保存结果。退出/心跳用例也不能替代认证、预认证资源上限、长期泄漏或抗识别验证。

## 后续验证优先级

已完成的有限 VPS 观察包括 600 秒混合负载、UDP 黑洞、源端口变化、进程重启反例与空闲计量，具体版本和边界见[实验报告](RESULTS.md)。下一轮增加恶意输入覆盖：同一 session 的并发附加、部分握手/慢读、控制流背压、未知流 ID 连续输入、凭据/证书轮换、端点所属进程变化。可靠传输的字节/半关闭/失联测试应持续约束恢复语义；检测器和主动探测实验需要另立数据集与成功标准。这些新增项目和多日运行仍未验证，不能由已完成的有限检查代替。
