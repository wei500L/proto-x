# PROTO-X 原型协议说明

实现版本：`0.2.0-experimental`；更新日期：2026-11-07（Europe/Moscow）。当前内层会话记录版本为
**1**，与研发任务书的 v3.0 编号不同。实现使用 Go、TLS 1.3 和
[quic-go v0.65.0](../go.mod)，提供本地 SOCKS5 CONNECT 到远端 TCP 目标的代理。
本页描述已实现机制；与 VLESS／Hysteria2 的性能优劣需要另行测量。

v0.2 默认入口已改为真实 HTTP/2 / HTTP/3，包含网站回落、TLS exporter 绑定认证、标准 ECH 和记录填充，详见 [WEB-CARRIER.md](WEB-CARRIER.md)。ACK、FIN、窗口和原 socket 恢复语义仍适用；下面旧 QUIC / TLS 映射与 pin-only 认证描述只对应显式原生诊断承载，不是新默认入口。

## 承载、认证与会话

客户端保留应用连接，服务端保留目标 TCP socket；中间的 `Session` 将这些连接
映射为带字节偏移的 `Flow`。外层 `carrier.Link` 可以替换，内层 socket 和会话
状态不随一次外层断开立即销毁。参见
[Session.Attach、Drop 与 Bridge](../internal/session/session.go)。

| 承载 | 记录映射 | 主要边界 |
| --- | --- | --- |
| HTTP/3（默认） | 控制 POST 与每 Flow 的双向 POST，记录带有界填充封套 | 实际 HTTP/3 与普通网站；仍共享 QUIC 拥塞控制 |
| HTTP/2（默认 TCP 回退） | 同一 TLS 连接中的独立双向 POST | 实际 HTTP/2；仍有 TCP 跨流队头阻塞 |
| QUIC | 一个双向控制 stream；每条 Flow 的两个发送方向各用一个单向 stream | 不同 Flow 不共用一个有序字节流；仍共享拥塞控制、连接窗口、CPU 和链路 |
| TLS/TCP | 全部记录复用一个可靠有序 TCP 字节流 | UDP 不可达时可尝试此入口；TCP 丢包仍会造成跨 Flow 队头阻塞 |

[carrier](../internal/carrier/carrier.go) 使用标准 TLS／QUIC 完成加密、包重传和
拥塞控制。客户端强制校验**叶证书 DER 的 SHA-256 pin**及 ALPN `proto-x/1`；
公共 CA 链、域名匹配和有效期不是这个 pin 信任模型的额外判据。换证书需要同步
更新 pin。共享的 256 位随机 token 在受保护的 HELLO 中认证；session ID 为
128 位随机数。它们不是多租户身份系统。没有启用 0-RTT，也没有早期应用请求重放。

认证顺序为 TLS／QUIC 握手 → HELLO → WELCOME → 附加 Session。HELLO 的 JSON
字段是 `version`、`session`、`token`、`resume`、`window`；服务端要求版本和窗口
匹配配置。WELCOME 含 `ok`、`resumed`，失败时可含 `error`，例如
`session_lost` 或 `session_limit`。认证失败不会进入代理会话。
参见 [Server.handshake](../internal/app/server.go)。

## 记录格式

[wire/frame.go](../internal/wire/frame.go) 定义固定 32 字节头，整数均为大端序。
负载最多 4096 字节，正常 DATA 分块最多 2048 字节；读取时先检查头和长度再分配。

| 字节偏移 | 字段 | 含义 |
| --- | --- | --- |
| 0 | Kind，uint8 | 以下 1–10 的记录类型 |
| 1 | Flags，uint8 | bit 0 为 FIN 确认标志；其他位必须为 0 |
| 2–3 | Reserved | 必须为 0 |
| 4–11 | ID，uint64 | 0 为会话控制；客户端 Flow ID 为递增奇数 |
| 12–19 | Offset，uint64 | DATA 起点、累计 ACK、FIN 终点或心跳时间标记 |
| 20–27 | Limit，uint64 | 对端允许发送到的字节终点 |
| 28–31 | Length，uint32 | 后续 payload 长度 |

| Kind | 内容与作用 |
| --- | --- |
| 1 HELLO / 2 WELCOME | ID=0；上述 JSON 握手 |
| 3 OPEN | payload 为 `host:port`，最多 1024 字节；服务端建立或找到已有 Flow |
| 4 OPENED | 目标连接成功，兼带累计 ACK 和可用窗口；不带 payload |
| 5 DATA | payload 对应 `[Offset, Offset+Length)` 的可靠字节 |
| 6 ACK | Offset 为连续接收终点，Limit 为接收信用；FIN 标志确认对端半关闭 |
| 7 FIN | Offset 为该方向最后字节之后的位置；另一方向可继续发送 |
| 8 RESET | 结束异常 Flow；可带简短原因 |
| 9 PING / 10 PONG | ID=0；PONG 原样回显 Offset 中的发送端单调时间标记 |

QUIC 控制 stream 还允许携带非零 Flow ID 的 ACK／OPENED／FIN／RESET，例如
已退休 Flow 的最终回复；它不为这些回复新建 per-flow stream。

## 交付、背压与恢复语义

每条 Flow 在两端分别维护发送未确认缓冲和接收未读取缓冲。ACK 的 Offset 是
`rxNext`：**对端会话层已连续接收**，不代表目标应用已执行，也不代表持久化。
Limit 为 `rxConsumed + window`，其中 `rxConsumed` 是代理桥接从 `Flow.Read`
取走的字节数，不是目标进程实际读取量。发送端只在远端信用内发送；本地未确认
缓冲达到窗口时，`Write` 阻塞，向应用施加背压。

[Flow.receive 与 sendLoop](../internal/session/session.go) 丢弃已接收的重复前缀，
部分重叠只追加新字节；超窗口数据和非法 ACK／FIN 状态会失败。当前承载提供流内
有序交付，PROTO-X 没有另建乱序重组队列、按包 ARQ 或 FEC。偏移与缓存主要用于
**外层载体重建后的重传去重**。

载体替换增加会话 generation，各 Flow 从已确认的 `txBase` 重发保留字节，重新
交换 OPEN／OPENED、ACK 和必要的 FIN。同一 Flow 的重复 OPEN 找到已有目标
socket，不会再次拨号。正常结束需要双向 FIN、最终 ACK、接收 EOF 被读取以及
没有在途记录；随后终止 sender、回收 stream，留下最终偏移的 tombstone。
墓碑可回答丢失的最终 FIN ACK，并按最高 ID 后方 8192 的范围裁剪；过旧 OPEN
不能重新打开目标。参见 [maintenance 与 receive](../internal/session/session.go)。

这一恢复机制要求**客户端进程、服务端进程、原会话和两端原 socket 仍然存活**。
外层断开时应用读写可能暂停，缓冲满后阻塞；仅断开载体不会被当作应用 EOF。
会话到期、显式 RESET、应用关闭或目标自行关闭则结束原连接。服务端重启、独立
服务器切换、复制证书或 token 都不能恢复旧 SSH／TCP socket；新请求可以通过新
会话建立，旧业务失败必须向应用暴露。

[Client.manage](../internal/app/client.go) 顺序尝试配置端点，每次尝试默认最多
1200 ms。已工作载体失败后等待 100 ms，从下一个端点开始；整轮失败再等 200 ms。
只有整轮未恢复成功且某端点明确返回 `session_lost`，才放弃旧会话；若只是全部
不可达，则保留到断连恢复租期到期。端点应指向同一会话拥有者的不同入口；混用
独立服务器仍可能提前放弃稍后可恢复的原会话。当前没有暖备用或并行路径竞速。
`test_rotate_seconds` 是故障注入开关，不能当作恢复时延保证。

## 调度、默认值与成本

每个 Flow 初始拥有 8192 字节稀疏流信用，以 4096 B/s 补充、上限 8192 字节。
DATA 被信用覆盖时进入高优先级；OPEN、ACK、FIN 等流元数据也优先。
[scheduler.Budget](../internal/scheduler/budget.go) 在两类均等待时最多连续放行
3 条高优先级记录，再放行 1 条低优先级记录；这是**记录数**规则，不是 3:1
带宽保证，也没有识别 SSH 或 AI 应用。

预算由每个 Session 的单向发送流共享，计费为每条记录的 `32 + payload + 64`
字节，最后 64 字节只是外层开销估计。已进入 TLS／QUIC 的字节不能再被调度器
抢占。心跳和排队的终止回复绕过此预算；真实 TLS／QUIC／IP 头、ACK 与重传也需
外部计数，因此 `rate_mbps` 不是严格线速上限。基础拥塞控制仍然生效。

[Defaults 与 Init](../internal/app/config.go) 的初始配置如下，均是实验起点：

| 项目 | 默认值 |
| --- | --- |
| 发送预算 | 服务端 8 Mbps；生成的客户端配置为 2 Mbps，每 Session、每方向 |
| 调度 | `priority=true`，`adaptive=false` |
| 应用窗口 / 活跃流 | 每方向每 Flow 64 KiB；每 Session 最多 32 条 Flow |
| 服务端会话 / 预认证等待 | 最多 2 个 Session；TLS 与 QUIC 共用 8 个认证槽 |
| 载体队列 | 入站记录 128 条；控制回复 64 条，控制队列耗尽时关闭载体 |
| 心跳 / 失联 / 断连租期 | 500 ms / 2 s / 90 s；维护循环按心跳周期检查 |
| 本地入口 / 目标策略 | 数字 loopback 上的 SOCKS5，生成配置为 `127.0.0.1:1088`；默认拒绝常见私网目标 |

可选 `adaptive` 用 RTT 相对历史最小值的增加估计排队，每次载体附加重置参考；
这只是待验证的降速／回升启发式。v0.1.1 默认由客户端发 PING、服务端回复 PONG，
两端仍按原阈值检查最后收包时间。服务端静默达到自己失联窗口的一半后会主动
补探测，以兼容心跳比其失联阈值更慢的客户端。正常默认连接两端合计每秒约 2 个 PING 与 2 个 PONG，
仅记录头为 128 B/s；服务端启用 `adaptive` 时，仍主动发 PING 获取自己的 RTT
样本。这是按配置计算的记录开销，QUIC/TLS、IP、ACK 等成本另见实测；v0.1 的
默认双端主动探测是每秒约 4 个 PING 与 4 个 PONG。默认最大应用
缓冲有效容量约 8 MiB，不能等同于 RSS 上限；QUIC、TLS、socket 缓冲和 Go 运行时
需要额外资源。8 槽限制已在 QUIC 等待控制流前执行，但不是公网抗洪泛证明。

本原型尚无 UDP ASSOCIATE、TUN、跨服务器 socket 恢复、FEC 或网站回落。固定 ALPN
和默认 SNI 具有识别特征；没有抗 DPI 或俄罗斯运营商普遍可达的证据。低预算与
稀疏流调度是否比同预算基线更好，应结合失败率、吞吐和外层开销评估，不能仅凭
设计推导。已有功能测试与边界见 [独立实现评审](review-workloads.md) 和
[安全评审](security-review.md)，比较入口见 [基线](baselines.md) 与
[负载说明](workloads.md)。
