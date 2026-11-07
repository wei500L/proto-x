# 稀疏 QUIC DATAGRAM 副本：独立源码评审

日期：2026-11-07（Europe/Moscow）；评审者：workloads Agent。范围仅为隔离工作树
中基于 `5d80253` 的未提交原型和本机 quic-go v0.65.0 源码。本次没有修改实现、
执行测试或操作 VPS；测试运行结果应由实际运行记录另行给出。

在原型发送同一份不可变字节的前提下，未从本次检查中发现副本造成可靠字节丢失、
重复交付、越窗口或提前 FIN 的路径。健康链路误扣预算的常见路径及副本占用可靠
接收队列的问题已由主开发者修复；QUIC 内部发送期限和副本先交付后恢复的测试覆盖
仍有限制。
这不是形式化证明，也不构成性能收益结论。

复核时的文件 SHA-256 前缀：

| 文件 | 前缀 |
| --- | --- |
| `internal/session/hints.go` | `288fe61ae98c1956` |
| `internal/session/session.go` | `15a51ecde9708c22` |
| `internal/carrier/carrier.go` | `381c9e7630e0104c` |
| `internal/session/hints_test.go` | `cce62c8be9b2192e` |
| `internal/carrier/hints_test.go` | `34a214ccc38250ae` |
| `internal/app/integration_test.go` | `efb56b335a388ce3` |

## 已修复：原字节已 ACK，副本仍先扣主预算

初次审查的 `hints.go` 哈希前缀为 `30d5a6597e6620a3`。当时
`hintUseful` 只在定时前、两个 `Acquire` 后执行。可由代码直接构造的时序为：

1. 原 DATA 写入 QUIC 后，副本进入 worker，检查时尚未 ACK。
2. 等待 8 ms 期间原 DATA 已 ACK，例如健康低 RTT 链路。
3. worker 仍取得副本预算及主预算，然后才发现无用、增加 `HintSkipped`。

因此即使实际未发送这个副本，也会推迟待发送原始记录，制造额外限速。不能把
这种少发后台字节引起的尾延迟变化归因于冗余交付。

当前 [sendHints 源码（研究补丁）](../patches/sparse-copies.patch) 已在 8 ms 等待后和独立副本
预算等待后复查用途，在这些时刻已 ACK 的副本不再消耗后续主预算。本次已读取
修改后源码，未冒称相关回归测试已经运行。ACK 仍可能与主预算放行竞争；预算
一旦放行没有退款，所以 `HintSkipped` 并不意味着完全未消耗调度额度。这是
当前保守计费的剩余边界，区别于上述可避免的固定 8 ms 路径。

## 仍有限制：40 ms 不是 QUIC 发送或交付期限

[SendHint](../../internal/carrier/carrier.go) 调用 `Conn.SendDatagram`，后者
进入 quic-go 的 [datagramQueue.Add](https://github.com/quic-go/quic-go/blob/v0.65.0/datagram_queue.go)。
队列最多 32 条；满时等待出队或连接关闭，接口不接收调用者 context。已入队项
也没有有效期字段。

因此应用在第 39 ms 通过用途检查后，可能阻塞到第 100 ms 才入队；已入队副本
还可能继续等拥塞窗口。`context.WithDeadline` 只能中止之前的预算等待，不能
取消这次 `SendDatagram` 或撤回它的队列项。副本 worker 在此期间不能处理其余
副本，应用侧 64 条队列会填满并丢弃新副本。此处是源码确定的条件路径，不是
本次已在真实链路观察到的 100 ms 数字。

主开发者已把常量改为 `hintSubmitWindow`，并明确它是**调用 QUIC 前的年龄
检查**；不能理解为在 40 ms 内完成入队。当前保留原 quic-go 接口，内部过期问题
尚未解决。它不会凭空增加可靠字节；连接关闭会唤醒库内等待，不应据此声称永久
goroutine 泄漏。它仍会让拥塞恢复时的陈旧副本占用线路，后续实验必须纳入这项
代价。发送端期限保证需要可取消／可过期的队列支持，仅增加外围 context 不够。

## 已修复：副本占用可靠记录的接收队列

初审的 `carrier.go` 哈希前缀为 `3e5148866f3f8424`，其中
[datagramLoop](../../internal/carrier/carrier.go) 和 `readLoop` 共用容量 128
的 `l.in`。副本入队的 `default` 只保证副本生产者不等待，没有为可靠记录保留
空间。若 Session 消费者暂时停顿，128 条合法副本可以先占满队列，随后可靠
ACK／FIN／DATA 的 `readLoop` 阻塞在同一 channel。消费者恢复后，可靠记录还需
排在已有副本后面处理。

这是明确的共享队列队头等待，原注释“optional copy must not stall the
reliable record receiver”未实现所描述的隔离。没有证据说它在正常负载下必然出现
显著时延；但在 CPU 压力或突发到达条件下，可能直接损害本功能追求的交互体验。

当前已拆出容量 32 的 `Link.hints`，副本不再占用可靠 `l.in` 的位置；Session
改用 `NextFrame`，优先取得已经排队的可靠记录。若可靠记录与副本同时新到达，
仍可能先处理一条副本；不能解释为绝对抢占。修改后已从源码核对，新增
`TestCopyQueueCannotDelayAlreadyQueuedReliableControl` 将副本队列填满，再放入
可靠 ACK，断言先返回 ACK。本次未执行该检查，也未把队列隔离外推为 CPU／线路
成本隔离。

## 已核对的交付、信用与生命周期关系

- `queueHints` 只在原可靠 `Send` 成功后，为稀疏信用覆盖的 DATA 复制 payload；
  单份最多 900 字节，原可靠路径始终保留全部原字节。队列满丢副本不会丢原始数据。
- `Unreliable` 只是本地 metadata，不在线上编码；DATAGRAM 解析严格限制 DATA、
  奇数非零 ID、零 Flags／Limit、完整长度。不能通过 DATAGRAM 注入 OPEN、ACK、
  FIN 或 RESET。未知 Flow 的合法副本被忽略，不拨号、不推进 ID 水位。
- [Flow.receive](../../internal/session/session.go) 对未打开、已失败、未来偏移、
  溢出、越接收窗口和 FIN 后的新字节副本直接忽略。连续新后缀走原来的接收缓冲，
  以后可靠原件只追加未交付部分。副本没有更新远端信用，也没有新增乱序缓冲。
- 副本先到后产生的 ACK 仍只表示会话层已收到字节。发送端可以据此修剪重传
  缓冲，因为接收端保留字节；若外层随后断开，两端活 Session 以相同 offset
  恢复。它不是目标应用已执行或服务器重启后持久化交付的证明。
- FIN 仍来自可靠记录，携带最终字节 offset；同一流可靠记录顺序及接收 EOF
  检查继续生效。退休后的副本被忽略，不重新建立目标 socket。墓碑与最终 FIN
  ACK 的原有机制没有因 DATAGRAM 而新增依赖。
- 提交前检查 Flow 退休／错误、ACK 水位、当前 Link 和 generation。旧 Link
  被替换会关闭；Session 接收循环也核对当前 Link。检查之后与关闭仍可能竞争，
  所以会有已无用副本尝试发送，但在本次同字节语义下没有找到因此破坏交付的路径。

上述判断依赖原件与副本携带相同内容。接收端采用“先收到的连续字节生效”，不会
把之后可靠记录的重复前缀重新与已交付内容比较。网络包由 QUIC 认证；若认证端点
自身发送矛盾内容，不能宣称可靠 stream 会自动纠正已交付的副本。

## 测试目前证明什么

| 源码中的检查 | 实际覆盖与不足 |
| --- | --- |
| `TestSparseCopyDeliveredOnceAcrossOriginalOverlap` | 直接向 Flow 注入先到副本和重叠原件，检查字节及计数；未运行 worker、预算或 QUIC 队列 |
| `TestOptionalCopyCannotAdvanceAcrossGapOrMutateControlState` | 检查未来偏移、控制类型、溢出和过大副本被忽略；是 Flow 层检查 |
| `TestOptionalCopyRespectsConsumedWindowAndFinishedStream` | 检查满窗口及 FIN 后新字节；没有交织主预算等待与退休 |
| `TestQUICAuthenticatedDatagramCarriesOnlyOptionalDATA` | 实际 QUIC、证书 pin、畸形 OPEN 丢弃和 DATA metadata；测试 HELLO 是 fixture 字节，没有校验应用 token，不能单靠此项证明应用认证 |
| `TestCopyQueueCannotDelayAlreadyQueuedReliableControl` | 填满独立副本队列，确认已排队可靠 ACK 优先；没有运行网络或制造 CPU 压力 |
| `TestQUICToTLSWithSparseCopiesRetainsOriginAndBytes` | 当前增加每方向 15 ms 的受控 FIFO 延迟和 `HintSent > 0` 断言，再检查 QUIC→TLS 字节与单次目标 socket；没有要求副本先交付 |

最后一项初稿（哈希前缀 `b03d295d4b4df18d`）即使 `queueHints` 丢弃所有副本，
仍能沿原可靠路径通过。该问题已通过延迟路径和提交计数断言修正；本次读取了
修改后测试，未执行它。当前检查要求**实际向 QUIC 提交过副本**，而不是只开启
选项；仍不能证明先由副本交付的字节与恢复交织正确。

若要覆盖后一语义，应控制原件暂停点，使 `HintDelivered > 0`，在这些字节已
ACK、可靠原件未到时替换载体，再检查完整内容、半关闭和单次目标拨号。固定
延迟无丢包路径不能保证产生此先后关系。这个缺口与“测试正在执行但本次未取得
结果”是两件事。

## 性能归因和开关语义

`sparse_redundancy=false` 当前只关闭本端副本发送。QUIC 配置始终启用 DATAGRAM
能力，接收端不检查这个布尔值。无副本对照应关闭**两端**；只关客户端不能禁止
服务端下行副本。若希望开关表示双向禁用，需要另外定义协商／接收策略。

`HintSent` 是 QUIC 成功接受入队的数量，不是线上实际包数；MTU 变化还可能在
打包时丢弃。`HintDelivered` 是副本先贡献的字节数，不能命名为“已修复丢包
字节”。原可靠 `Send` 返回时数据可以仍在 QUIC 缓冲中；8 ms 从函数返回计算，
不是从原包离开发送口计算。quic-go 的
[packet_packer](https://github.com/quic-go/quic-go/blob/v0.65.0/packet_packer.go)
在普通 STREAM 数据前装入 DATAGRAM，副本也比 2048 字节原记录更小。故无丢包
时仍可能因打包顺序、分块和记录读取等待而先交付；先交付本身不是独立丢包恢复证据。

副本预算为 `min(配置速率 × 10%, 64 KiB/s)`，并再计入同一个主预算；关闭
整形时仍有 64 KiB/s 副本上限。两者按头部、payload 及估计开销计费，允许单条
记录初始放行，并非任意短时间窗内的硬 10% 线上比例。副本可能额外引发可靠 ACK，
QUIC 头、ACK、重传和过期后仍发出的副本都要进入外层成本测量。

保留原型的依据应是固定总预算下，成功率、完整失败分母、应用停顿／分位数和
goodput 共同改善；加上无丢包对照及相同源端后台限速，可区分多发副本与少发后台
流量的收益。已有计数器有助于解释，但不能取代外层抓包、实际发送时间或独立重复。
