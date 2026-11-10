# v0.3 恢复改动独立复核

日期：2026-11-10。复核从 `e4c93d9` 上已有的未提交恢复原型开始，随后检查本轮新增的 attempt fence；原型不是已经部署的 v0.3。复核者独立于实现者，没有操作 VPS、生产服务或秘密配置。本文仅覆盖恢复和认证边界，不是协议安全证明。

## 结论与实际修复

旧原型把 TLS/ECH 备用准备与 HELLO 激活分开，这是正确的边界：准备阶段没有创建或恢复服务器 Session。只要 HELLO 已发出，候选失败就不再保证旧承载仍存活。

发现并在记录层替身上各重复 10 次复现了两个状态机问题：

1. 服务端成功写出 WELCOME，立即附着候选并关闭原承载。若回程 WELCOME 丢失，客户端可以超时，而服务端已经切换。这个窗口仍然存在，文档和代码注释已明确保留。
2. 较早 HELLO 的 WELCOME 写入被延迟；较新 HELLO 先完成恢复；随后较早握手结束，又替换较新的承载。原型没有在线路上交换顺序号，服务端的本地 generation 无法区分这两次激活。**本轮新增的单调 attempt fence 修复此回滚问题。**

这两个复现都在 `net.Pipe` 加可控写入替身上执行，故障点是 WELCOME 的本地完成与远端接收之间。它们验证真实服务器握手函数的状态变化，不是 TLS/QUIC 抓包、不等于测得真实网络发生概率，也没有证明未认证的外部观察者能够伪造 HELLO。

## Fence 的保证和边界

`Session.NextAttempt` 给客户端每次激活分配递增 `uint64`，包括失败尝试；纯备用准备不消耗序号。达到最大值后返回错误，不能回到零。序号属于 Session，因此新随机 Session ID 可建立独立顺序。

HELLO 和 WELCOME 携带 attempt。adaptive 客户端要求精确回显；旧服务器忽略该字段并返回零时，客户端拒绝附着，不退回无 fence 的模式。服务端 `AttachAttempt` 在同一个 `s.mu` 临界区内比较并发布：

- attempt 必须大于已经成功附着的非零 attempt。
- 重复、较小的 attempt 被拒绝。
- 一旦 Session 接受非零 attempt，普通 `Attach` 和 attempt=0 不能绕过 fence。
- 已关闭的候选不更新序号；已关闭的 Session 不接受候选。
- legacy 模式仍允许旧行为，供固定 v0.2 对照和兼容使用；它不具有新保证。

该设计排序的是**已经成功附着的尝试**。它不预留尚未完成握手的更高 attempt；较低 attempt 在更高 attempt 提交前仍可能先成功。较高 attempt 已附着后，较低 attempt 无法再回滚它。这个性质不需要多阶段预留协议。

服务端仍先发送 WELCOME，再尝试 `AttachAttempt`。因此 WELCOME OK 和精确回显表明服务器理解字段，不能单独证明候选最终赢得竞争；竞争输家会被关闭。回程 WELCOME 丢失也仍会产生双方短暂状态不一致。更高 attempt 的重试可以从中恢复，但不承诺该窗口内的原承载继续工作。若未来需要更强的双端提交语义，必须另行设计确认、超时和失败状态，不能仅多加一个 ACK 就宣布原子提交。

## 旧帧、流与锁顺序

`receiveFrame` 在 `s.mu` 内检查承载身份，并保持该锁直到 Flow 状态变更完成。旧承载已经出队的 DATA、ACK、FIN、RESET、OPEN 不能在新承载发布之后污染新代次。`Drop(old)` 也不会清除新承载。

可见调用路径遵循 `s.mu → f.mu`；发送循环在调用 `Current` 前不持有 `f.mu`，`Write` 只更新原子需求时间，不反向取 `s.mu`。未发现本轮引入的反向锁序。Flow 的 TCP 关闭与部分 trace 日志仍可能发生在持锁期间；这不是无限等待的证明，后续性能分析应保持 trace 配置一致。

目标 socket、流偏移、累计 ACK、有限发送窗口、去重和半关闭仍由原 Session/Flow 保存。新 attempt 只决定承载归属，不创建同一 Flow 的第二次目标请求。应用主动关闭、原进程消失或会话租期到期仍不能复活旧 TCP socket。原有真实 H2/H3 连续性测试和本轮故障实验是此项的行为依据；本复核没有把单独的状态机测试替代为所有应用连续性验证。

## 业务数据的因果进展复核

后续实现加入 `deliveryProof`，让已经可靠确认的业务上行数据成为路径仍有用的证据。它针对控制探针暂时无进展、其他 HTTP 流仍正常工作的情况；仅收到下行 DATA 仍不足以证明上行路径健康。`recovery_probe_only=true` 禁用这类业务证据，保留纯 PONG 的对照。

每个 Flow 只有八个固定 marker，保存尝试发送的**新 DATA 末端偏移和发送前时间**。发送循环在通过共享调度预算、再次检查当前承载/代次后，以 `Session.mu → Flow.mu` 的次序记录 marker，随即释放锁再执行承载 Send。这个时间是实际传输时间的下界：等待、阻塞或失败可能让判断更保守，不能使延迟反馈看起来比实际更新鲜。

代次改变时，以该 Flow 曾尝试发送的最高末端建立 replay floor。旧数据即使重发、以前的 ACK 丢失，也不成为新代次的新鲜证据。累计 ACK 只采用其完整覆盖、超过旧已确认偏移和 replay floor 的新 marker。八槽环被覆盖的旧 marker 直接失去证明能力，不扩展存储或估算一个更晚时间。首次 OPEN 的首次合法 OPENED 可以证明该 OPEN 曾经过往返；恢复过程中重复 OPEN/OPENED 不可以，因为服务端可能主动重新发布已有 Flow 的 OPENED 状态。

ACK 校验和证据提取在同一个 Flow 锁内完成；非法帧返回错误，重复/过期 ACK 没有新偏移，不产生新证据。旧承载帧仍先受 Session 代次检查。新增锁路径与既有接收路径同为 `Session → Flow`，没有在持有 Flow 锁时反取 Session 锁；网络 Send 不在这两个锁内执行。源码和重复 race 检查未发现新锁反转或无界队列。

路径保留尚未回复的 PING 供实际 PONG 计算 RTT；业务 ACK **不生成 RTT 样本**。若最新可证明发送时间为 S，最早未答探针时间为 P，则有效探针年龄为 `now − max(P, S)`。依据使用发送时间，而不是 ACK 到达时间，防止故障前已发出的数据在故障后晚到确认时掩盖当前失联。

本次审查发现并在冻结前修正一个决策边界：即使 S 晚于 P，若 `now − S > T`，晚到 ACK 也不能增加供管理器取消准备的 Proof；否则路径仍处于 Suspect/Confirmed 时，会无谓丢弃就绪备用并冷却一秒。现在旧反馈只能改善上述年龄下界，只有仍在当前阈值 T 内且晚于 P 的发送证据才会触发取消准备。

独立确定性测试构造 P=1,000 ms、T=150 ms、当前时刻=2,000 ms：确认 S=1,100 ms 的 ACK 仍保留 Confirmed 状态、有效年龄 900 ms、Proof 不变；确认 S=1,950 ms 后年龄变为 50 ms，才解除怀疑。另一路测试通过真实 Flow ACK 校验：控制探针已经 Confirmed，最近业务 DATA 的累计 ACK 可以解除怀疑；打开 probe-only 消融则仍为 Confirmed。这里的逻辑时钟/记录夹具是决策语义验证，不是实际网络秒数。

新增 [`delivery_review_test.go`](../internal/session/delivery_review_test.go) 的七项测试，在 race 下各重复 20 次通过；包括无效/陈旧/重复 ACK、跨代 replay floor、首次/重复 OPENED、100 次发送经过八槽环、旧承载 ACK 拒绝、下行 DATA 不生成证据、迟到反馈和 probe-only 消融。新核心下又运行真实 H2↔H3、私有 CA/名称/pin/ECH 与 ACK 合并的准备/激活集成，各方向重复 10 次通过，同一个目标 TCP 继续精确字节传输和半关闭。

局限是有意保守的：没有可证明新上行的纯下行流仍依赖探针；已经被八槽环覆盖或落在 replay floor 内的确认不提供这类进展；繁忙调度可能使发送前时间明显早于实际发包。它不增加带宽冗余，也不对应用重复执行请求。真实网络中减少了多少误准备、误切换和尾延迟，仍应由业务证据开/关的同条件实验回答，不能从这些通过的状态机测试直接得出。

## RTT 历史新鲜度修正复核

该路线目前保留为显式实验，应用默认 `recovery_count_history=true` 使用纯计数历史；后续对照出现不利证据，主线没有把单条夹具的改善当成采用新鲜度筛选的充分理由。

先前 pilot 暴露了纯 32 样本历史与探针频率的反馈：旧排队峰提高尾部阈值，策略随之降低探针频率，旧峰又因新样本到得更慢而长时间留在历史内。新的筛选保留同一承载最近 32 个匹配 PONG 的 RTT 和接收时间，先用全部原始样本的中位数得到 `H = max(2 s, 8 × rawMedianRTT)`，再按距**最后一次有效 PONG**的时间筛选；至少保留最近三条。

筛选和阈值计算只读取历史，不更新 `proof`、未答探针、最新有效回复时间或样本数。静默、重复/无匹配 PONG、未来时间戳不会让历史自动变新或让旧排队峰凭空消失。只有同一当前承载上的匹配 PONG 才能推进时间参考。这避免把“没有消息”当成链路已经恢复的证据；新的筛选也不修改 TLS、认证、attempt fence 或旧承载帧隔离。

索引审查与测试覆盖了冷启动 0/1/2 样本、3 样本下界、32 项缓冲区填满后多次回绕。按正常写入不变量，`next` 始终在 0–31，回溯索引也在 0–31；不足三条时直接返回后备值，筛选之后至少三条，两个分位索引均合法。恰好位于 H 边界的样本被保留，超过边界的旧样本在下一次有效回复后排除。`recovery_count_history=true` 保留旧纯计数窗口，作为显式消融。

独立新增四项测试到 `recovery_fence_test.go`：稀疏 RTT 从 1 ns 到 30 s、每小时一个样本且累计 80 条；窗口的精确边界；100 次无回复探针以及重放/无匹配/未来 PONG 不更新证据；换代清空历史、保留消融模式，旧 PONG 和被拒绝的旧 attempt 不改变新代次状态。与四项主线路径测试一起，在 race 下各重复 20 次通过。

主线的固定输入夹具可重现纯计数历史的 **622 ms** 阈值；该夹具中新鲜度筛选后为 **150 ms**。这说明代码能够消除指定旧排队峰的驻留机制，不等于新的真实网络恢复时延或误判率。它不是统一缩短所有超时：独立稀疏测试中持续高 RTT 仍保留至少对应 RTT 的阈值，静默也不降低已有判断依据。

仍有明确局限：原始 32 条的中位数可能在长期慢→快转换期间保持较大的 H；至少三条规则在极稀疏采样下会保留很旧的证据。三个相关样本不提供统计置信保证，间歇性拥塞和非平稳路径仍可能造成过早准备或较慢恢复。2 s 与 8 倍是可检验的策略常数，必须用未用于选择它们的轨迹和真实链路对照来检查泛化，不能仅凭这一条 pilot 夹具宣布最优。

## ACK 合并复核

`ack_coalesce` 默认关闭。启用后只延迟累计接收 ACK：无 RTT 样本时 5 ms，有样本时 `clamp(RTT/4, 1 ms, 10 ms)`。下一次到达的普通数据不会不断延长已有截止时间。未确认接收量达到窗口四分之一、应用消费释放窗口信用、重复/超前记录需要对齐、FIN 或承载换代时，ACK 立即具备发送资格，之后仍受共享发送调度约束。

DATA 到达后立即唤醒应用读取，OPEN、真实 DATA 和 FIN 不等待 ACK 合并计时器。累计偏移、去重和窗口含义没有改变；对端不需要启用相同选项。源码复核未发现此改动引入新的锁反转、越过窗口或取消后仍等待计时器的问题。流的 `lastAcked` 只来自单调接收偏移，不会被新的承载重置为更高值。

已有两项 ACK 测试以及三项路径判断测试，在 race 下各重复 20 次通过。窗口/半关闭测试确实经历了承载替换和同一目标连接，但其源端先读完请求再回显，并非故障时两方向都有业务载荷在途。小回复测试证明 50 次单字节往返在一秒内完成，不能独立证明没有额外尾延迟。测试之外的收益、计时器分配成本和线速字节影响仍应由固定配置的对照测量回答。

路径测试验证未匹配 PONG 不生成往返进展、有限队列保留最早未答探针、慢/抖动 RTT 获得更长阈值，以及单向下行数据不掩盖未答上行探针。它们是确定性的本地状态夹具，不是黑洞误报率或真实网络分类结果。

## 真实备用准备与激活验证

新增实际 H2→H3、H3→H2 测试，两个方向各重复 10 次。每次使用新私有 CA 签发证书，正常验证链、inner 名称和附加 pin；直接从每条原生准备连接核验 `HandshakeComplete`、TLS 1.3、ALPN 与 `ECHAccepted`，不是另开诊断连接代替。

测试先建立一个服务器 Session 和一个真实目标 TCP socket。完成备用 TLS/ECH 准备后取消上下文并关闭准备，或使用预先取消的上下文让准备失败，服务器仍保持原 Session 和 generation 1；原 Flow 能继续往返，目标累计 accept=1。随后通过另一承载激活同一 Session，完成后取消准备及激活的短期上下文，服务器进入 generation 2，原 Flow 继续传输。重复 `Activate` 被拒绝且不关闭已成功激活的路径。

每次切换后跨多个窗口传输 **196,608 字节**，校验完整字节与 EOF/半关闭，目标累计 accept 仍为 1。两端启用了 ACK 合并。此结果验证 loopback 上的所有权、上下文生存期、认证恢复和原 socket 连续性，不等于弱网故障恢复时间或公网证书可用性结论。

## 认证与 ECH

准备和激活继续使用 `WebClientTLS`：配置 ECH 时要求 `ECHAccepted`，验证链/名称及可选 pin；客户端启动拒绝把 ECH 配置与旧裸 TLS/QUIC fallback 混用。准备成功只能证明备用 TLS/ECH 握手成功，不证明 HTTP 控制 POST、WELCOME、目标拨号或业务数据已经完成。

HTTP 认证仍使用该 TLS 连接的 exporter、新鲜 nonce 和 HMAC。HTTP 流绑定同一连接的 exporter；新承载重新认证，而不是复用旧连接头。HELLO 中的 attempt 和 Session ID 位于 TLS 保护的载荷内，改变它们需要合法连接及共享 token；fence 不取代认证、防重放或会话身份。

共享 token 仍是单一信任域。持有 token 且已知 Session ID 的参与者不在本方案的相互隔离保证内。仅知道 IP、观察加密帧或拥有自己普通站点连接的主动观察者，不能因此取得用户连接的 exporter 或会话明文。

## 独立验证

本地环境：Go 1.27.1，macOS arm64。新增独立测试文件：

- [`internal/session/recovery_fence_test.go`](../internal/session/recovery_fence_test.go)：legacy 兼容和升级 fence、较小/重复/零 attempt、关闭候选、32 次并发附着、64 次并发序号分配、序号溢出，以及旧代次的 DATA/ACK/FIN/RESET/OPEN 隔离；后续追加四项历史新鲜度、稀疏采样与换代测试。
- [`internal/app/recovery_fence_test.go`](../internal/app/recovery_fence_test.go)：延迟 WELCOME 不得覆盖新 attempt、WELCOME 丢失边界与更高 attempt 重试、真实 TLS 下精确/缺失/错误 attempt 回显。
- [`internal/app/recovery_prepare_test.go`](../internal/app/recovery_prepare_test.go)：真实 H2/H3、私有 CA/名称/pin/ECH、准备取消与失败、单次激活、短期上下文结束、原目标 TCP 连续和半关闭。
- [`internal/session/delivery_review_test.go`](../internal/session/delivery_review_test.go)：因果业务进展、八槽 marker、replay floor、延迟/非法 ACK 与 probe-only 消融。

执行：

```sh
go test -race ./internal/app ./internal/session -run '^TestRecovery' -count=10
go test -race ./internal/cover ./internal/carrier -run 'Test.*(Gate|Auth|Replay|WebTLS|WebECH)' -count=1
go test -race ./internal/app -run '^TestPreparedRecovery' -count=10
go test -race ./internal/session -run 'Test(CoalescedACK|Path)' -count=20
go test -race ./internal/session -run 'Test(RecoveryHistory|Path)' -count=20
go test -race ./internal/session -run '^TestDeliveryReview' -count=20
```

第一条在追加历史测试之前实际通过：当时的 7 个顶层恢复测试重复 10 次；回显测试每次另包含 3 个子场景。第二条实际通过，重跑了已有 exporter、防重放、证书和 ECH 正反例。第三条实际通过，共 20 个双承载准备/激活场景；第四条在追加主线历史夹具之前实际通过，当时的 5 个顶层测试各重复 20 次。第五条在新鲜度修正后实际通过，8 个顶层测试各重复 20 次。第六条在新增业务进展后实际通过，7 个顶层测试各重复 20 次；第三条也在该核心版本上重新通过。完整项目 race/vet、冻结构建和部署检查由主线实验记录报告，不从这些定向检查外推。

本地原始日志保存在忽略目录 `.local/review-v03/`。回归测试已纳入源码，可用上述命令重新执行；早期两个问题的发现记录不能被当前测试通过覆盖。

## 仍需纳入结果解释的事项

- 接收匹配 PONG 才能证明该路径有过往返进展；未匹配的下行 DATA 不足以证明上行正常。此改进没有把序贯规则变成拥塞与黑洞的完美分类器。
- adaptive 控制探针可加快到 100 ms；`QueueControl` 绕过数据调度预算。探针、TLS 备用准备、重传和封装必须从实际链路计数中纳入成本。
- 客户端根据 RTT 尾部延长耐心时，服务端仍可能受固定 `DeadAfter` 限制。高 RTT/拥塞结论必须检查两端的首次关闭原因。
- 初审发现直接替换旧承载未累计其记录统计；本轮已统一通过 `retireLink` 关闭并累计，覆盖直接替换和 Drop。`Session.RecordSent/Received` 仍是退役应用记录的诊断快照，关闭时尚在完成的并发计数可能不完全收敛，也不含全部外层握手、封装、填充、重传与 QUIC ACK。因此不能当作线速计量，成本比较继续使用明确层次的 relay/抓包或链路计数。
