# 独立实现评审与负载工具验证

评审者：`workloads` Agent；日期：2026-11-07（Europe/Moscow）。源码复核基线为
`5d80253`；下列会话和负载测试保留 2026-11-06 22:43 UTC 前冻结点的实际结果。
研发期间发现的问题由主 Agent 修改核心实现，评审者独立维护负载工具和
`internal/session/session_test.go`。

这是源码评审和有限功能测试，不是形式化证明、密码审计或俄罗斯实网结论。

## 已发现并修复的问题

| 问题 | 原有影响 | 当前处理及证据 |
|---|---|---|
| 正常 FIN 完成后仅从 flow map 删除，没有终止 sender | 每条结束的流留下一个等待中的 goroutine，长用内存增长 | 每流 `done` 与退休信号；24 条真实 TCP 目标流结束后检查退休通道及 sender 栈，测试通过 |
| 客户端没有推进 tombstone 清理所需的 ID 水位 | 客户端 tombstone 随连接数无限增长 | `Open` 更新 `maxID`；测试跨过 ID 水位后两端只保留新墓碑，重放旧 OPEN 不得重拨目标 |
| reset / 最终 ACK 在真正完成写入前被标记完成 | 队列等待或载体替换时可能提前回收状态 | `inFlight`、发送完成后的标记、`rxReadEOF`；FIN 恢复与正常回收测试通过 |
| 墓碑只记“已关闭”，丢失最后 FIN ACK 后只会 Reset | 已正确交付的连接在恢复末尾可能变成错误结束 | 墓碑保留两向最终 offset；故障注入丢掉服务端所有 FIN ACK，再替换载体，客户端依靠墓碑完成且目标只连接一次 |
| 控制回复可能同步阻塞接收循环，墓碑回复创建无人回收的 QUIC writer | 背压时接收与回复耦合；关闭流回复可能耗尽 stream 配额 | 主 Agent 改为容量 64 的独立控制队列，墓碑回复走控制 stream；双向控制压力测试通过。未把静态风险写成已在实网复现的故障 |
| `CloseWrite` 不广播满发送缓冲的条件变量 | 同时阻塞的 `Write` 只能等后续 ACK 或租期到期 | 新回归先实际失败；增加 `cond.Broadcast` 后通过 |
| 自适应速率的 4096 B/s 下限可能高于用户设置的 cap | 很低 cap 下反而突破配置 | 下限再限制到 cap；由主 Agent 修复。此项是边界源码评审，不是性能收益 |
| 核心 RTT 和 last-RX 用墙钟 | 虚机或 NTP 调整墙钟可能误报排队/失联 | 主 Agent 改为 session 起点的单调 elapsed；测试 Ping 同步改为 elapsed |
| 先删除 flow、后关闭退休通道 | `FlowCount()==0` 的观察者可能仍看到未退休 sender | 主 Agent 在同一临界区关闭退休通道；修复前由并行 race 测试发现偶发失败 |
| QUIC 等待首个控制 stream 发生在预认证槽位之前 | 未打开控制 stream 的连接可能积累等待 goroutine | `RunServer` 已在 `AcceptQUIC` 前占用与 TLS 共用的 8 个槽位，超额关闭 `busy`；安全评审 Agent 的有限回环检查观察到 8 个等待连接、第 9 个被关闭，详见 [安全评审](security-review.md) |

`carrier.seen` 的历史条目清理由主 Agent 同时修复。实际 QUIC stream 生命周期和
TLS 握手由主 Agent 的 carrier/app 测试覆盖；本文件不冒称内存管道已验证 QUIC。

## 会话测试覆盖的语义

`session_test.go` 使用 `net.Pipe` 包装为 carrier，以及真实 `net.Listener` 目标。
此处内存 carrier **没有运行 TLS**，刻意把状态机验证与密码承载验证分开。

1. 发送 2 MiB 确定字节，TCP 目标等到半关闭后返回 1 MiB + 31 字节；两向内容和
   EOF 均验证，避免把普通双向 echo 误当半关闭测试。
2. 2 MiB echo 进行中暂停受控源，执行 `Drop` / `Attach`；断开期间发送和接收
   缓冲不超过窗口；恢复后无丢失、重复或内容变化，服务端同一 socket 被保留，
   Dial 和 Accept 均恰好一次。
3. 300 ms 测试租期到期会唤醒阻塞 Read / Write，返回 `ErrSessionLost`；已过期
   会话拒绝新载体，不透明重拨旧业务。
4. 重复数据和部分重叠只交付一次；超窗口数据、非法 ACK、错误 FIN offset 和
   EOF 后新数据被拒绝。
5. 正常流退出、墓碑水位裁剪、旧 OPEN 防重拨、并发半关闭以及最终 FIN ACK
   丢失后的恢复均有回归测试。

最终实际运行命令：

```sh
go test -race -count=1 -timeout=45s ./internal/bench ./cmd/pxbench ./internal/session
```

在上述冻结点结果为：`internal/bench` 通过（2.255 s），`internal/session` 通过
（3.016 s），`cmd/pxbench` 编译通过。时长是该次测试进程输出，不是长期运行证据。

## 负载工具的测量修正

完整使用方法见 `internal/bench/README.md`。正式矩阵应同步重编客户端与受控源；
旧源没有新的单调 elapsed 字段，不能与新测量端混用。

- 默认小请求为无副作用的受控 `POST /small`，避免 Go HTTP 客户端在已写请求后
  自动重放 GET。可显式选择 GET；两种模式都记录 connection/write 尝试。
- 每次请求都保留成功、失败、超时、测试结束未完成、负载发生器拒绝的分母；
  成功分位数附带样本量，不靠删除失败优化结果。
- Echo 明确是单 outstanding 的 closed-loop；HTTP 是固定到达率 open-loop。
  原 TCP 流断开会被记录，下一条 echo 才创建新连接。
- SSE 的源计划时间、实际产生时间均增加相对同一源会话起点的**单调 elapsed**。
  source gap、产生延迟和 excess gap 只使用 elapsed；墙钟纳秒仅用于相关性元数据。
  用合成 +10 秒 / -1 小时墙钟跳变测试，源间隔仍准确为 10 ms。
- Linux VM smoke 发现：网络 poller 先触发父 deadline，而 `ctx.Err()` 尚未发布，
  导致约 47 ms / 267 ms 的末尾 echo 被错误记作 3 秒超时，并立即新开一次请求。
  现在 censoring、循环和定时等待同时检查单调 deadline，回归覆盖“Err 为 nil
  但 deadline 已过”以及 100 ms 无响应 echo 测试只产生一次 censored、零 timeout。
- 每条原始事件新增 `recorded_elapsed_ns`；不能用虚机墙钟差代替实际运行时长。
- `-background-mbps` 为每个下载 worker 的**源端应用负载**上限；4 KiB 平滑发送，
  阻塞后不积攒追赶突发。它不是代理总 wire cap。真实 16 KiB @ 1 Mbps 检查和
  非法速率输入检查通过，可用于所有协议同样降低后台负载的公平对照。

`results/smoke-20261106T2235` 是修正前的历史 smoke，原始证据应保留，但不能把
其中负 source delay 和末尾伪 timeout 当作协议性能。后续正式数据需使用冻结后
二进制及其哈希。

## 剩余验证边界

- 没有证明 TCP 目标进程或服务器失效后能恢复旧 socket；实现依赖同一服务器
  进程内的活会话和缓冲。
- 受控内存载体的确定性故障注入不等同于丢包、NAT rebinding、真实 LTE 切网或
  跨承载部署；这些需要单独网络实验。
- 控制队列耗尽会关闭 carrier，属于显式有界退化策略。QUIC 等待控制流前的
  [共享预认证槽位](../internal/app/server.go) 已修复并经有限边界检查；9 个回环
  连接不能证明长期认证客户端滥用或大规模未认证洪泛下的资源表现。此次未实施
  对公网的洪泛。
- Payload 缓冲的逻辑长度有界，不代表完整进程 RSS 只等于这些长度；QUIC、TLS、
  kernel socket buffer、Go 堆和 goroutine 都应计入真实部署资源记录。
- 未发现可据此宣布“全面优于 VLESS/Hysteria2”的依据；优劣必须由固定版本、
  相同负载和网络条件的正式矩阵及真实恢复测试给出。
