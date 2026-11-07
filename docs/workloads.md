# 受控业务负载与测量口径

代码基线：`5d80253`；更新日期：2026-11-07（Europe/Moscow）。`pxbench` 同时提供
受控目标服务和负载客户端，用已知内容、明确节奏的流量测量代理后的应用等待。
详细参数见 [内部 README](../internal/bench/README.md) 与
[命令入口](../cmd/pxbench/main.go)。本页不把工具通过自测写成协议性能结论。

## 运行方式

在仓库根目录构建；目标服务应运行在代理服务端可访问的位置。以下示例可用于
同机实验；分机时，目标地址仍从**代理服务端**解释。所有业务显式经过 `-proxy`
的 SOCKS5 CONNECT，域名交给 SOCKS 服务端解析，不读取系统或环境代理设置。
`-proxy direct` 只作标明的工具对照组。

```sh
go build -o bin/pxbench ./cmd/pxbench
bin/pxbench serve -http 127.0.0.1:18080 -echo 127.0.0.1:18081
```

在另一终端运行负载，代理服务须已启动：

```sh
bin/pxbench run \
  -proxy 127.0.0.1:1088 \
  -http-target http://127.0.0.1:18080 \
  -echo-target 127.0.0.1:18081 \
  -duration 30s -rps 5 -background 1 \
  -run-id example -output .local/results/example.jsonl
```

PROTO-X 默认拒绝私网目标；实验配置需显式设置 `allow_private_targets:true`
才可访问上述 loopback fixture。namespace 实验应把 fixture 放在服务端一侧，
受损链路只承载待测代理流量，管理通道独立。参见 [实验环境](lab.md)。

HTTPS 可用 `serve -http '' -https 127.0.0.1:18443 -cert … -key …` 启动；测量端
设置对应 `-http-target https://…` 和 `-ca`。证书 SAN 必须包含目标 IP／域名。
完整可执行示例见内部 README。HTTP 客户端固定为 HTTP/1.1；比较 VLESS Vision
时宜包括真实内层 TLS 负载，并记录是否开启 `-cold-http`（禁用 HTTP keepalive）。

## 五种负载

| 业务 | 默认参数和调度 | 应查看的结果 |
| --- | --- | --- |
| 小 HTTP | 5 请求/s，固定到达计划（open-loop）；验证 1024 字节响应；3 s 超时；并发上限 64 | 排队、TTFB、请求总时延、计划到完成时延、完整状态分母 |
| 持久 Echo | 64 字节带序号内容；最小起始间隔 100 ms；一次仅一个未完成请求（closed-loop） | 成功时延、失败／超时／删失、连接次数、原 socket 是否保留 |
| SSE | 每 50 ms 计划产生一个带序号 token；源端独立生产者；最多排队 256 个 | 接收间隔、源间隔、额外间隔、源延迟、重连和终止停顿 |
| 后台下载 | 默认 1 个连续下载，逐块校验确定字节 | 应用有效字节、吞吐、错误与中断 |
| 后台上传 | 默认关闭；`-uploads N` 开启，每次默认 256 KiB | 仅服务端确认完成的字节计入 goodput；未确认尾块另记 |

默认小请求为受控、无副作用的 **POST /small**，避免 Go HTTP 客户端在请求字节
已经写出后自动重放。零字节写出时仍可能重新尝试；`-http-method GET` 则允许
正常的幂等重试。两者都记录 `http_connection`、`http_write` 和尝试次数。
参见 [runHTTP 与 httpOne](../internal/bench/run.go)。

Echo 失败会结束旧 socket，下一条请求才显式重连，不静默重放失败请求。它是
闭环负载：慢或失败的路径在同样时间内产生更少样本，不能把成功分位数较低解释
成同样业务压力下的优势。读恢复结果时必须同时核对连接次数和失败分母。

`-background-mbps 6` 表示**每个下载 worker 的源端应用预算**为 6 Mbps；默认
0 不限速，多个 worker 各得该预算。源端按 4 KiB 分块，首块可立即发送，阻塞后
不积攒追赶突发；定时精度、背压或容量可能让实际速率更低。这不是代理总线速
上限，交互流量、加密、ACK 和重传不在其中。给所有基线使用相同参数，可以单独
检查减少后台负载的通用收益。参见 [FixtureHandler](../internal/bench/serve.go)。

各负载可分别用 `-rps 0`、`-echo-interval 0`、`-stream-interval 0`、
`-background 0`、`-uploads 0` 关闭。

## SSE 时间与停顿

每个 token 包含序号、确定 payload、源端计划／实际产生时间，以及相对**当前
源连接起点**的单调 elapsed 纳秒。源端产生与 socket flush 分离；256-token
队列耗尽是显式源错误，不能被解释成网络交付成功。

- 源产生延迟 = 源实际 elapsed − 源计划 elapsed。
- 同一源连接内的源间隔 = 相邻 token 的实际产生 elapsed 之差。
- 接收间隔使用客户端单调时间；额外间隔 = max(0，接收间隔 − 源间隔)。

这里没有相减两台机器的绝对时钟，**不测量单向传输时延**。源端墙钟字段只供
关联。重连后序号从 0 开始；跨连接的接收间隔保留并标注，不套用同一源连接的
源间隔公式。摘要统计超过 250 ms／1000 ms 的接收及额外间隔。

连接终止后的未完成间隔和整轮最后一个 token 之后的
`sse.run_tail_gap_ms` 单独作为右删失记录：只能知道“至少已等待这么久”。
它们可能描述重叠时间段，不能与已完成间隔相加当成独立停顿次数，也不能因
最后没有 token 就把长卡顿删掉。参见 [runSSE](../internal/bench/run.go)。

## 原始证据、统计与已验证范围

每轮写出 JSONL 和同名 `.summary.json`，权限 `0600`，拒绝覆盖已有文件。
原始事件包括配置、每次 HTTP／Echo、SSE token 与连接事件、下载区间、上传
完成和运行末尾。文件可能含端点元数据，发布前需脱敏。

每次操作只有一种状态：`success`、`failure`、`timeout`、`censored`（整轮结束
时未完成）或 `rejected`（发生器并发已满）。成功分位数使用最近秩
`ceil(p × N)`，附带样本数；完整状态分母必须一起报告。10 个成功样本的 p99
只是最大值，不能当成稳定的尾延迟估计。参见
[Event、OperationStats 与 distribution](../internal/bench/events.go)。

调度与删失同时检查父上下文的**单调 deadline**和 `ctx.Err()`，防止 socket
先超时、context 通知稍后到达的竞态制造假超时或多发请求。每条原始事件还有
`recorded_elapsed_ns`；运行时长不用虚机墙钟差计算。

冻结前实际运行过：

```sh
go test -race -count=1 -timeout=45s ./internal/bench ./cmd/pxbench ./internal/session
```

该次 bench 与 session 测试通过，命令包编译通过。负载测试覆盖显式 SOCKS 路径
中的五类业务、内容损坏、序号／源节奏、状态分母、防覆盖、源端 pacing、合成
墙钟跳变和运行截止竞态。会话测试另外覆盖字节去重、半关闭及载体重建时保留
目标 socket；详见 [独立实现评审](review-workloads.md)。这些是有限功能测试。

历史 `results/smoke-20261106T2235` 使用修正前工具，包含虚机墙钟回跳造成的负
源延迟，以及运行末尾误记的 Echo timeout。保留原始证据，但不能据此作正式
协议性能比较。后续实验必须同步重编**负载端与源端**并记录二进制哈希。

`pxbench` 不模拟 IP 丢包、不测外层字节或独立采集代理 CPU／RSS，也没有检测器
或抗识别结论。比较需保存 run-id、版本／配置、路径、故障时刻、实际时长及外部
流量／资源计数；保持各协议的负载与统计口径一致。基线版本与配置见
[baselines.md](baselines.md)，网络条件及独立重复由实验矩阵记录。
