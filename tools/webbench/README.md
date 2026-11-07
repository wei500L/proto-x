# HTTP 承载与填充的本地开销检查

`run.py` 冻结给定的 PROTO-X、pxbench 和计数 relay，随后启动只监听 loopback 的
独立测试进程。该工具不访问 VPS。每个新输出目录只使用一次；中途失败和已生成的
原始业务事件同样保留。完整配置、证书、令牌、进程日志和源文件快照留在 `.local/`。

正式默认矩阵为两轮，每例 12 秒。顺序先为 `h2-p0, h3-p127, h2-p127, h3-p0,
tls, quic`，第二轮倒序。每例启用同一二进制的一个承载和一个端点；旧 `tls/quic`
用 `protox init --legacy` 生成。服务端/客户端发送调度预算为 8/2 Mbps，最多 32 流、
64 KiB 窗口、开启 priority、关闭 adaptive。Web 使用显式开发证书 pin，未开启 ECH。

所有业务实际经过 SOCKS：5 次/秒的 1024 字节 POST 响应、100ms 一次的持久 echo、
50ms 源节奏的 SSE，以及一个源端按 2 Mbps 发送的后台下载。HTTP keepalive 开启。
后台源限速和 PROTO-X 发送预算都不是总外层字节限速。Web 调度器按记录大小加填充
上界预留预算；实际随机填充可以更少。TLS/QUIC/HTTP 的全部外层开销不在该预算内。

```sh
python3 tools/webbench/run.py \
  --protox .local/protox-web --pxbench bin/pxbench \
  --protox-sha256 REVIEWED_BINARY_SHA256 \
  --private .local/webbench/study-new \
  --out results/web-overhead-20261107/study-new \
  --label study-new
python3 tools/webbench/summarize.py results/web-overhead-20261107/study-new
```

短冒烟使用 `--pilot --rounds 1 --duration 1.5`，不得并入正式结果。协议二进制必须
提供期望哈希，冻结前后核对；所有实际命令、二进制 build info 和文件哈希均留存。
源快照记录的是冻结时仓库状态，不自动证明已提供的二进制由该精确快照构建。

每轮的 `trial.json` 保存完整命令、配置摘要、退出状态和采样 RSS。
`events.jsonl` / `events.summary.json` 保留业务分母、失败、超时和右删失，发布时只
替换本地路径。`relay-events.jsonl` 不含 payload 或私有 UDP 映射，保留所有计数与
故障事件。relay 的 `--capture-bytes 0 --capture-packets 0` 只关闭内容保存；
`capture_truncated:true` 表示没有保存内容，不表示转发丢包或计数被截断。

字节计数覆盖握手、300ms 启动后空闲、业务和退出。TCP 统计是实际 TLS 字节及
relay 读取次数，不是 IP 包数/重传数；UDP 统计是真实 UDP payload 字节与数据报数，
不包含 UDP/IP 头或网卡开销。每 200ms 尝试采样 RSS，实际时间戳保留；最大值是
采样峰值下界，非操作系统高水位。`ps %cpu` 仅作诊断，不能当作区间 CPU 成本。

摘要独立从原始事件重建分母、最近秩分位数、SSE 源/接收/额外/终止间隔和下载字节，
并核对证据哈希与 relay 正常结束。每轮分别比较填充开销，不汇总掩盖失败。
归一化指标是“双向承载字节 / 已验证接收应用字节”，分母不含请求、内层 HTTP/SSE
语法与时间戳，故不是纯协议开销百分比。环回时延不支持弱网、抗识别或实际俄罗斯
网络中的优越性结论。
