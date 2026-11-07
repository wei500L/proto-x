# 信用窗口诊断：旧fork + Brutal6/1.5，seed227

扩大应用信用窗口确实提高了有效吞吐：64/128/256KiB分别为3.634/5.165/5.505Mbps；HTTP/echo p95仍约151–160ms。本次数据支持“64KiB窗口约束了吞吐”的判断，不支持“只扩大窗口便能改善交互延迟”，也不用于选择部署默认值。

同一个冻结CC二进制46b55aa58073753d2a3fa16d76c117ce86692eaca57a2b05e355e52700c45819，双方Brutal发送6/1.5Mbps、丢包补偿开启、应用pacer8/2Mbps、priority=true、adaptive=false。只改变两端window_bytes；三个批次的脱敏server/client完整配置逐字段比较，除window_bytes完全相同。两端实际CC/QUIC日志全部通过检查。

共同链路：本地Linux VM包级netem、物理8/2Mbps、名义RTT60ms、每方向1%丢包/5ms抖动、额外名义队列100ms。每项3秒预热加25秒测量，HTTP POST5/s（验证自有CA的HTTPS keep-alive）、echo最小间隔100ms、SSE源端50ms、一个不限速后台下载、请求超时3秒、每进程GOMAXPROCS=1。按seed227预先打乱窗口顺序为64→256→128KiB；相同netem seed不保证相同业务消息逐个遇到同样丢包。

| 双端窗口KiB | HTTP成功/总数 | HTTP p95 / p99 ms | Echo成功/总数 | Echo p95 ms | SSE p99 / max ms | 下载Mbps | 双向qdisc Mbps |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 64 | 125/125 | 156.2 / 174.6 | 234/235 | 151.4 | 67.5 / 132.3 | 3.634 | 4.493 |
| 128 | 125/125 | 154.2 / 161.6 | 226/227 | 156.2 | 126.4 / 134.4 | 5.165 | 6.210 |
| 256 | 125/125 | 160.0 / 167.5 | 236/236 | 154.0 | 63.5 / 127.6 | 5.505 | 6.602 |

| 双端窗口KiB | Server/Client峰值MiB | Server/Client CPU% | qdisc/下载字节比 |
|---:|---:|---:|---:|
| 64 | 15.4 / 17.4 | 3.4 / 2.7 | 1.236 |
| 128 | 15.3 / 17.3 | 5.5 / 4.4 | 1.202 |
| 256 | 17.1 / 15.4 | 5.5 / 4.4 | 1.199 |

三个运行全部完成，HTTP375/375，无HTTP/echo应用失败、完整超时或拒绝；echo表中差额均为测量结束截尾。没有SSE错误、异常结束或完整gap超过250ms，末尾截尾单列保存。全部原始事件计数和分位数与汇总一致。此处只有一个种子的三项短测试，p99尤其不稳定；128KiB的较大SSE p99保留，不被当作确定的窗口因果效应。

qdisc成本合计两方向，包括控制、交互及重传；与下载字节的比率不等于协议头开销。CPU为一个核心的平均百分比、RSS按100ms采样；不外推大规模多会话的内存上限或长期VPS稳定性。没有路径迁移、服务器失效或俄罗斯现场验证。

这里没有在同一seed227补跑正式Hysteria，也没有改部署默认；本小实验目的仅为定位PX内部容量限制。与其他seed/时段的Hysteria结果不能直接构成严格成对比较。

- [cc-window-w65536-s227-20261106T232446Z](../cc-window-w65536-s227-20261106T232446Z/manifest.json)
- [cc-window-w262144-s227-20261106T232555Z](../cc-window-w262144-s227-20261106T232555Z/manifest.json)
- [cc-window-w131072-s227-20261106T232738Z](../cc-window-w131072-s227-20261106T232738Z/manifest.json)

复跑把PROTOX_LAB_CC_WINDOW_BYTES设为65536、131072或262144后调用scripts/lab/run-cc-matrix.sh，使用--seed 227 --variants px-fork-brutal6；完整实际参数见manifest。comparison.json/csv及extractor.py保留复算入口。
