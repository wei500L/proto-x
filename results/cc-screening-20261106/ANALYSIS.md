# 独立拥塞控制筛选：训练种子211/223

单纯换入Hysteria的BBR或Brutal，没有解决本版PX的交互等待。相对同一个旧QUIC fork的Reno，下载提高到约3.52–3.53Mbps，但HTTP/echo p95多数增至约145–153ms；正式Hysteria Brutal6的HTTP p95为85.4/94.1ms、echo约85ms、下载约5.73Mbps。PX部分HTTP p99和SSE点估计更低，但方向不一致且每项仅约125次HTTP，不能宣称综合优势。

## 方法与身份

本地Linux VM包级netem，下行8／上行2Mbps、名义RTT60ms、每方向1%独立丢包及5ms抖动、额外名义排队100ms，offload关闭；每进程GOMAXPROCS=1。每项独立预热3秒后测25秒，HTTP POST 5/s（HTTPS、验证自有CA、keep-alive）、echo最小间隔100ms、SSE源端50ms，一个不限速后台下载；请求超时3秒。双方PX信用窗口64KiB、应用帧pacer8/2Mbps、priority=true、adaptive=false。

两个seed分别随机打乱五个变体，211/223均为训练/发现集；307未使用。运行器、所有四个二进制及实验源码来源摘要在两批中完全相同。完整脱敏配置、原配置SHA、Go build info和原始事件/资源/tc状态均在各run目录；所有PX两端实际QUIC连接日志、fork两端认证后实际CC安装日志均通过检查，没有拿环境变量配置意图冒充实际安装。

- 稳定PX：quic-go v0.65.0默认Reno，二进制28ee62b17791e92dff0f2745c866913d3d500e3b530730102c9f35c977e0e638。
- fork三个模式共用二进制46b55aa58073753d2a3fa16d76c117ce86692eaca57a2b05e355e52700c45819；使用apernet/quic-go v0.63.1-0.20261004180939-a10df75c260c、显式QUIC v1，session/scheduler/JSON语义保持相同。
- [Hysteria CC固定来源](https://github.com/HyNetworkS/hysteria/tree/ca8fbd874fd6ca82413948de6dc5924405e103e1/core/internal/congestion)：只变更包导入路径，CC逻辑和常数未改。它们是复用组件，不是PROTO-X原创算法。两端Brutal速率分别为750000/187500字节每秒（6/1.5Mbps），丢包补偿保持开启。
- 正式Hysteria 2.13.0使用同样Brutal6/1.5Mbps；不会只与明显过载的Brutal8对比。

稳定版与fork版不仅改变CC，还改变QUIC实现/版本选择，所以先看fork内Reno/BBR/Brutal对照；不能把稳定版与fork版的全部差异归功于CC。

## 每次测量

| seed | 变体 | HTTP成功/总数 | HTTP p95 / p99 ms | Echo成功/总数 | Echo p95 ms | SSE p99 / max ms | 下载Mbps |
|---|---|---:|---:|---:|---:|---:|---:|
| 211 | px-priority | 125/125 | 116.6 / 193.3 | 241/242 | 137.2 | 91.1 / 152.7 | 2.769 |
| 211 | px-fork-reno | 125/125 | 131.9 / 189.8 | 241/242 | 114.7 | 84.7 / 151.9 | 2.821 |
| 211 | px-fork-bbr-standard | 125/125 | 148.3 / 156.5 | 231/232 | 153.3 | 71.2 / 142.9 | 3.524 |
| 211 | px-fork-brutal6 | 125/125 | 149.4 / 165.9 | 233/234 | 152.3 | 127.5 / 163.1 | 3.530 |
| 211 | hy-brutal6 | 125/125 | 85.4 / 196.8 | 244/245 | 84.5 | 119.9 / 129.2 | 5.726 |
| 223 | px-priority | 125/125 | 163.8 / 180.4 | 244/245 | 98.6 | 88.8 / 140.9 | 2.523 |
| 223 | px-fork-reno | 125/125 | 120.6 / 170.4 | 241/241 | 129.5 | 86.7 / 152.2 | 2.623 |
| 223 | px-fork-bbr-standard | 125/125 | 145.9 / 162.7 | 234/235 | 149.0 | 128.7 / 177.1 | 3.519 |
| 223 | px-fork-brutal6 | 125/125 | 144.3 / 168.4 | 233/234 | 151.7 | 120.3 / 138.3 | 3.530 |
| 223 | hy-brutal6 | 125/125 | 94.1 / 179.7 | 247/247 | 85.2 | 127.4 / 198.3 | 5.726 |

## 资源与外层成本

| seed | 变体 | Server/Client峰值MiB | Server/Client CPU% | 双向qdisc Mbps | qdisc/下载字节比 |
|---|---|---:|---:|---:|---:|
| 211 | px-priority | 16.3 / 15.9 | 2.8 / 2.6 | 3.453 | 1.247 |
| 211 | px-fork-reno | 17.3 / 15.2 | 2.8 / 2.6 | 3.502 | 1.242 |
| 211 | px-fork-bbr-standard | 17.3 / 15.4 | 3.5 / 2.7 | 4.369 | 1.240 |
| 211 | px-fork-brutal6 | 15.3 / 15.3 | 3.4 / 2.7 | 4.375 | 1.239 |
| 211 | hy-brutal6 | 25.4 / 25.1 | 3.8 / 3.2 | 6.327 | 1.105 |
| 223 | px-priority | 15.6 / 16.3 | 2.4 / 2.3 | 3.147 | 1.247 |
| 223 | px-fork-reno | 15.3 / 15.3 | 2.6 / 2.4 | 3.272 | 1.248 |
| 223 | px-fork-bbr-standard | 17.4 / 15.3 | 3.4 / 2.8 | 4.356 | 1.238 |
| 223 | px-fork-brutal6 | 17.3 / 15.3 | 3.5 / 2.8 | 4.384 | 1.242 |
| 223 | hy-brutal6 | 27.3 / 25.1 | 3.6 / 3.1 | 6.356 | 1.110 |

qdisc字节是实验链路的内核SKB计数，合计双向包含控制、交互及重传；除以下载字节不是纯协议头开销。CPU为每个代理进程占一个核心的平均百分比；共同fixture/workload另有独立记录。此VM资源结果不代替128MB VPS整机长期压力测试。

## 失败、截尾与结论范围

HTTP 1250/1250、echo 2389/2397；所有10项运行完成。没有HTTP/echo应用失败、完整3秒超时或拒绝，echo差额均为末端截尾。没有SSE序列/源端错误、连接失败、异常结束或完整gap超过250ms，终端右截尾gap单独记录。分析器按原始事件重新核对各状态样本数、nearest-rank分位数、SSE源端/接收/超额gap分位数，十项全部一致。

BBR/Brutal两个种子的PX吞吐均停在约3.5Mbps，且双向外层仅约4.4Mbps，提示还应检查应用信用窗口或ACK/调度；这只是待验证的解释，当前数据不能定位具体瓶颈。下一步只改变两端window_bytes为64/128/256KiB，在同fork、同Brutal、同pacer下另做seed227诊断，不改默认部署。

此轮不注入路径迁移。已知旧fork在路径迁移时可能把CC重置为Reno，因此静态路径筛选不证明迁移正确性。未测俄罗斯现场、DPI、真实业务目标时延或连续长期在线。短样本p99不稳定，两个种子不合并为伪独立的大样本，不隐藏单项退化。

原始入口：

- [cc-screen-s211-20261106T231831Z](../cc-screen-s211-20261106T231831Z/manifest.json)
- [cc-screen-s223-20261106T232127Z](../cc-screen-s223-20261106T232127Z/manifest.json)

comparison.json/csv保留每个trial全部字段；extractor.py为本次复算工具快照。
