# PROTO-X v0.2：识别缺口改造与实测

日期：2026-11-07。旧版固定 `proto-x/1`、`proto-x.local` 和无网站回落的批评成立。本轮已实现真实 H2/H3 承载、同站点负认证回落、连接绑定认证、防重放、标准 ECH、有界填充与正常证书验证，并在授权测试 VPS 上运行。**这些是可验证的功能进展，尚未证明整体抗审查能力优于 VLESS + REALITY + Vision 或 Hysteria2。**

测量候选版本为 `0.2.0-experimental`，macOS SHA256 为 `cff89b2f1b9819482b90c85cd54d420e280475bc23ddafe62cc904aa67dc0ca9`。最终交付另修复了初始化文件的符号链接写入问题；它不改变传输/认证/调度代码。测量目录保留原候选哈希，最终源文件和程序哈希单独记录在 [验证 manifest](../results/verification-web-20261107/manifest.json) 与 [部署状态](../results/deployment-web-20261107/final-state.json)，不把旧样本重标为新二进制。

## 实现改变了什么

| 旧缺口 | 本轮实现 | 仍然存在的限制 |
| --- | --- | --- |
| 自定义 ALPN、裸记录 | 真正 HTTP/2 与 HTTP/3；每个虚拟流一个双向 POST，控制流独立 | Go TLS/QUIC、HTTP 参数与交互形态仍可能被识别；没有复刻浏览器 |
| 固定默认 SNI | endpoint 明确配置证书名称；开发初始化采用给定名称/主机 | 名称与目的 IP 仍是端点属性，代码不会自动取得域名 |
| 只认自签 pin | Web 默认校验证书链、名称、有效期，可加 pin；开发 pin-only 必须显式打开 | 当前 VPS 用私有 CA，公网可信身份未解决 |
| 无正常网站 | 同一 TLS 服务提供静态网站，普通/错误认证/重放请求由同一个网站 handler 处理；支持 H1、无 ALPN、H2、H3 | 公开目录必须只含公开内容；共享开发模板本身可被探测 |
| 凭据或请求可跨连接复用 | TLS exporter 绑定的 HMAC-SHA256，绑定方法、authority、完整 URI、时间和 nonce；有界防重放缓存 | 共享 token 是单一信任域，没有多租户或分用户撤销 |
| 无 ECH | Go 标准 TLS/HPKE 的 ECH；客户端配置后必须实际接受，不能静默降级 | 需分发有效 ECH 配置及匹配密钥，无自动 DNS 发现/轮换；IP、outer 名和 ECH 使用仍可见 |
| 固定记录长度 | 加密 body 内每记录随机 0–127 字节填充，可选 0/63/127/255 上限；不等待凑包 | 没有证据证明改善分类器误报/漏报或真实可达性，未隐藏心跳时序 |
| 承载改造破坏旧会话 | 保留 socket、有限缓存、偏移、ACK、去重与半关闭，H3↔H2 后恢复同进程 Session | 原服务器死亡、租期到期或应用自身超时仍会结束旧流 |

没有仅更改 ALPN 后继续发送裸流。HTTP HEADERS/DATA、HPACK/QPACK、流控制和错误处理由标准 HTTP 实现完成。TLS 握手结束后，HELLO/OPEN 随请求 body 发出，不额外等待 HTTP 200，也不启用 0-RTT。具体线格式和配置见 [WEB-CARRIER.md](WEB-CARRIER.md)，认证边界见 [cover-auth.md](cover-auth.md)。

## 独立的识别与主动探测

[独立报告](../results/recognition-http-v02-20261107/ANALYSIS.md) 与 [工具](../tools/recognition/README.md) 保留探针定义、原始脱敏观察及历史失败。

真实原生客户端分别以 H2/H3、ECH 开/关运行四组业务：总计 **16/16 代理请求成功**，每组 SSE 的 **16/16 事件完整**，四条原生 ClientHello 均成功解析，无旧 ALPN。ECH 开启时，可见 SNI 从 inner 类别变为 outer 类别。数据来自真实 TLS 字节/UDP 数据报，不是伪造 pcap。

ECHAccepted 状态来自**另外建立的 TLS 诊断连接**；原生抓取提供外层 ClientHello 与成功业务，原生客户端另外由“配置 ECH 即要求接受”的代码保证。这两个来源没有混成同一个客户端回调。测试使用私有 CA、正确名称和 pin；不是公网证书实验。

主动访客与两种普通站点参照比较：一组与候选使用相同 TLS 参数及窗口，一组用较接近默认的 Go TLS/HTTP 栈。两边共享证书与站点内容。每组各端均获得 **34/34 有效 HTTP 响应**，另有四个预期旧入口拒绝，共 **38/38 声明行为匹配**；两组累计 **152/152 ClientHello 成功解析**。覆盖 H2/H3 普通与负认证请求、Go 与 OpenSSL 的无 ALPN/显式 HTTP/1.1，以及旧协议探针。

这里的匹配仅指状态、协议、选择的通用头、body 散列和错误类型。没有比较全部时序分布，也没有训练检测器或报告 TPR/FPR。不能把 38/38 匹配解释为“100% 无法识别”，或把普通 Go 站点视为浏览器总体分布。

本轮保留的失败包括：修复前 12/12 无 ALPN 访客失败；一次非法 H2 preface 关闭时的响应字节差异；首轮 UDP relay 回流疑点；错误 OpenSSL 参数只握手未发 HTTP；原生抓取达到前缀上限。修复后补测成功没有覆盖或删除旧数据。

## 成本与功能对照

[成本报告](../results/web-overhead-20261107/REPORT.md) 对同一个冻结二进制做六个配置、每个两次的交错短测：H2/H3 的 padding0、padding127，以及旧 TLS/QUIC 诊断承载。每轮 12 秒，累计实际业务 144.011 秒，源端背景下载 2 Mbps，调度预算 8/2 Mbps。这里只使用本机 loopback，没有丢包、人工 RTT 或线路限速。

| 归一化双向承载字节 / 已验证接收应用字节 | 两次实测变化 |
| --- | --- |
| H2 padding127 相比 H2 padding0 | +10.02%、+10.35% |
| H3 padding127 相比 H3 padding0 | +10.02%、+10.11% |
| H2 padding0 相比同二进制旧 TLS | +3.78%、+3.16% |
| H3 padding0 相比同二进制旧 QUIC | +2.44%、+2.34% |

累计 HTTP **720/720**、echo **1440/1440**、SSE **2880 token / 12 连接**；无业务错误、意外 SSE 结束或 >250ms SSE 接收间隔。12 个无限下载在运行结束时全部记录为删失，校验过的有效字节仍计入 goodput。实际下载约 1.83–1.85 Mbps。

TCP 成本是 relay 读取的 TLS 字节，UDP 成本是实际数据报 payload；不包含 IP/链路层头、TCP 重传和网卡开销。分母只包括声明的已验证接收应用内容，不含请求和全部应用语法，所以倍率不能直接称为“纯协议开销”。macOS Web 服务端 RSS 的采样峰值约 21.70–22.75 MiB，客户端约 21.31–22.44 MiB；不外推成小 VPS 内存。

默认填充是可关闭的实验策略。数据表明它有约一成成本，尚没有证据说明这笔成本换来了更低识别率；它不是已经优化出的最佳强度。旧 TLS/QUIC 诊断也不能替代 VLESS/Hysteria2 的性能基线。

## 授权 VPS 上的当前版本测试

VPS 本轮核实为 Debian 13 x86_64、128 MiB RAM；当前运行的开发机到该 VPS 路径是唯一外部实测路径，未证明它代表莫斯科家宽/俄罗斯移动网总体。TCP/UDP 33290 属于测试服务，SSH 及已有参考服务保留。当前部署使用私有 CA、名称校验、pin、ECH 和 padding127。

### 8 秒双向 UDP 黑洞

[原始事件与统计](../results/vps-web-blackhole-20261107/fault-summary.json)：H3 被切断后转为 H2，日志显示 generation 1→2、恢复 17 条当时保留的 Flow。真实 SSH 只使用一个原进程/原应用连接，**220/220 行顺序正确，退出码 0**，最长接收间隔 **3227.27ms**。

同时负载并非无损：HTTP **149/150**，一次 3 秒超时；echo **238/240**，一次超时、一次运行末尾删失；SSE **523 token、2 个连接、1 次意外结束**，最长接收间隔 **3753.97ms**，终止缺口也保留。该应用配置的 3 秒 inactivity deadline 在恢复期间触发；保留原 Session 不会撤销应用已经关闭的 socket。

这个结果证明同进程保留 socket 在 H3→H2 下有实际作用，也暴露恢复慢于该应用超时的问题。旧 v0.1.1 的约 2.71 秒 SSH 暂停不是本轮成绩；新旧运行条件和时段不同，**不能宣称恢复更快**。

### 120 秒混合负载

[业务统计](../results/vps-web-soak-20261107/bench.summary.json)、[资源统计](../results/vps-web-soak-20261107/soak-summary.json)：实际业务 120.000s，源端背景下载 2 Mbps，每秒 5 个 cold HTTP POST。HTTP **600/600**，echo **1151/1152**（唯一未完成项是运行末尾删失），均无超时/失败；echo 仅一次连接。SSE **2398 token / 1 连接**，零序列/源错误与意外结束；最大间隔 **503.50ms**，4 次 >250ms、0 次 >1s。下载有效速度 **1.854 Mbps**。

25/25 次资源查询有效，MainPID 不变、NRestarts 0→0；systemd/cgroup 的采样内存最高 **11.86 MiB**，平均 CPU 约 **16.96% 单核**。内核 MemoryPeak 14.34 MiB 包括测量前活动，不是本轮独占峰值，也不等同 RSS。有限两分钟观察不构成长期可靠性证明。

### 60 秒空闲成本

[记录](../results/vps-web-idle-20261107/idle-summary.json)：实际 60.215s，一条 H3、ECH 必须接受、无应用目标、padding127，含启动/关闭。双向 UDP payload **59,532 字节 / 448 包**，约 **988.66 B/s**；按每包增加 28 字节估算 IPv4+UDP，约 **1196.98 B/s**。旧版另一次观察约 827.57 B/s，当前 Web/ECH/填充成本更高；这不是同期配对实验。没有用该值推算无线电能耗，也没有证明心跳时序不可检测。

## 正确性与工程修复

当前完整 race/vet、真实 SOCKS 字节校验和半关闭、两向恢复且目标仅 accept 一次、并发短流回收、取消退出、错误 token/HELLO 零目标拨号，以及 CA/pin/ECH 正反例已执行。Go 1.26 兼容路径也单独执行了 Web carrier/app race 检查。认证 fuzz 为 315,998 次，record fuzz 为 33,180 次；这些是有限输入探索，不是安全证明。完整命令、范围和输出见 [验证记录](../results/verification-web-20261107/manifest.json)。

开发中实际修复了 handler 返回后写 ResponseWriter 的 race、正常退役变成 HTTP reset、Go 1.27 H2 wrapper 锁重入、无 ALPN 访客拒绝，以及关闭后的新 Link 接纳。独立源码复核还复现了预置悬空链接让初始化私钥落入公开目录的问题；初始化改为 Lstat + 独占创建，拒绝覆盖既存条目。父目录仍须受信；启动时任意把已有秘密放入 cover 的误配置不会因此自动安全。

部署脚本把证书、token、站点、ECH 和配置作为整包事务，21 个本地替身故障检查通过，真实 VPS 安装/更新也通过五秒进程存活检查和应用探测。旧的五文件回滚被完整恢复说明替代。详细独立审查见 [independent-review.md](../results/verification-web-20261107/independent-review.md)。

## 还没有补齐的目标

- **公网身份**：没有获得可用自有域名与公网 CA 证书。当前 `.test` 类私有名称、私有证书与目的 IP 都可能形成强识别特征。不能用成功验证私有 CA 代替此项。
- **主动身份保密**：当前一张证书同时覆盖 inner / outer SAN，普通访客可枚举证书获知这些名称。ECH 的被动 SNI 隐藏不保证主动探测也保密，更没有自动构建匿名集。
- **流量拟态**：标准 Go 指纹、QUIC transport 参数、POST 使用方式、包长和心跳时序没有拟合真实浏览器/应用分布；没有独立检测器、主机隔离数据集或真实 DPI 试验。
- **公开站点与接入**：必须提供自己的内容；默认模板可能被规则识别。exporter 绑定要求直接 TLS 终止，不能直接接 TLS-terminating CDN/nginx；透明 TCP 转发另当别论。
- **路径与恢复**：H2 备用须真实可达；两种路径同时封锁仍不可用。恢复延迟尚未满足本轮 3 秒应用 inactivity deadline，不支持原服务器死亡后的旧 socket 复活。
- **成本与长期行为**：填充增加约一成承载成本，空闲开销也上升；尚未做新 Web 承载与调好参数的 VLESS/HY 的完整弱网、移动切换、长时资源和抗识别联合比较。

下一轮最有价值的是在真实自有域名/有效证书及独立站点内容下，采集多应用 cover 与代理流量，按主机和会话拆分训练/测试；同时比较 padding0/127、Hysteria2 和 REALITY/Vision 的可达性、误判及相同成本下的交互退化。当前可以部署继续使用和测量，不能把这些后续工作写成已完成。

## 复现入口

- [构建、客户端和部署](deployment.md)，[完整包恢复](deployment-web.md)。
- [主动探测与 ClientHello 工具](../tools/recognition/README.md)。
- [同栈成本实验](../tools/webbench/README.md)。
- [VPS 的 idle / soak / fault 脚本](vps-experiments.md)。
- 本轮核对的一手规范/实现：RFC 9849、Go `crypto/tls`、quic-go HTTP/3；获取时间和内容哈希见 [sources.json](../results/verification-web-20261107/sources.json)。
