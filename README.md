# PROTO-X

可构建、可部署的实验性 TCP 代理，当前源码版本 `0.3.0-experimental`。默认使用**真实 HTTP/2 与 HTTP/3**：普通访问得到静态网站，每条已认证代理流使用独立 HTTP 流；服务端保留目标 socket，外层 H3 / H2 中断切换后按偏移恢复原连接。客户端提供本机 SOCKS5 CONNECT。

**当前没有证明整体优于合理调参的 Hysteria2。** 已完成的弱网对照中，Hysteria2 Brutal 6/1.5 Mbps 是很强的反例；PROTO-X 的恢复能力已经在测试 VPS 上实际运行，但抗识别、服务器进程故障后的旧连接恢复、长期生产可靠性仍未得到证明。

v0.2 针对早期识别缺口增加标准 HTTP 承载、TLS exporter 绑定认证、防重放、真实网站回落、标准 ECH 和有界随机填充。默认入口不再使用 `proto-x/1` ALPN 或 `proto-x.local` SNI。**没有证明浏览器指纹等价或普适抗 DPI。** 公网可信身份仍需要自有域名和证书；开发自签与私有 CA 不会自动变成公网可信。实现、主动探测和实际 ClientHello 证据见[抗识别改造报告](docs/recognition-v02.md)。

旧版独立稀疏副本研究在预先固定的 5% 丢包、1 Mbps 背景源预算验证中，相对关闭副本降低 HTTP / echo p95 约 18% / 22%，代价是多约 11% 外层字节；相对 Hysteria2 的中位延迟和流式尾部仍较差。该分支见[研究归档](research/README.md)，未合并进新 Web 版本，历史性能结果不能当作本轮成绩。

## v0.3 研究结果与部署状态

本轮增加按双向探针、因果业务确认和备用路径证据决定恢复的策略，使用单调激活代次防止旧恢复覆盖新路径；另提供累计 ACK 合并。ACK 的独立 160 会话批次中，业务窗口包数约减少 13.36%、估算 IPv4 字节减少 3.31%，HTTP p99 基本持平；检测 AUC 仍为 1，**没有据此宣称抗识别增强**。新建配置默认关闭未经证明有益的随机填充，旧配置中的显式值保留。

最终 8/2 Mbps Linux 黑洞对照中，每种三次：联合配置的承载恢复中位数 2.86→0.46 秒，SSE 最大停顿中位数 3.61→0.58 秒；HTTP 超时 12→0，原 SSE/echo 目标连接均保留 3/3。该结果合并了恢复、ACK 和填充配置变化，单独的因果业务证据尚未证明降低实测误切率。

实验方法、失败与局限见 [v0.3 主报告](docs/research-v03.md)、[恢复对照](docs/recovery-lab-v03.md)、[识别审计与 ACK 留出评估](docs/recognition-v03.md)。算法开关与兼容要求见 [部署说明](docs/deployment.md)。

11 月 10 日测试 VPS 的 SSH/服务连接超时，未部署新版；原本地 `1088` 仍监听但当前 HTTPS 探测也超时。本轮构建保存在 `bin/v03/`，保留原 `bin/protox`。下面 v0.2/VPS 数字是历史记录，不能理解为当前服务健康。

## v0.2 历史实测

- H2/H3 × ECH 开关共 16/16 真实代理请求成功；两个普通站点参照各有 38/38 声明探测行为匹配。这是局部功能证据，没有测出一般检测器的识别率。
- 同栈 12 轮成本实验：HTTP 720/720、echo 1440/1440、SSE 2880 个事件；默认填充额外增加约 10%–10.35% 归一化承载字节。
- VPS 的 8 秒 UDP 黑洞中，H3→H2 保留原 SSH，220/220 行完整，最大暂停 3.23 秒；同时 HTTP 有一次超时，SSE 重连一次，未宣称恢复更快。
- VPS 的 120 秒混合负载中，600/600 个 cold HTTP 成功，SSE 2398 个事件保持同一连接，无 >1 秒停顿；服务未重启。60 秒 Web/ECH 空闲观察约 1.20 KB/s（估算 IPv4+UDP，含启停）。
- 完整 race/vet、Go 1.26 兼容路径、独立初始化文件安全回归及真实部署探测通过。测量候选与最终修复版的哈希分别保留。

数据、代价、失败与未解决的公网身份/指纹问题见[v0.2 报告](docs/recognition-v02.md)。

## 历史 v0.1 / v0.1.1 已运行成果

- QUIC / TLS 客户端与服务端、证书 pin 与随机 token、有限会话/流窗口、字节确认与去重、半关闭、失联恢复。
- 真实测试 VPS 上通过 SOCKS 建立 SSH；8 秒 UDP 黑洞期间切换 TLS，**原 SSH 连接的 220 行输出完整、顺序正确**，最长接收间隔 2.77 秒。
- 真实路径 UDP 源端口改变后保留 QUIC 承载及原 SSH 连接，最长输出间隔 356 毫秒。
- v0.1.1 降低重复空闲探测：两次各约 60 秒测量中，估算 IPv4/UDP 流量由 1.37 KB/s 降至 0.83 KB/s；新版 UDP 黑洞复测原 SSH 220/220 行，最长停顿 2.71 秒。
- 10 分钟新建流与持续 SSE 测试：3000/3000 HTTP 成功、11995 个 SSE token 保持同一连接，服务未重启；也保留了 53 次超过 250 ms 的 SSE 间隔。
- VLESS + REALITY + Vision、Hysteria2 BBR / Brutal 的固定版本基线，以及 Linux 网络命名空间内的双向带宽、延迟、抖动和丢包实验。
- HTTP、持久回显、带源端产生节奏的 SSE、校验下载/上传、原始事件、失败/超时/测试结束截尾的独立统计。

这些是有限场景的测量，不是所有俄罗斯家宽/移动网络的结论。性能数字、负面结果和运行目录见 [实验报告](docs/RESULTS.md)。

## 本机启动

需要 Go 1.26 或更新版本；本次实际构建使用 Go 1.27.1，并运行了 Go 1.26.0 兼容分支测试。构建脚本同时生成当前平台，以及 Linux arm64 / amd64 的静态程序。

```sh
scripts/build.sh
bin/protox init -dir .local/demo -host 127.0.0.1 -server-name localhost \
  -tls-port 14443 -quic-port 14443
bin/protox server -config .local/demo/server.json
```

另一个终端启动客户端：

```sh
bin/protox client -config .local/demo/client.json
curl --socks5-hostname 127.0.0.1:1088 https://example.com/
```

`init` 默认生成 Web 配置、256 位随机 token、开发证书与示例网站，拒绝覆盖已有文件。开发客户端明确使用 pin-only；公网部署应换成有效证书、CA 验证与实际自有内容。旧裸承载仅通过 `init -legacy` 生成。默认下行 8 Mbps、上行 2 Mbps 是应用记录预算，新增填充预扣最大成本，**不是精确外层字节上限**。

新 Web 测试 VPS 配置在 `.local/vps-web/`，旧 `.local/vps/` 只保留历史记录。部署、客户端接入见[部署说明](docs/deployment.md)；含网站、ECH 和 CA 的更新与回滚必须使用[整包部署说明](docs/deployment-web.md)。不要发布 `.local/`。

## 设计和边界

| 能力 | 当前实现与边界 |
| --- | --- |
| HTTP 交互流隔离 | 每个虚拟流有独立双向 POST；H3 减少跨流等待，仍共享拥塞控制与线路。 |
| 小流调度 | 共享 pacing、有限稀疏信用、竞争时高/低优先级约 3:1；不是应用识别器，调度收益需结合消融实验判断。 |
| 同进程恢复 | 服务端保留目标 socket，双方保留有限未确认字节与偏移；替换承载后去重恢复。默认保留 90 秒。 |
| H3 / H2 切换 | UDP 不可用而 TCP 入口可用时可继续原会话；H2 仍有 TCP 跨流队头阻塞。 |
| 原服务器失效 | 无法保存已消失的目标 socket；明确终止旧流，不自动重放应用请求。 |
| 加密认证 | TLS 1.3；Web 默认 CA+域名验证、可附加 pin；exporter 绑定 HMAC 与防重放；不启用 0-RTT。 |
| 抗识别 | 正常 HTTP 网站回落、可选标准 ECH、记录填充；仍可暴露 Go 指纹、IP、外层域名、时序等。 |
| 客户端 | 仅本机 SOCKS5 TCP CONNECT；没有 UDP ASSOCIATE、TUN、移动端应用或自动改写 mihomo 配置。 |

稳定研究基线使用 quic-go v0.65.0。该版本的默认发送控制器在 `NewCubicSender` 调用中选择了 **Reno 模式**，不能因为类名含 Cubic 就把当前实现归因为 CUBIC。拥塞控制替换和选择性冗余另作受控研究，未经验证的分支不自动成为 VPS 部署版本。

## 复现与继续研发

```sh
go test -race -count=1 -timeout=120s ./...
go vet ./...
```

| 入口 | 内容 |
| --- | --- |
| [Web 承载](docs/WEB-CARRIER.md) | HTTP 流映射、认证、填充、ECH、证书配置和限制。 |
| [本轮识别测量](docs/recognition-v02.md) | 已修复特征、主动/被动实验、未解决问题。 |
| [协议说明](docs/PROTOCOL.md) | 记录格式、认证、窗口、ACK、FIN、恢复和资源边界。 |
| [实验报告](docs/RESULTS.md) | 实测结果、适用范围、负面结果与归因。 |
| [基线](docs/baselines.md) | 固定版本、校验和、REALITY/Vision、BBR/Brutal 配置。 |
| [实验室](docs/lab.md) | Lima / Debian VM、netem、命名空间、矩阵执行。 |
| [VPS 实验复跑](docs/vps-experiments.md) | 空闲、混合负载、承载/进程故障的准备、执行及收尾。 |
| [负载和统计](docs/workloads.md) | HTTP / echo / SSE / bulk 的测量方法与删失口径。 |
| [安全评审](docs/security-review.md) | 已修复问题、有限检查、尚未验证的威胁与边界。 |
| [研究归档](research/README.md) | 稀疏副本、CC 原型、源码包、补丁与独立重建记录。 |
| [研发状态](RESEARCH.md) | 已选/淘汰机制、分支、实际测试进度及续接入口。 |

`results/` 保留原始事件和配置摘要。真实部署标识、密钥、凭据及完整私密日志位于 Git 忽略的 `.local/`。测试 VPS 的管理 SSH 与原有参考服务独立保留；生产服务器未作为实验机使用。
