# PROTO-X

可构建、可部署的实验性 TCP 代理。当前重点是有界缓冲、稀疏流调度，以及**原目标 socket 存活时，跨 QUIC / TLS 承载继续同一条应用连接**。客户端提供本机 SOCKS5 CONNECT；服务端使用标准 TLS 1.3 和 QUIC，不自行设计密码算法。

**当前没有证明整体优于合理调参的 Hysteria2。** 已完成的弱网对照中，Hysteria2 Brutal 6/1.5 Mbps 是很强的反例；PROTO-X 的恢复能力已经在测试 VPS 上实际运行，但抗识别、服务器进程故障后的旧连接恢复、长期生产可靠性仍未得到证明。

当前部署为 `0.1.1-experimental`。独立的稀疏副本研究版本在预先固定的 5% 丢包、1 Mbps 背景源预算验证中，相对同版关闭副本降低 HTTP / echo p95 约 18% / 22%，代价是多约 11% 外层字节；相对 Hysteria2 的中位延迟和流式尾部仍较差。该分支及可复现补丁见[研究归档](research/README.md)，尚未并入 VPS 默认版本。

## 已运行的成果

- QUIC / TLS 客户端与服务端、证书 pin 与随机 token、有限会话/流窗口、字节确认与去重、半关闭、失联恢复。
- 真实测试 VPS 上通过 SOCKS 建立 SSH；8 秒 UDP 黑洞期间切换 TLS，**原 SSH 连接的 220 行输出完整、顺序正确**，最长接收间隔 2.77 秒。
- 真实路径 UDP 源端口改变后保留 QUIC 承载及原 SSH 连接，最长输出间隔 356 毫秒。
- v0.1.1 降低重复空闲探测：两次各约 60 秒测量中，估算 IPv4/UDP 流量由 1.37 KB/s 降至 0.83 KB/s；新版 UDP 黑洞复测原 SSH 220/220 行，最长停顿 2.71 秒。
- 10 分钟新建流与持续 SSE 测试：3000/3000 HTTP 成功、11995 个 SSE token 保持同一连接，服务未重启；也保留了 53 次超过 250 ms 的 SSE 间隔。
- VLESS + REALITY + Vision、Hysteria2 BBR / Brutal 的固定版本基线，以及 Linux 网络命名空间内的双向带宽、延迟、抖动和丢包实验。
- HTTP、持久回显、带源端产生节奏的 SSE、校验下载/上传、原始事件、失败/超时/测试结束截尾的独立统计。

这些是有限场景的测量，不是所有俄罗斯家宽/移动网络的结论。性能数字、负面结果和运行目录见 [实验报告](docs/RESULTS.md)。

## 本机启动

需要 Go 1.26 或更新版本；本次实际构建使用 Go 1.27.1。构建脚本同时生成当前平台，以及 Linux arm64 / amd64 的静态程序。

```sh
scripts/build.sh
bin/protox init -dir .local/demo -host 127.0.0.1 \
  -tls-port 14443 -quic-port 14443
bin/protox server -config .local/demo/server.json
```

另一个终端启动客户端：

```sh
bin/protox client -config .local/demo/client.json
curl --socks5-hostname 127.0.0.1:1088 https://example.com/
```

`init` 生成私密配置、256 位随机 token 和证书，拒绝覆盖已有文件。默认下行发送预算 8 Mbps、上行 2 Mbps；它们是应用记录调度预算，**不是精确的外层字节速率上限**。实际可用速度受到拥塞控制、每流窗口、RTT、丢包和运行时影响。

现有测试 VPS 的客户端配置在 `.local/vps/client.json`，本机入口为 `127.0.0.1:1088`。部署、启动、mihomo 接入、备份和恢复命令见 [部署说明](docs/deployment.md)。不要发布 `.local/`。

## 设计和边界

| 能力 | 当前实现与边界 |
| --- | --- |
| QUIC 交互流隔离 | 每个虚拟流在每个方向有独立的 QUIC 流；仍共享连接拥塞控制与线路。 |
| 小流调度 | 共享 pacing、有限稀疏信用、竞争时高/低优先级约 3:1；不是应用识别器，调度收益需结合消融实验判断。 |
| 同进程恢复 | 服务端保留目标 socket，双方保留有限未确认字节与偏移；替换承载后去重恢复。默认保留 90 秒。 |
| TLS 回退 | UDP 不可用而 TCP 入口可用时可继续原会话；TLS 复用仍有 TCP 跨流队头阻塞。 |
| 原服务器失效 | 无法保存已消失的目标 socket；明确终止旧流，不自动重放应用请求。 |
| 加密认证 | TLS 1.3、证书 SHA-256 pin、共享随机 token；不启用 0-RTT。 |
| 抗识别 | 自定义 ALPN 和 SNI 明显可识别，没有抗 DPI 或真实网站拟态证明。 |
| 客户端 | 仅本机 SOCKS5 TCP CONNECT；没有 UDP ASSOCIATE、TUN、移动端应用或自动改写 mihomo 配置。 |

稳定研究基线使用 quic-go v0.65.0。该版本的默认发送控制器在 `NewCubicSender` 调用中选择了 **Reno 模式**，不能因为类名含 Cubic 就把当前实现归因为 CUBIC。拥塞控制替换和选择性冗余另作受控研究，未经验证的分支不自动成为 VPS 部署版本。

## 复现与继续研发

```sh
go test -race -count=1 -timeout=60s ./...
go vet ./...
```

| 入口 | 内容 |
| --- | --- |
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
