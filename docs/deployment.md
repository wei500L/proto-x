# 构建、部署、接入与恢复

更新：2026-11-10。源码为 `0.3.0-experimental`；默认使用真实 HTTP/2 / HTTP/3。真实地址、登录信息和密钥不放在公开文档中，以下地址与名称均为占位符。

## v0.3 构建与当前状态

本轮实际构建在 `bin/v03/`，保留原 `bin/protox`、本地 `1088` 进程和 `.local/vps-web/` 配置。经干净 `e4c93d9` 重建确认这些旧磁盘二进制的身份；但 11 月 10 日 SSH 与服务端口超时，本地 SOCKS 的公共 HTTPS 探测也超时，**没有完成 v0.3 远端部署**。不能用三天前的资源清单或 active 记录代替当前核验。见 [source-identity.json](../results/verification-v03-20261110/source-identity.json)。

保留旧程序另行构建：

```sh
PROTOX_BUILD_DIR=bin/v03 sh scripts/build.sh
bin/v03/protox version
```

新程序可读取原 v0.2 配置。未指定 `recovery_mode` 时保持 legacy 行为；新建配置及省略 `web_padding` 的配置默认填充 0。已有显式 `web_padding: 127` 的配置仍为 127。以下字段都是 JSON 配置字段，应合并到原对象，不能拼接第二个对象：

| 字段 | 作用与兼容 |
| --- | --- |
| `recovery_mode: "adaptive"` | 客户端启用双向探针、因果业务进展及备用准备策略；必须连接支持 attempt 回显的 v0.3 服务端。 |
| `recovery_mode: "legacy"` | 与 v0.2 服务端互通时使用；新服务器仍接受未进入 fenced 状态的 legacy 会话。 |
| `recovery_no_prepare: true` | 研究消融；同检测器确认后冷拨，不提前准备。 |
| `recovery_count_history: true` | 默认按最后 32 次 RTT；显式 false 启用未显示稳定总体收益的时间窗口实验。 |
| `recovery_probe_only: true` | 研究消融；忽略因果业务确认，仅依据匹配探针进展。 |
| `ack_coalesce: true` | 该方向合并累计 ACK；两端各自配置，线格式保持兼容。 |
| `recovery_trace: true` | 记录单调阶段时间、真实 ECH 接受和代次；实验使用，常态建议关闭。 |
| `web_padding: 0` | 关闭额外随机填充；H2/H3 记录封装仍存在。 |

先升级服务端再让新客户端使用 adaptive。v0.2 客户端/服务端拒绝未知配置字段，因此回滚须使用原整包配置，不能把新增字段的配置直接交给旧程序。已经 fenced 的同一会话不允许降到 attempt=0；回滚进程会结束原会话，后续应用建立新连接。ECH 要求不会因恢复模式变化而取消。

本轮已从原配置准备私密完整副本 `.local/vps-web-v03/`：采用联合实验参数（adaptive、纯计数 RTT、因果业务证据、ACK 合并、填充 0），保留原 CA/ECH/认证，关闭 trace 和私网目标权限；客户端暂用空闲测试入口 1089。配置加载、服务器证书与密钥匹配、客户端 CA/ECH 配置解析及取消启动检查通过；这不代表完成网络握手。最终直连 SSH 超时，经本机代理的 SSH 也未成功，见 [最终可达性记录](../results/verification-v03-20261110/final-reachability.json)。

SSH 可达后可按原事务脚本部署测试机：

```sh
PROTOX_BUILD_DIR=bin/v03 sh scripts/deploy-test.sh \
  .local/ssh_config protox-test .local/vps-web-v03
```

该目录需要原证书、token、网站、CA/ECH 及配套配置，不能只有一份 JSON。脚本整包备份和自动回滚语义不变，选择新目录二进制不会改 SSH、防火墙或生产服务。激活后仍要验证普通 HTTPS、H2/H3+实际 ECH 和真实 SOCKS 业务。`recovery_trace` 每个探针有日志，现有 systemd 日志限流可能截断轨迹；严谨测量使用本轮私有实验 harness 的完整捕获。

停止旧本地客户端前核实 PID 对应的可执行文件与配置；停止会结束现有应用 socket。新程序使用配套配置时先选择空闲 SOCKS 端口做实际探测，成功后再替换 `1088`。本轮没有因端口仍监听而宣布业务健康，也没有在 SSH 不可达时实施远端替换。

## 历史 v0.2 入口与运行方法

下文记录 11 月 7 日部署布局。路径仍可用于恢复，但状态须重新实测。旧 `.local/vps/` 与 v0.1 测量仅为历史记录；最近一次成功部署配置是 `.local/vps-web/`。

## 当前入口

| 项目 | 位置 |
| --- | --- |
| 本地程序 | `bin/protox` |
| 配套客户端配置 | `.local/vps-web/client.json` |
| 本地 SOCKS5 TCP CONNECT | `127.0.0.1:1088` |
| 管理 SSH | `ssh -F .local/ssh_config protox-test` |
| 服务端单元 | `protox.service` |
| 远端程序 / 配置 | `/opt/proto-x/protox` / `/opt/proto-x/server.json` |
| 实验映射 | TCP 33290：HTTPS H2/H1；UDP 33290：HTTP/3 |
| 最近部署、探测和资源记录 | [final-state.json](../results/deployment-web-20261107/final-state.json) |

本轮测试部署启用了 ECH、私有 CA 验证、正确名称验证及附加叶证书 pin，`experimental_pin_only=false`。**私有 CA 不等于公网可信证书。** 普通访客只有显式信任这套 CA 才能完成证书验证；部署公开站点仍需实际自有域名和有效公网证书。实际网页与 SOCKS 请求分别验证，不能只凭 systemd active 判断应用可用。

日常部署关闭 `allow_private_targets`，不运行临时 pxbench fixture。恢复/负载实验才临时允许受控私网目标，测量后恢复。此开关放开整组私网目标，不是只放开 fixture 的三个端口。

## 构建和本地客户端

需要 Go 1.26 或更新版本。本次使用 Go 1.27.1 构建，并通过 Go 1.26.0 的 Web 承载/应用 race 测试。

```sh
sh scripts/build.sh
bin/protox version
```

脚本先执行 `go test ./...`，再构建本机程序及 Linux arm64 / amd64 独立程序。使用 `-trimpath -buildvcs=false`，PROTO-X 统一使用 `-ldflags='-s -w'`；Linux 交叉编译关闭 CGO。精确版本和二进制 SHA256 见部署与验证 manifest。关闭 VCS 嵌入使同源、同工具链重建不依赖工作区 dirty 状态，但不保证不同 Go 版本生成同一哈希。

已有后台客户端时不要再启动同端口的第二个进程。检查当前监听：

```sh
lsof -nP -iTCP:1088 -sTCP:LISTEN
```

若未运行，在仓库根目录前台启动：

```sh
bin/protox client -config .local/vps-web/client.json
```

后台实例的 PID 和日志分别为 `.local/vps-web/client.pid`、`.local/vps-web/client-final.log`。停止之前用 `ps -p PID -o command=` 确认是这套配置对应的客户端，再对该 PID 发送 TERM；不能仅凭可能过期的 PID 文件终止进程。退出客户端会结束它持有的应用连接。

用另一个终端验证显式 SOCKS 请求：

```sh
curl --socks5-hostname 127.0.0.1:1088 \
  --connect-timeout 10 --max-time 20 -I https://example.com/
```

目标域名由代理端解析。这个请求成功只说明当次业务路径可用。当前没有 SOCKS UDP ASSOCIATE、TUN 或移动端程序。

## 创建新配置

在空目录生成开发用配置：

```sh
bin/protox init -dir .local/example-web \
  -host 192.0.2.1 -server-name notes.example \
  -tls-port 33290 -quic-port 33290
```

默认生成 `server.json`、`client.json`、`server.crt`、`server.key`、`token` 与 `cover/`。客户端配置明确启用开发 pin-only；生成命令不会签发公网证书、设置域名或修改 NAT。已有配置拒绝覆盖。相对资源路径以配置文件所在目录为基准。

公网身份配置步骤：将服务端证书与私钥换成自己的完整有效证书链和配套私钥，部署实际公开站点内容；客户端的 `server_name` 必须与证书匹配，关闭 `experimental_pin_only`。公网 CA 通常不设置 `ca_file`；私有测试 CA 需显式提供 PEM。更换证书时同步更新或移除旧的可选 `pin_sha256`，其值是叶证书 DER 的 SHA256。客户端不需要服务端私钥或 ECH 私钥。

可选 ECH：

```sh
bin/protox ech-keygen -dir .local/example-web -public-name cover.example
```

服务端配置 `ech_keys_file: "ech-keys.json"`；客户端配置 `ech_config_file: "ech-config.bin"`。仅 `.bin` 可公开分发；JSON 含解密私钥。证书须适用于所服务的 inner / outer 名称。配置 ECH 后客户端要求实际接受，不会静默去掉 ECH 重试，也不允许混入旧裸 TLS/QUIC fallback。没有自动 DNS HTTPS 记录发现或轮换管理。

ECH 无法隐藏目的 IP、outer 名称和流量行为。本轮单张证书包含 inner / outer SAN，主动证书枚举仍可能获知 inner 名称。当前直接 TLS 终止与 exporter 认证绑定，不能直接部署在终止 TLS 的 CDN/nginx 后面。详见 [Web 承载说明](WEB-CARRIER.md)。

默认下行 / 上行发送调度预算为 8 / 2 Mbps，Flow 每方向窗口 64 KiB，单 Session 最多 32 流，服务端最多 2 个 Session，priority 开启。它们不是外层精确线速或资源总量保证。v0.2 部署配置的 Web 填充为 0–127 字节，每记录预扣最大填充成本；本轮实测额外承载成本约一成，见 [成本报告](../results/web-overhead-20261107/REPORT.md)。

## 服务端部署和整套恢复

已有私密配置目录可直接部署到授权测试 VPS：

```sh
sh scripts/deploy-test.sh .local/ssh_config protox-test .local/vps-web
```

脚本上传完整证书、token、cover、ECH 和配置包，保存旧完整资产及原 systemd 状态，激活后检查五秒存活、PID 和重启数。失败时恢复整套旧包；仍需单独验证 HTTPS 和 SOCKS。它不改 SSH、防火墙、NAT、生产服务或本地客户端。

**旧的五文件手工回滚命令已不适用。** 新备份结构、自动恢复限制和可直接执行的整包手工恢复命令见 [deployment-web.md](deployment-web.md)。备份含私钥、token 和 ECH 密钥，保留在受限目录。首次部署备份可能没有任何旧版本，不能把它称为可回滚的 v0.1.1 服务。

本轮登录时 `/opt/proto-x` 已不存在；历史 v0.1.1 部署记录不是连续运行证明。此轮重新安装 v0.2，之后又完成了实验后关闭私网目标的整包更新。SSH 与原参考服务保留。最新备份路径及完整日志仅放在 `.local/vps-web/`。

服务检查：

```sh
ssh -F .local/ssh_config protox-test \
  'systemctl --no-pager --full status protox.service'
ssh -F .local/ssh_config protox-test \
  'journalctl -u protox.service -n 100 --no-pager'
ssh -F .local/ssh_config protox-test \
  'systemctl show protox.service -p ActiveState -p SubState -p NRestarts -p MemoryCurrent -p MemoryPeak'
```

`systemctl stop/start/restart protox.service` 分别停止、启动、重启该测试服务。任何服务端进程重启都会丢失原会话和目标 socket；不能依靠相同 token/ECH 配置复活旧 SSH。客户端重新创建新会话后，新请求可继续。

服务以 `protox` 用户运行。unit 设置 `GOMAXPROCS=1`、`GOMEMLIMIT=32MiB`、`GOGC=50`、`MemoryHigh=40M`、`MemoryMax=56M`、`TasksMax=128`、`LimitNOFILE=2048`。内存硬限制可能终止进程，Go 软限制不等同 RSS 保证。实际资源与重启数需要一起观察。

## mihomo 手工接入

把节点合并到现有 `proxies`，再加入希望使用的代理组；不要创建重复顶层键：

```yaml
proxies:
  - name: PROTO-X-local
    type: socks5
    server: 127.0.0.1
    port: 1088
    udp: false
```

先运行本地客户端，再选择这个节点。mihomo 本身没有原生实现 PROTO-X；这里是 SOCKS 转接，没有自动修改用户现有配置。使用 TUN 或全局接管时，让外层服务器地址直接出站，避免循环代理，例如在可能代理的规则之前合并：

```yaml
rules:
  - IP-CIDR,192.0.2.1/32,DIRECT,no-resolve
```

换成实际授权端点，并覆盖它使用的全部 IPv4/IPv6。规则格式依据 mihomo 的 SOCKS / IP-CIDR 文档；订阅持久覆盖方式以使用中的版本为准。

外层连接变化时，同一活进程保留的会话、确认偏移和目标 socket 可在默认 90 秒租期内恢复。H3↔H2 切换需要备用路径实际可达；默认 2 秒失联阈值不代表完整恢复只需 2 秒。两端应用还须在暂停期间保持 socket，本轮 3 秒 SSE 应用超时就导致了重连。测量方法见 [VPS 实验复跑](vps-experiments.md)，结果见 [本轮报告](recognition-v02.md)。
