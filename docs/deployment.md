# 构建、部署、接入与恢复

更新日期：2026-11-07（Europe/Moscow）。主线版本为
`0.1.1-experimental`，用于持续研发和受控使用。以下命令从仓库根目录执行；
`192.0.2.1` 是文档地址，生成新配置时必须换成自己已授权服务器的地址。
本页不包含登录凭据，真实部署配置保留在 `.local/`。

## 当前实验入口与构建

| 项目 | 当前约定 |
| --- | --- |
| 本地客户端配置 | `.local/vps/client.json` |
| 本地 SOCKS5 | `127.0.0.1:1088`，仅 TCP CONNECT |
| SSH 管理 | `ssh -F .local/ssh_config protox-test` |
| 测试服务 | systemd 单元 `protox.service` |
| 服务端程序 / 配置 | `/opt/proto-x/protox` / `/opt/proto-x/server.json` |
| 代理入口 | TCP 33290（TLS）与 UDP 33290（QUIC） |

SSH alias 使用私密配置中的管理端口，不应改成代理端口。测量以外的部署状态为
`allow_private_targets=false`，临时 fixture 已停止；恢复测试需要临时允许受控的
loopback 目标，并在测量结束后再次关闭。fixture 与 PROTO-X 服务是不同进程。
空闲、混合负载和故障试验的完整前提、命令与清理步骤见 [VPS 实验复跑](vps-experiments.md)。

安装 [go.mod](../go.mod) 要求的 Go 1.26 工具链后运行：

```sh
sh scripts/build.sh
bin/protox version
```

[build.sh](../scripts/build.sh) 先执行 `go test ./...`，随后构建本机的
`bin/protox`、`bin/pxbench`，以及 Linux arm64／amd64 的独立二进制；Linux
交叉构建使用 `CGO_ENABLED=0`。实际使用 Go 1.27.1 完成了这些构建；精确的
实测版本以各 run 的 SHA256 和部署记录为准。

已有私密配置可直接启动客户端：

```sh
bin/protox client -config .local/vps/client.json
```

此命令保持前台运行，日志写入 stderr；关闭进程会结束它持有的应用连接。
本地 1088 端口只能运行一个监听者。用另一个终端验证显式 SOCKS 请求：

```sh
curl --socks5-hostname 127.0.0.1:1088 \
  --connect-timeout 10 --max-time 20 -I https://example.com/
```

`--socks5-hostname` 把目标域名交给代理端解析。这个请求成功说明当次 HTTP 路径
可用，不代表长测、UDP 或所有业务均已验证。

## 新配置与服务端部署

为新环境创建**空目录中的成套配置**：

```sh
bin/protox init -dir .local/example-pair \
  -host 192.0.2.1 -tls-port 33290 -quic-port 33290
```

[init](../cmd/protox/main.go) 生成 `server.json`、`client.json`、`server.crt`、
`server.key` 和 `token`，文件权限为 `0600`，已有同名文件时拒绝覆盖。配置内
相对文件路径从配置所在目录解析。服务端需要 server 配置、证书、私钥和 token；
客户端需要 client 配置与 token，**不需要服务端私钥**。

需要前台联调时，服务端命令为：

```sh
bin/protox server -config .local/example-pair/server.json
```

Linux 主机使用其架构对应的二进制执行同样的 `server -config` 参数；使用下述
systemd 部署时由 unit 启动服务，无需再启动第二个前台监听进程。

默认服务端发送预算为 8 Mbps，生成的客户端发送预算为 2 Mbps；预算按 Session
及方向生效，不是精确外层线速上限。默认每 Flow 每方向窗口为 64 KiB，每 Session
最多 32 条 Flow，服务端最多 2 个 Session，`priority=true`、`adaptive=false`。
两端窗口必须相同。临时访问私网 fixture 才需要 `allow_private_targets:true`；
新生成的配置默认关闭该选项。详细语义见 [协议说明](PROTOCOL.md)。

测试 VPS 的部署或更新使用现有 SSH alias 和完整私密服务端配置目录：

```sh
sh scripts/deploy-test.sh .local/ssh_config protox-test .local/vps
```

若部署新生成的一对配置，把第三个参数换成对应目录，并使用那一对的客户端
配置连接。部署脚本不会自动更新正在运行的本地客户端。NAT／主机防火墙须允许
相应 TCP 与 UDP 入口；脚本不调整映射、系统防火墙或 SSH 管理通道。

[deploy-test.sh](../scripts/deploy-test.sh) 根据远端 `uname -m` 选择 Linux
二进制，上传到 staging；把当前程序、配置、凭据和 unit 备份到
`/opt/proto-x/backups/<UTC时间戳>/`，再安装并重启服务。文件由 root 管理，
配置与凭据为 `root:protox`、`0640`，服务以无登录权限的 `protox` 用户运行。
每次更新都保存脚本打印的备份路径，便于配对回滚。

仓库的 [systemd unit](../scripts/protox.service) 设置 `GOMAXPROCS=1`、
`GOMEMLIMIT=32MiB`、`GOGC=50`，以及 `MemoryHigh=40M`、`MemoryMax=56M`、
`TasksMax=128`、`LimitNOFILE=2048`。前者是 Go 运行时策略，不能当作 RSS 保证；
systemd 内存限制的实际执行依赖主机 cgroup 配置。触发硬限制可能终止服务并丢失
会话状态，需要把失败率、RSS 和重启次数一起观察。

## SOCKS 与 mihomo 手工接入

应用可直接把 SOCKS5 地址设为 `127.0.0.1:1088`。客户端只监听数字 loopback，
不支持把这个无认证入口直接暴露给其他机器，也未实现 UDP ASSOCIATE。

在 Clash Verge／mihomo 的手工配置或持久覆盖中，把以下节点合并到现有
`proxies` 列表，再把节点名加入希望使用的代理组；不要新建重复顶层键：

```yaml
proxies:
  - name: PROTO-X-local
    type: socks5
    server: 127.0.0.1
    port: 1088
    udp: false
```

该配置让 mihomo 把 TCP 业务交给本机 PROTO-X 客户端；mihomo 本身并未原生实现
PROTO-X。先启动 `protox client`，再在代理组中手工选择 `PROTO-X-local`。
SOCKS 字段依据 [mihomo 官方文档](https://wiki.metacubex.one/config/proxies/socks/)。
订阅更新可能覆盖直接编辑的配置，应使用自己当前版本提供的持久覆盖方式。

若开启 TUN 或全局流量接管，确保 **PROTO-X 到服务器的外层连接直接出站**，避免
再次送回本地 SOCKS。可在可能匹配代理的规则之前加入实际服务器 IP 的 DIRECT
规则；以下地址仍是占位示例：

```yaml
rules:
  - IP-CIDR,192.0.2.1/32,DIRECT,no-resolve
```

如端点使用多个 IPv4／IPv6 地址，应为实际所有外层地址安排直连；域名解析变化
后也要保持路由一致。这里没有自动修改用户的 mihomo 配置。其他 UDP 业务需由
原有策略处理，不能因外层使用 QUIC 就认为 SOCKS 支持 UDP。

## 服务检查与回滚

以下命令只管理测试服务，使用已有 SSH 配置：

```sh
ssh -F .local/ssh_config protox-test \
  'systemctl --no-pager --full status protox.service'
ssh -F .local/ssh_config protox-test \
  'journalctl -u protox.service -n 100 --no-pager'
ssh -F .local/ssh_config protox-test \
  'systemctl show protox.service -p ActiveState -p SubState -p NRestarts -p MemoryCurrent -p MemoryPeak'
```

需要重启服务时运行：

```sh
ssh -F .local/ssh_config protox-test 'systemctl restart protox.service'
```

需要停止实验服务时，将子命令换为 `systemctl stop protox.service`；之后可用
`systemctl start protox.service` 恢复运行。**任何服务端重启都会
结束其原有会话与目标 socket**；systemd 的自动重启同样如此。重启后重新执行
本地 SOCKS 请求，分别核对服务状态、认证和应用连通性。

部署脚本仅在 `systemctl restart` 返回失败时尝试自动回滚。`Type=simple` 服务
可能在启动命令返回成功后才退出；脚本没有端到端健康探测，因此不能只凭退出码
认定更新成功。若需手工回滚，把下面的时间戳换成实际备份目录名：

```sh
ssh -F .local/ssh_config protox-test 'sh -s' <<'REMOTE'
set -eu
protox_backup=/opt/proto-x/backups/REPLACE_TIMESTAMP
for file in protox server.json server.crt server.key token; do
  test -f "$protox_backup/$file"
done
systemctl stop protox.service
for file in protox server.json server.crt server.key token; do
  cp -p "$protox_backup/$file" "/opt/proto-x/$file"
done
if [ -f "$protox_backup/protox.service" ]; then
  cp -p "$protox_backup/protox.service" /etc/systemd/system/protox.service
fi
systemctl daemon-reload
systemctl start protox.service
systemctl --no-pager --full status protox.service
REMOTE
```

若备份包含凭据变更，客户端也要恢复配套的配置与 token 后重启。备份含私钥和
token，只保留在受限目录；不要把整个 `.local` 或服务端备份上传到公共仓库。

## token、pin 轮换与连接恢复边界

凭据和证书在进程启动时载入，没有热更新或新旧 pin 并存机制。先在新的空目录
生成一对配置，地址与端口按实际部署替换：

```sh
bin/protox init -dir .local/rotation-next \
  -host 192.0.2.1 -tls-port 33290 -quic-port 33290
```

随后完成配套切换：

1. 将监听地址、窗口、速率等需要保留的参数核对到新配置；新 `client.json`
   中的 `pin_sha256` 已与新证书匹配，token 也成套生成。
2. 保存当前客户端私密配置和服务端备份；使用新目录部署服务端，并让各客户端
   使用对应的新 client 配置及 token 重新启动。轮换窗口内旧连接会断开。
3. 检查服务状态和显式 SOCKS 请求。记录采用的配置版本，不把凭据值写入日志。

若只轮换 token，生成 32 个安全随机字节的十六进制表示，同步更新两端
`token_file` 指向的文件，再重启两端；证书未变则 pin 不变。只修改磁盘 token
不能立即撤销已在内存中使用的旧 token。若只更换证书，客户端必须同步修改
`pin_sha256`；它是**叶证书 DER**的 SHA-256，不是私钥或 SPKI 的哈希。

外层 QUIC／TLS 连接中断时，客户端会尝试其他配置入口；同一服务器进程保留的
Session、缓冲和原目标 socket 可在默认 90 秒断连租期内继续恢复。默认心跳
500 ms、失联阈值 2 秒不是完整恢复时延承诺；拨号、路径状态和目标超时也影响
结果。两端应用 socket 仍须存活。

服务端进程退出、租期到期或目标 socket 关闭后，旧 SSH／TCP 流不能复活；换到
没有原状态的独立服务器也不能靠相同 token 或证书恢复旧流。新请求可建立新
会话，旧应用可能需要自行重连。原型的可靠性和抗识别范围见
[协议说明](PROTOCOL.md) 与 [安全评审](security-review.md)。
