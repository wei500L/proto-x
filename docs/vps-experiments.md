# 测试 VPS 实验复跑入口

更新日期：2026-11-07（Europe/Moscow）。本页依据当前 [`vps-idle.py`](../scripts/vps-idle.py)、[`vps-soak.py`](../scripts/vps-soak.py)、[`vps-fault.py`](../scripts/vps-fault.py) 整理操作步骤，仅用于已授权的专用测试 VPS。当前 Web/ECH 的观测见 [v0.2 报告](recognition-v02.md)；末尾旧观测保留各自版本，不能混用。

以下命令从仓库根目录执行，沿用 [部署文档](deployment.md) 中的 `.local/ssh_config`、管理 alias `protox-test`、`.local/vps-web/client.json` 和测试单元 `protox.service`。换环境时替换这些私密配置与 alias，不把真实地址、token、证书 pin 或 SSH 信息写入公开结果。每次将 `REPLACE_RUN_ID` 换成新的日期/序号；`--out` 目录和对应私有目录都不能已经存在。

## 三个脚本会做什么

| 脚本 | 本地监听与进程 | 远端操作 | 需要 loopback fixture |
| --- | --- | --- | --- |
| idle | 新建 SOCKS `127.0.0.1:1090`、UDP relay `127.0.0.1:16662`，结束后停止本轮进程 | 不执行 SSH，不主动打开应用目标或重启服务 | 否；可保持私网目标许可关闭 |
| soak | 使用已有 SOCKS，默认 `127.0.0.1:1088`；启动负载进程 | 通过管理 SSH 读取 `protox.service` 资源，不重启或改配置 | 是 |
| fault | 新建 SOCKS `127.0.0.1:1089`；blackhole/rebind 使用 UDP relay `127.0.0.1:16660` | 主机键预检查后，**每轮先重启 `protox.service`**；restart 模式还会在测量中再次重启 | 是，另需原有 SSH 服务可从 `127.0.0.1:22` 访问 |

fault 的测量前重启会结束重启前的所有 PROTO-X 会话和目标 socket。它检查的是**本轮启动后建立的流**能否穿过随后注入的故障，不能用来证明重启前旧 SSH/TCP 流恢复。脚本不修改管理 SSH、主机防火墙、NAT 映射或其他已有服务。

## 共同前提

本地需要 Python 3、Go、OpenSSH，以及 fault 探针使用的 `/usr/bin/nc`；该 `nc` 必须支持 `-x host:port -X 5` 的 SOCKS5 参数。JSON 核对通过本地 Python 完成；本轮小 VPS 没有 Python 3，不需为此安装。先构建本地程序；`build.sh` 目前不构建 faultrelay，需要下面单独的 `go build` 命令：

```sh
sh scripts/build.sh
go build -trimpath -o bin/faultrelay ./tools/faultrelay
bin/protox version
```

已部署服务与本地配置的 token、叶证书 pin、窗口须匹配。idle/fault 支持 `h3` 和旧 `quic` UDP 端点；当前使用 H3→H2 回退，两个入口必须指向**同一服务端进程**。旧 `quic/tls` 组合仍可复跑。实验配置只保留一个 UDP 入口及其 TCP 备用：idle 选择第一个 H3/QUIC，fault 也将所有 UDP 条目改向同一个本地 relay；这不是多端点竞速测试。CA、token 和 ECH 文件路径按原配置目录解析，ECH 要求保持不变。

管理 alias 必须已有可信主机键和可非交互使用的认证方式，SSH 配置须保持严格主机键验证。fault 还要求该账号能非交互重启测试单元；脚本不会配置 sudo、SSH 登录策略或新的密钥。可先做不改变远端状态的检查：

```sh
ssh -F .local/ssh_config -o BatchMode=yes \
  -o StrictHostKeyChecking=yes -o ControlPath=none protox-test true
ssh -F .local/ssh_config protox-test \
  'systemctl --no-pager --full status protox.service'
```

保留独立管理终端。按顺序运行实验，确保上述本地端口空闲；不要用 `pkill` 或停止未知进程来腾端口。默认服务端只允许 2 个 Session，停止客户端后远端状态仍可保留至默认 90 秒恢复租期结束，因此并行客户端或立即重复试验可能遇到 `session_limit`。idle/soak 不会自动清空它们。fault 的重启也会中断其他正在使用这个测试服务的客户端，必须选用没有需要保留业务流的测试窗口。

若本机由 mihomo/TUN 接管流量，保持外层服务器连接与管理 SSH 的原有直连安排，避免测试流量再次进入同一个 SOCKS；具体接入见 [部署文档](deployment.md)。

## 为 soak/fault 准备受控目标

两个脚本使用 `pxbench` 的默认目标，当前没有转发自定义目标参数：HTTP/SSE/下载为**服务端** `http://127.0.0.1:18080`，TCP echo 为服务端 `127.0.0.1:18081`。把 fixture 开在客户端的 loopback 不能满足这个前提。

fault 的真实 SSH 探针还固定连接服务端 `127.0.0.1:22`。它必须是管理 alias 对应的**同一个既有 SSH 服务**，使用相同主机身份，并接受已有登录账号/密钥；公网管理端口可以因 NAT 映射而不同。先在管理终端检查现有监听及访问权限。若内部 SSH 不在 22，当前脚本不适用；不要为了让测试通过而重配 SSH 或新开防火墙端口。

准备工作只涉及本轮 fixture 和测试服务配置，使用以下手工步骤：

1. 确认远端 18080/18081 没有其他服务占用。记录测试前的服务状态、程序哈希和私网目标开关；不要输出完整认证配置。
2. 建立一个新的、受限的本轮目录并备份当前服务配置；记录这个路径供恢复使用：

```sh
ssh -F .local/ssh_config protox-test 'uname -m'
ssh -F .local/ssh_config protox-test 'sh -s' <<'REMOTE'
set -eu
umask 077
protox_trial=/opt/proto-x/experiments/REPLACE_RUN_ID
mkdir -p /opt/proto-x/experiments
mkdir "$protox_trial"
cp -p /opt/proto-x/server.json "$protox_trial/server.before.json"
REMOTE
```

3. `deploy-test.sh` 不上传 pxbench。根据上一步架构，把本地交叉构建的 fixture 上传到本轮目录。下面示例用于 `x86_64`；`aarch64` 应改用 `bin/pxbench-linux-arm64`：

```sh
scp -F .local/ssh_config bin/pxbench-linux-amd64 \
  protox-test:/opt/proto-x/experiments/REPLACE_RUN_ID/pxbench
ssh -F .local/ssh_config protox-test \
  'chmod 700 /opt/proto-x/experiments/REPLACE_RUN_ID/pxbench'
```

4. 在管理终端用现有编辑器，仅把 `/opt/proto-x/server.json` 的 `allow_private_targets` 设为 JSON 布尔值 `true`，保留其他字段和原来的 `root:protox`、`0640` 权限。这个开关放开的是整组私网目标限制，并非只允许上述三个端口；只在受控测量期间启用。验证 JSON 后，重启测试服务使配置生效：

```sh
ssh -F .local/ssh_config protox-test \
  'cat /opt/proto-x/server.json' | python3 -c 'import json,sys; json.load(sys.stdin)'
ssh -F .local/ssh_config protox-test 'systemctl restart protox.service'
```

5. 另开一个管理终端，前台运行 fixture，并保留该终端以便最后用 Ctrl-C 停止它：

```sh
ssh -t -F .local/ssh_config protox-test \
  '/opt/proto-x/experiments/REPLACE_RUN_ID/pxbench serve -http 127.0.0.1:18080 -echo 127.0.0.1:18081'
```

fixture 是独立进程，故障脚本重启 `protox.service` 不会重启它。不要把未验证的配置或部分写入文件投入运行。

## 运行空闲观察

```sh
python3 scripts/vps-idle.py \
  --client-config .local/vps-web/client.json \
  --seconds 60 \
  --out results/vps-idle-REPLACE_RUN_ID
```

`--seconds` 默认 60，允许 10–3600。脚本不打开应用流，不需要 fixture 或 `allow_private_targets=true`。它故意把 relay 的故障定时器安排在观察结束以后；若数据中出现 `fault_start`，该次空闲观测无效。检查只有一次配置承载的 H3/QUIC 附加，以及 relay 最后一条事件为 `end`。

`idle-summary.json` 的字节是本地 relay 观察的 UDP payload，包含连接建立和关闭；IPv4+UDP 数值按每包另加 28 字节估算。它不包含 Ethernet/VPN 头，也不证明远端实际收包量、纯稳态开销或移动无线能耗。

## 运行有限时长混合负载

先确认远端 fixture 已运行、私网目标已临时允许，并使用已有的本地 1088 客户端。若尚未启动，在另一个本地终端执行：

```sh
bin/protox client -config .local/vps-web/client.json
```

再运行观察：

```sh
python3 scripts/vps-soak.py \
  --ssh-config .local/ssh_config --ssh-host protox-test \
  --proxy 127.0.0.1:1088 \
  --seconds 600 --background-mbps 2.5 \
  --out results/vps-soak-REPLACE_RUN_ID
```

时长默认 600 秒，允许 10–86400；后台源速率允许大于 0、最高 20 Mbps。实际负载为每秒 5 个 cold HTTP POST、持久 echo、50 毫秒源节奏的 SSE，以及一个按参数限速的后台下载。`background-mbps` 是该下载 worker 的源端应用速率，不是整个代理的外层线速上限。

资源通过独立管理 SSH 大约每 5 秒采一次，另有首尾采样。`MemoryCurrent`/`MemoryPeak` 是 systemd/cgroup 口径，不是纯 Go 堆或进程 RSS；`MemoryPeak` 可能包含测量前活动。CPU 数值依赖成功采样与进程连续性，需同时检查有效采样数、所有采样的 PID、重启计数及时间跨度。脚本不重启服务，也不会在结束后停止已有客户端或远端 fixture。

## 运行承载或进程故障

目前 `--host-key-alias` **可省略**。脚本先用 `ssh -G` 读取有效管理配置：优先使用显式参数，其次使用已有 `HostKeyAlias`，否则由有效 `HostName` 和端口派生已信任的名称；非 22 端口采用 `[hostname]:port`。随后禁用已有 `ControlPath` 复用，进行一次直接管理 SSH 主机键预检查。失败会在重启测试服务之前停止，但已经创建的结果目录不能直接复用。

通常不要传 `--host-key-alias`。确实需要时，它必须是**现有可信管理主机键的名称**，不能凭 SOCKS 目标或 alias 猜一个新名称。当前 fault 脚本对管理与隧道 SSH 都强制 `StrictHostKeyChecking=yes`，沿用既有 known_hosts 与认证配置；不要丢弃 known_hosts、更换主机键或修改脚本关闭检查来绕过失败。

以下三个命令是三个独立试验，使用不同输出目录，逐个运行；每个都会先重启测试服务：

```sh
python3 scripts/vps-fault.py \
  --ssh-config .local/ssh_config --ssh-host protox-test \
  --client-config .local/vps-web/client.json --fault blackhole \
  --out results/vps-blackhole-REPLACE_RUN_ID

python3 scripts/vps-fault.py \
  --ssh-config .local/ssh_config --ssh-host protox-test \
  --client-config .local/vps-web/client.json --fault rebind \
  --out results/vps-rebind-REPLACE_RUN_ID

python3 scripts/vps-fault.py \
  --ssh-config .local/ssh_config --ssh-host protox-test \
  --client-config .local/vps-web/client.json --fault restart \
  --out results/vps-restart-REPLACE_RUN_ID
```

| 模式 | 当前固定行为 | 解释范围 |
| --- | --- | --- |
| blackhole | relay 就绪约 8 秒后，双向丢弃其 UDP 流量 8 秒；TLS 备用直连、不受 relay 丢包影响 | 检验同一原会话向可用 TLS 入口切换；不是整个互联网路径或运营商 DPI 黑洞 |
| rebind | relay 就绪约 8 秒后更换面向服务器的 UDP 源端口；`-for` 不用于此模式 | 仅源端口变化；不是手机换 IP、换运营商或休眠唤醒 |
| restart | 不使用 UDP relay；测量计时约 8 秒后再次重启 `protox.service` | 旧目标 socket 丢失，预期旧 SSH 失败；另查新请求是否恢复 |

每轮 benchmark 为 30 秒，使用默认 HTTP keepalive、5 请求/秒、echo、SSE 和一个**未设置源端限速**的后台下载。它与 soak 的 cold HTTP 和 2.5 Mbps 后台设置不同，不能直接拿两者尾延迟作同条件比较。故障定时、等待和进程收尾会使脚本实际墙钟时间长于 30 秒。

真实 SSH 探针经本轮 SOCKS 连接到远端 127.0.0.1:22，由一个 SSH 进程顺序输出 1–220，源端每行间隔约 100 毫秒。blackhole/rebind 应检查 `ssh_exit=0`、220 行齐全且顺序正确；最长接收间隔包含源节奏、排队和恢复暂停，不等于一次 RTT。

当前 restart 判据要求 SSH 非零退出、收到 1–219 行且构成从 1 开始的正确前缀、重启请求之前已有输出，以及随后有成功的重启命令返回。它使用同一个控制器单调时钟中的 SSH 和重启事件；不能把它与 benchmark 自身的 `recorded_elapsed_ns` 直接相减。还必须用 benchmark 原始事件确认故障后出现新的成功请求；旧 SSH 失败判据本身不证明新请求恢复，也不单独证明中断原因。

历史 restart 结果使用过较弱的判据，因此阅读旧记录时仍须核对 `ssh-events.jsonl` 中的故障前输出。当前判据用该次保留事件及反例做了[离线核验](../results/verification-v011-20261107/fault-evidence-check.json)，没有为这次工具修改重新执行 VPS 重启实验。仅凭重启命令返回 0 也不能证明服务持续健康。

## 数据与判读

| 输出 | 内容 |
| --- | --- |
| idle：`relay.jsonl`、`idle-summary.json` | relay 生命周期、方向计数、实测时长、客户端二进制哈希与开销估算 |
| soak：`bench.jsonl`、`bench.summary.json`、`resources.jsonl`、`soak-summary.json` | 应用原始事件/汇总、资源采样及有效性、有限观测时长 |
| fault：`manifest.json`、`bench.jsonl`、`bench.summary.json`、`ssh-events.jsonl`、`fault-summary.json`、`client-carriers.json` | 脚本/本地二进制哈希、脱敏配置、SSH 序列、应用结果和承载附加/脱离 |
| fault 的附加文件 | blackhole/rebind 有 `relay.jsonl`；restart 有 `restart-events.jsonl` |

衍生客户端配置及完整日志放在 `.local/vps-idle/<输出目录名>`、`.local/vps-soak/<输出目录名>` 或 `.local/vps-fault/<输出目录名>`，不要发布整个私有目录。远端程序版本/哈希、准备和恢复状态需要另外记录；上述脚本不会自动证明远端二进制与本地源码一致。

`pxbench` 退出 0 表示测试器完成记录，不保证所有请求成功。必须一起看成功、明确失败、超时、截尾、SSE 序号/源错误、连接数和 goodput；保留总分母。说明见 [负载文档](workloads.md)。异常中止时可能只留下部分 JSONL 或没有 summary，按未完成试验记录，不补写计划时长。

## 结束与异常后的恢复

纯 idle 且未改变远端配置时，不需要重启或启动 fixture。做过 soak/fault 的试验，正常完成或失败退出后都执行以下核对：

1. 等待脚本和本轮 SSH 探针退出。idle/fault 正常收尾会停止它们启动的本地进程；异常强杀不能依赖这点。按本轮私有日志、命令行和 PID 检查 1089/1090、16660/16662 的残留，只终止确认属于本轮的进程。soak 使用的原有客户端由操作者决定保留。
2. 在前台 fixture 所在管理终端按 Ctrl-C，核对远端 18080/18081 的本轮监听已经消失。保留管理 SSH 的 22 及公网管理通道，不停止其他原有服务。
3. 在管理终端把 `/opt/proto-x/server.json` 的 `allow_private_targets` 恢复为 `false`，保留其他配置与权限。若配置损坏，使用本轮 `server.before.json` 恢复后仍核对该开关为 false；不要覆盖试验期间另行确认的配置变更。此备份只含服务配置，完整版本/凭据回滚另见 [部署文档](deployment.md)。
4. 检查 JSON 和开关后，重启**仅** `protox.service` 使恢复生效。这个重启同样不会保留旧流。核对服务健康及原服务状态，保存一份脱敏的收尾记录。

以下只输出开关，不打印完整配置；在手工恢复后运行：

```sh
ssh -F .local/ssh_config protox-test 'python3 -' <<'PY'
import json
from pathlib import Path
cfg = json.loads(Path('/opt/proto-x/server.json').read_text())
assert cfg.get('allow_private_targets', False) is False
print('allow_private_targets=false')
PY
ssh -F .local/ssh_config protox-test 'systemctl restart protox.service'
ssh -F .local/ssh_config protox-test \
  'systemctl show protox.service -p ActiveState -p SubState -p NRestarts -p MemoryCurrent'
```

必要时重新启动自己使用的本地 1088 客户端，再做显式 SOCKS HTTPS 请求：

```sh
curl --socks5-hostname 127.0.0.1:1088 \
  --connect-timeout 10 --max-time 20 -I https://example.com/
```

这只是当次公网应用可达性检查。若脚本中断在服务重启、后台重启线程或收尾阶段，先用仍保留的管理终端核查实际状态；不要把缺失 summary 当作“没有发生远端改动”。

## 已保留的历史结果

| 记录 | 已观察到的范围 |
| --- | --- |
| [v0.1.1 idle](../results/vps-idle-v011-20261107/idle-summary.json) | 60.214 秒、0 应用流、1 次 QUIC 附加；包含启动/关闭的本地 UDP 计数 |
| [早期 soak](../results/vps-soak-20261107/soak-summary.json) | 600.332 秒脚本墙钟、117/117 有效资源采样；对应 benchmark 约 600 秒；不是 v0.1.1 的多日稳定性结果 |
| [错误主机键别名试验](../results/vps-blackhole-v011-20261107/execution-note.json) | 保留原 `vps-blackhole-v011-20261107`；错误显式别名被主机键验证拒绝，SSH 退出 255、收到 0 行，不计为 SSH 恢复成功 |
| [修正后的补跑](../results/vps-blackhole-v011-repair-20261107/fault-summary.json) | `vps-blackhole-v011-repair-20261107`；从有效管理配置派生可信名称并预检查，SSH 220/220、顺序正确、退出 0，最长接收间隔约 2708.73 ms |
| [部署收尾检查](../results/deployment-v011-20261107/final-state.json) | 当时测试服务与原参考服务正常、私网目标许可关闭、临时 fixture 已停止，并完成一次公网 SOCKS HTTPS 检查 |

错误别名试验的 HTTP/echo/SSE 数据仍保留；补跑包含了实际 SSH 负载，两轮不能被合并为同一完整成功试验。更完整的失败分母和比较见 [结果报告](RESULTS.md)。这些都是一个授权 VPS 路径上的有限观察，不是所有俄罗斯网络、移动切换、抗识别或跨服务器存活的保证。
