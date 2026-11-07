# HTTP/2、HTTP/3 整套部署与恢复

更新：2026-11-07。此页对应新版 `scripts/deploy-test.sh`；旧文档中只复制五个文件的恢复命令不适用于带 cover / ECH / CA 的部署包。

主任务已在专用 VPS 完成首次安装与后续整包更新，并单独核对普通 HTTPS、H2/H3 SOCKS 与 ECH 要求。当前配置、实际版本及脱敏状态见 [部署状态](../results/deployment-web-20261107/final-state.json)。下面 21 项故障事务测试仍是本地替身测试，不能把它们改称远端回滚实测。

## 适用范围与准备

此脚本只用于用户明确授权的专用测试 VPS。SSH alias 必须指向该测试机；脚本无法从一个任意 alias 自动判断它是不是生产机。它只管理 `protox.service` 和 `/opt/proto-x` 下列出的项目资产，不改 SSH、NAT、防火墙或其他服务，也不操作本地客户端。

本地需要 Python 3 标准库及其 SSL 模块、OpenSSH、已经构建的 Linux 二进制。远端需要 root SSH、systemd、tar、sha256sum、getent 和账号管理命令。Python 只在本地用于组包；远端执行 shell 与系统工具。非交互 SSH 使用 `BatchMode=yes` 和 `StrictHostKeyChecking=yes`，所以应先完成密钥登录和已核对的 host key 配置。

在仓库根目录构建后，用私密服务端目录部署：

```sh
sh scripts/build.sh
sh scripts/deploy-test.sh .local/ssh_config protox-test .local/vps-web
```

`build.sh` 会运行项目 Go 测试并构建二进制。部署脚本通过远端架构选择 `bin/protox-linux-amd64` 或 `bin/protox-linux-arm64`；本页的本地事务测试没有执行远端应用，也不替代构建与在线互通验证。

## 部署包与相对路径

目录至少包含有效的 `server.json`，以及该配置引用的证书、私钥、token。HTTP/2 或 HTTP/3 配置必须声明 `cover_dir` 并提供完整公开目录。常见目录如下；可选文件不必全有：

```text
.local/vps-web/
  server.json
  server.crt
  server.key
  token
  cover/
    index.html
  ech-keys.json       # 可选，服务端私有 ECH 密钥
  ech-config.bin      # 可选，供客户端使用的公开 ECH 配置
  ca.crt             # 可选；也接受输入名 ca.pem
  client.json        # 保留本地，不上传
```

打包时只改临时副本，源目录和原 `server.json` 保持不变。配置字段指向的资源被复制为下面的固定名称，并把临时配置中的字段改为对应相对路径：

| 配置字段 | 部署后的资源 |
|---|---|
| `cert_file` | `/opt/proto-x/server.crt` |
| `key_file` | `/opt/proto-x/server.key` |
| `token_file` | `/opt/proto-x/token` |
| `cover_dir` | `/opt/proto-x/cover/` |
| `ech_keys_file` | `/opt/proto-x/ech-keys.json` |
| `ech_config_file` | `/opt/proto-x/ech-config.bin` |
| `ca_file` | `/opt/proto-x/ca.crt` |

源路径可以是私密目录内的相对路径，或该目录内的绝对路径。以 `/opt/proto-x/` 开头的部署路径也可映射到私密目录中的对应文件，例如 `/opt/proto-x/certs/site.key` 从输入目录的 `certs/site.key` 读取。其他绝对路径、`..` 跳转和资产符号链接会被拒绝。

systemd 仍使用 `WorkingDirectory=/opt/proto-x` 和 `/opt/proto-x/server.json`。应用按配置所在目录解析这些相对路径，因此全部运行资产从 `/opt/proto-x` 读取。脚本不会依赖临时 staging 路径，也不会保留原本位于本地开发机的绝对路径。

若可选字段非空，引用的资源必须存在。字段未设置时，输入目录中标准名称的 `ech-keys.json`、`ech-config.bin`、`ca.crt` / `ca.pem` 仍会随包保存，但不会因此自动启用 ECH 或更改 CA 配置。如果同时有 `ca.crt` 和 `ca.pem`，须通过 `ca_file` 明确选择。

本地组包会检查 JSON、token 格式、证书与私钥配对，以及 CA 文件能否解析。它不验证公网上的域名、证书信任、NAT 映射或 ECH 互通。cover 必须只含公开目录与常规文件；部署脚本拒绝其符号链接，也拒绝把配置已引用的私钥、token、ECH 私钥或服务配置放进 cover。客户端配置和服务端私钥属于不同分发范围，脚本只上传服务器需要的资产。

## 更新事务与状态检查

每轮在本地 `.local/deploy-package.*` 创建完整包，在远端 `/opt/proto-x/.upload.*` 创建独立暂存目录。包有整体 SHA-256，解包后还逐个检查文件 SHA-256。共享旧 `staging/` 目录不会被读取或复用。

安装过程持有 `/opt/proto-x/.deploy-lock`，其中记录安装进程 PID、暂存路径和完整备份路径。另一次部署看到锁会退出，避免同时替换文件。备份成功前不会停止旧服务。

受管资产是：

```text
protox server.json server.crt server.key token cover
ech-keys.json ech-config.bin ca.crt ca.pem protox.service package.sha256
```

`ca.pem` 属于旧名称清理范围；新包统一使用 `ca.crt`。`protox.service` 同时在包内留副本，并安装到 `/etc/systemd/system/protox.service`。`experiments/`、`baselines/`、既有历史备份和其他未列出的文件不会被替换。

旧的整套受管资产和 systemd unit 先备份，再关闭该服务的常规开机启用并停服。服务停止后才删除旧受管项、移动完整新包并安装新 unit。这样新包省略的旧 ECH / CA 文件也会消失，cover 的旧页面不会残留。正常启动之前，证书、密钥、配置和站点均已换成同一部署包。

新文件由 `root:protox` 管理。目录为 `0750`，程序为 `0755`，配置、密钥、token 和公开文件为 `0640`；系统 unit 为 `root:root`、`0644`。服务继续以无登录权限的 `protox` 账号运行。缺少账号或组时会创建；初次安装失败后，这个无登录账号/组可保留，不用于运行残留服务。

`systemctl restart` 返回成功之后，脚本每秒检查一次，共五次：服务必须 active，MainPID 必须非零且不变，NRestarts 必须不增加。通过后才重新启用开机启动，并再次核对状态。`Type=simple` 程序在 restart 返回后才退出、或在观察期内反复重启，都会触发恢复。

这五秒是进程存活检查。它不能证明入口映射、普通网页、认证、代理转发或长连接恢复已经可用；部署后还应使用配套客户端，分别检查普通 HTTPS 访问和实际 SOCKS 请求。服务端重启会结束已有会话与目标 socket，不能把重启回滚描述为原有 SSH 流无损恢复。

## 自动恢复与备份内容

完整备份目录带 UTC 时间和随机后缀，例如 `/opt/proto-x/backups/REPLACE_BACKUP_ID/`：

```text
files/             # 当时实际存在的所有受管资产，含完整 cover
systemd-unit       # 旧系统 unit；初次安装没有这一项
was-active         # yes / no
was-enabled        # enabled / enabled-runtime / disabled / not-found 等已支持状态
had-unit           # yes / no
managed-assets     # 本轮固定受管集合
```

任何激活失败都会先停止新进程，再删除新受管项，恢复旧文件、旧 unit、原启用状态和原运行状态。原来停止的服务会保持停止。首次安装没有旧版本时，会移除新文件和 unit，并停止失败的服务。脚本只处理 `protox.service`，不停止 SSH、Xray、sing-box、busybox 或其他服务。

恢复成功后，本轮部署仍返回非零退出码，明确表示更新没有成功。自动恢复自身失败时返回 `3`，输出 `AUTOMATIC RESTORE FAILED`，保留部署锁、完整备份和暂存目录供恢复，不继续覆盖它们。

HUP、INT、TERM 及常规命令失败会进入恢复处理。SIGKILL、断电、内核故障或 SSH 失联后远端进程仍在运行等情形不能靠 shell trap 保证完成；检查锁中记录的 PID 与实际进程状态，不能仅因连接断开就同时启动第二轮更新。修改前关闭常规开机启用，可减少重启后启动半套文件的风险。

备份没有自动保留数量上限。上传与备份期间可能同时存在旧版本、旧版本备份、新 tar 和解包后的新版本；测试机需有相应空闲磁盘。历史备份含私钥与 token，只保留在 root 可读目录，不上传到公共仓库；确认版本和恢复需求后再清理旧备份。

## 手工恢复完整包

先选定同一轮完整备份。如果 `.deploy-lock` 存在，查看其 `pid`、`stage`、`backup`，核实记录的安装进程已经结束；仍在运行时等待其完成。确认是遗留锁后再删除锁内这三个记录与空锁目录。不要终止 SSH 管理进程来解锁。

以下命令要求锁已不存在，并把 `REPLACE_BACKUP_ID` 替换为实际目录名。它会恢复原运行状态；备份原来没有服务时不会新建运行中的服务。失败时保留锁与备份定位，便于继续处理。

```sh
ssh -F .local/ssh_config -o BatchMode=yes -o StrictHostKeyChecking=yes protox-test 'sh -s' <<'REMOTE'
set -eu
umask 077
base=/opt/proto-x
backup=$base/backups/REPLACE_BACKUP_ID
unit=/etc/systemd/system/protox.service
assets='protox server.json server.crt server.key token cover ech-keys.json ech-config.bin ca.crt ca.pem protox.service package.sha256'
test -d "$backup/files"
was_active=$(cat "$backup/was-active")
was_enabled=$(cat "$backup/was-enabled")
had_unit=$(cat "$backup/had-unit")
case "$was_active:$had_unit" in yes:yes|no:yes|no:no) ;; *) exit 1;; esac
case "$was_enabled" in enabled|enabled-runtime|disabled|not-found|'') ;; *) exit 1;; esac
if [ "$had_unit" = yes ]; then test -f "$backup/systemd-unit"; fi
mkdir "$base/.deploy-lock"
printf '%s\n' "$$" > "$base/.deploy-lock/pid"
printf '%s\n' "$backup" > "$base/.deploy-lock/backup"
if [ -f "$unit" ]; then
  systemctl disable protox.service
  systemctl stop protox.service
fi
for name in $assets; do rm -rf -- "$base/$name"; done
for name in $assets; do
  if [ -e "$backup/files/$name" ] || [ -L "$backup/files/$name" ]; then
    cp -a -- "$backup/files/$name" "$base/$name"
  fi
done
rm -f -- "$unit"
if [ "$had_unit" = yes ]; then cp -a -- "$backup/systemd-unit" "$unit"; fi
systemctl daemon-reload
case "$was_enabled" in
  enabled) systemctl enable protox.service;;
  enabled-runtime) systemctl enable --runtime protox.service;;
esac
if [ "$was_active" = yes ]; then
  systemctl start protox.service
  pid=$(systemctl show --property=MainPID --value protox.service)
  restarts=$(systemctl show --property=NRestarts --value protox.service)
  case "$pid" in ''|0|*[!0-9]*) exit 1;; esac
  for check in 1 2 3 4 5; do
    sleep 1
    systemctl is-active --quiet protox.service
    test "$(systemctl show --property=MainPID --value protox.service)" = "$pid"
    test "$(systemctl show --property=NRestarts --value protox.service)" = "$restarts"
  done
fi
rm "$base/.deploy-lock/pid" "$base/.deploy-lock/backup"
rmdir "$base/.deploy-lock"
printf 'Restored complete package and previous service state from %s\n' "$backup"
REMOTE
```

若凭据或证书也曾更换，本地客户端须使用对应备份版本的 token、信任配置和 ECH 参数，再做互通检查。只恢复二进制或者只恢复证书会破坏配套关系。

## 本地验证范围

```sh
sh -n scripts/deploy-test.sh
python3 scripts/test-deploy.py
```

2026-11-07，macOS arm64 / Python 3.9.6：21 项事务检查通过，完整运行 29.221 秒。验证脚本在私密临时目录中执行实际部署 shell、本地组包、tar、SHA-256 和文件操作；SSH、systemd、账号、所有权和等待时间用明确的测试替身代替，没有访问 VPS。

覆盖首次安装与账号创建、首次安装在 unit 创建前或启动后失败、旧包恢复、原来 inactive / disabled 或 enabled-runtime 状态恢复、旧 optional 和 cover 页面删除、stale staging 忽略、配置路径归一与源文件不变、证书私钥不匹配、缺失资产、公开目录符号链接或包含已知私密资产、路径跳转、上传中断、checksum 错误、备份失败、逐文件替换失败、restart 成功后退出、active 状态下 PID / NRestarts 变化、既有锁保护及自动恢复失败保留记录。

文件权限在本地实际检查；`root:protox` / `root:root` 所有权只核对命令意图，没有在 macOS 创建系统账号或改变实际所有权。真实 systemd 行为、实际五秒存活和 H2/H3 应用可用性需要由主任务在测试 VPS 上继续验证。
