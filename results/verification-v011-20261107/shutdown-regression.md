# v0.1.1 客户端退出回归记录

日期：2026-11-07（Europe/Moscow）。执行环境：`go version go1.27.1 darwin/arm64`。全部连接位于本机 loopback，使用测试临时生成的证书和 token；没有访问 VPS、虚拟机或生产环境。

测试源码：[`internal/app/client_shutdown_test.go`](../../internal/app/client_shutdown_test.go)。测试直接调用真实 `RunClient`，没有替换其管理循环、复制清理实现或加入生产测试钩子。

## 检查内容

- `TestRunClientCancelClosesPendingTLSHandshake`：对端完成真实 TLS 握手并读取 HELLO，随后扣住 WELCOME。此时客户端已持有承载，但还没有把它附加到 Session。取消客户端后检查退出及连接关闭。
- `TestRunClientCancelClosesAttachedTLSCarrier`：对端发送 WELCOME，再通过匹配的 PING/PONG 确认 Session 接收循环已处理记录，然后取消客户端。

两项测试均把应用握手截止时间设为 5 秒，要求取消后 2 秒内返回；在 `RunClient` 返回后立即读取对端，允许 300 毫秒的本机调度/传送时间来观察 EOF。这样不会通过等待旧实现的普通握手超时来掩盖提前返回。HELLO 与 PONG 是阶段屏障；测试不使用 `time.Sleep`。

## 实际执行结果

| 执行 | 用例与次数 | 退出码 | 结果 |
| --- | --- | --- | --- |
| 当前 v0.1.1 客户端，race | 两项各 1 次 | 0 | `ok proto-x/internal/app 1.471s` |
| 当前 v0.1.1 客户端，race | 两项各 10 次 | 0 | `ok proto-x/internal/app 1.371s` |
| 仅用 overlay 换回旧 `client.go`，race | 未完成握手用例 1 次 | 1 | 用例在 0.31 秒失败；包输出耗时 0.753 秒 |

耗时是 Go 测试输出，不是协议性能指标；重复通过也不是二十种独立网络场景。

当前版本的实际命令（在仓库根目录执行）：

```sh
go test -race -count=1 \
  -run '^TestRunClientCancelCloses(PendingTLSHandshake|AttachedTLSCarrier)$' \
  -timeout=20s ./internal/app

go test -race -count=10 \
  -run '^TestRunClientCancelCloses(PendingTLSHandshake|AttachedTLSCarrier)$' \
  -timeout=30s ./internal/app
```

旧实现负向复现的输出摘录：

```text
--- FAIL: TestRunClientCancelClosesPendingTLSHandshake (0.31s)
    client_shutdown_test.go:25: RunClient returned before its TLS carrier closed: read tcp 127.0.0.1:51579->127.0.0.1:51581: i/o timeout
FAIL
FAIL	proto-x/internal/app	0.753s
FAIL
```

这里的 FAIL 是实际观察到的旧缺陷，不计作当前版本的通过。旧 `RunClient` 已经返回，但未附加的 TLS 握手承载仍未关闭；读取在 300 毫秒后超时。随后测试清理关闭对端，旧管理循环才从握手读取中退出。

## 旧实现重跑方法

旧源码固定为提交 `5d80253d057b5004a3fad77d50ea4ed315eb0b85` 的 `internal/app/client.go`。**只替换这个文件**：其余当前实现和新增测试保持原样。下面在仓库根目录生成临时 Go overlay，运行同一个负向用例，然后删除临时目录；不依赖之前运行时的随机路径，也不修改工作区文件。预期命令退出码为 **1**，失败原因应与上面相同；编译失败或其他错误不能算作复现成功。

```sh
python3 - <<'PY'
import json
import pathlib
import subprocess
import tempfile

root = pathlib.Path.cwd().resolve()
(root / '.local').mkdir(exist_ok=True)
old = subprocess.run(
    ['git', 'show', '5d80253:internal/app/client.go'],
    cwd=root, check=True, stdout=subprocess.PIPE,
).stdout

with tempfile.TemporaryDirectory(prefix='shutdown-overlay-', dir=root / '.local') as name:
    work = pathlib.Path(name)
    replacement = work / 'client.go'
    replacement.write_bytes(old)
    overlay = work / 'overlay.json'
    overlay.write_text(json.dumps({
        'Replace': {str(root / 'internal/app/client.go'): str(replacement)}
    }))
    result = subprocess.run([
        'go', 'test', '-race', '-count=1', '-overlay', str(overlay),
        '-run', '^TestRunClientCancelClosesPendingTLSHandshake$',
        '-timeout=15s', './internal/app',
    ], cwd=root)
    raise SystemExit(result.returncode)
PY
```

旧文件 SHA-256 为 `91e23b44dc5af01db3d360adaaba69ad9068faad9e0ddd86e29d9a6445d9df28`。归档时当前文件的 SHA-256 如下，后续改动应重新绑定验证结果：

| 文件 | SHA-256 |
| --- | --- |
| `internal/app/client.go` | `5fe317675fc70e032727c4e625cfa57c55d116395f8fda64af5c335305b016bb` |
| `internal/app/client_shutdown_test.go` | `29d54cf0c1ec5ee9c330a7535fed19fa9ab3cc761c078097c6e7c0f4a99f9288` |

## 结论边界

本次实测覆盖真实 TLS 上的未完成应用握手和已附加空闲会话退出。`manage` 完成后再读取、关闭 `current` 的代码顺序已复核；首次 Session 发布与取消的窄竞态、非取消原因的 `Accept` 失败，没有在这两项测试中单独故障注入。QUIC 应用握手取消也没有由这两项 TLS 测试验证。

退出边界通过对端 EOF 检查，并留有上述 300 毫秒观察窗口；它不是每个系统调用先后顺序的形式证明。测试没有断言所有 SOCKS 处理协程已经退出，也没有断言服务端保留的目标 socket 随客户端退出立即关闭。原有十项安全边界检查、真实网络丢包、进程崩溃和长期资源泄漏不属于本次退出回归的覆盖范围。
