# Web 承载独立窄审查：2026-11-07

本次范围是 `internal/app/web.go`、`web_init.go`、`config.go`、`internal/carrier/web.go`、`web_tls.go`，并只为确认调用关系读取客户端、Link、静态站点和部署打包器。审查者未修改传输、TLS 或 app 实现；主开发者修复初始化缺陷后，审查者新增独立回归测试。没有重复已有的全量 race/vet、H3↔H2 恢复、ECH 和主动探测测试，没有访问 VPS。

**结论：本次确认一个需要本地写权限的 P2 初始化缺陷，修复后窄回归 24/24 通过。本次范围内未发现新的远程认证绕过或静默 ECH/CA/ALPN 降级阻断项。** 这不是对整个协议或依赖库的独立安全认证。

## WEB-REVIEW-01：悬空链接可让初始化将私密材料写入公开目录（已修复）

修复前 `initPair` 以 `os.Stat` 检查五个输出名，随后以 `os.WriteFile` 落盘；`GenerateECH` 对两个 ECH 输出名同样处理。`Stat` 跟随链接，悬空链接被当成目标不存在，之后的写入会跟随该链接。`InitWeb` 在写私钥前创建默认 `cover`，因此预置 `server.key → cover/leaked.key` 会把新私钥写成站点内的普通文件。ECH 私钥也有相同问题。

实际执行的本地隔离复现调用了当前源码的 `app.InitWeb`、`app.GenerateECH`、`cover.NewSite` 和 `carrier.WebHub.ServeHTTP`，由 `httptest` 驱动未认证分支，没有网络监听、TLS 互通或 VPS 测试。凭据和生成文件仅保存在忽略的 `.local/review-web-20261107/`，报告未保留任何私密内容。

| 修复前实际观测 | InitWeb / server.key | GenerateECH / ech-keys.json |
| --- | --- | --- |
| 初始化返回成功 | true | true |
| 输出路径仍为预置链接 | true | true |
| 未认证 handler 响应状态 | 200 | 200 |
| 响应体与生成私密文件逐字节相同 | true | true |
| 代理 Handshake 回调次数 | 0 | 0 |

前提是另一主体或错误的本地准备过程已能在初始化目录创建链接；不是远程攻击者从 URL 穿越 `os.Root`。受管部署脚本本来就拒绝资产链接，因而该打包路径未暴露。独立前台初始化则确实受影响，不能依赖“公开目录原本应只含公开内容”来豁免生成器写入错误。

修复前等价的初始化复现步骤如下；这是供复核的命令示例，本次实际运行的是上述 Go helper：

```sh
repro_dir=$(mktemp -d "$PWD/.local/web-init-review.XXXXXX")
ln -s cover/leaked.key "$repro_dir/server.key"
go run ./cmd/protox init -dir "$repro_dir" -host 127.0.0.1 -server-name localhost
ln -s cover/leaked-ech.json "$repro_dir/ech-keys.json"
go run ./cmd/protox ech-keygen -dir "$repro_dir" -public-name cover.example
```

主开发者新增 `private_files.go`：`requireNewFiles` 用 `Lstat` 拒绝任何既存条目及检查错误；`writeNewPrivateFile` 用 `O_WRONLY|O_CREATE|O_EXCL` 和 `0600` 创建。初始化配置、密钥、ECH 文件及默认站点写入都调用该 helper。只读复核确认独占创建也覆盖末级路径在检查和写入之间被创建的情况；父目录仍须可信，不能据此宣称可安全写入恶意本地目录树。

独立测试 `internal/app/web_init_security_test.go` 覆盖 Init 与 InitWeb 各五个输出名、GenerateECH 两个输出名，分别放入悬空链接和常规文件，共 24 个叶用例。断言初始化拒绝、链接目标未创建、链接原样保留、已有文件内容/身份/权限不变，并且没有生成其他输出。执行：

```sh
go test ./internal/app -run '^TestPrivateInitializersReject' -count=1 -v
```

实际结果：退出码 0，24/24 叶用例通过，包报告 0.441 秒；本次变更范围 `git diff --check` 通过。没有把这些文件系统用例算作网络或压力测试。

## 其他审查结论与保留边界

- **认证回落：** WebHub 对缺少/错误认证、无法解析或重复 carrier/stream、错误连接绑定、重复控制 Link 和容量拒绝使用同一 Site。Gate 后的无效 HELLO 是第二阶段认证失败，会结束已建立的 HTTP 通道；不能把它描述成仍返回一模一样的静态站点响应。没有发现未通过 HELLO 就创建代理 Session/目标 socket 的新路径。
- **TLS 策略：** Web 构造器显式要求 TLS 1.3、所选 ALPN 和配置的 ECHAccepted；DialWeb 又要求实际 H2/H3 ALPN。CA 文件错误不回落到系统根，pin-only 必须显式启用且具有 pin。配置 ECH 时 app 拒绝 legacy endpoint，重拨继续使用同一 ECH 设置。未配置 ECH 且显式加入旧 tls/quic endpoint 的诊断配置仍使用旧 pin 信任模型，不能把这一混合配置解释成所有路径都具有 Web CA 验证。
- **HTTP 生命周期：** 已读取 handler 返回前的 I/O barrier、首次 header flush 后发布 stream、取消/关闭时中止阻塞 I/O、正常流退役与故障中止的区分。未发现新的可确认生命周期缺陷；既有 race/恢复测试结论由其原运行记录提供，本审查没有重复执行。
- **公开目录误配置仍可能泄密：** 前台 app 启动只要求 `cover_dir` 非空，不验证它与私钥/token/配置的路径重合。若操作者将私密配置目录本身配置为网站根，普通静态文件 handler 就能发布其中的普通文件。文档明确要求只放公开内容，受管打包器另行拒绝已知私密资产位于 cover 内。此边界仍保留，修复 WEB-REVIEW-01 不意味着配置根目录自动安全。
- **连接资源与可用性：** H2 的 16 个 TCP 连接槽与 H3 的 16 个应用可见连接槽由普通网站访客和代理共享，没有为认证代理保留槽或每来源配额。H3 槽位限制在 QUIC 握手之后执行；不能约束握手前的 CPU/库内状态。普通网站响应没有全局写超时，保持活动的访客可能持续占槽。header、窗口、槽和 Session 上限不是整体 DoS 保证。本次只据代码确认这些边界，未运行占槽/洪泛实验或量化攻击成本；既有文档已保留 DoS 未解决范围。

## 代码快照

工作树基准提交 `a7fe191f07ac1824148294f46c33f3ad782e00fc`，相关 Web 文件当时包含未提交修改。修复前快照采集于 `2026-11-07T04:12:09.698899+00:00`；修复后记录于 `2026-11-07T04:15:20.868407+00:00`，均为 UTC。SHA-256 绑定具体内容，不把基准 commit 误写成本次最终实现版本。

修复前缺陷文件：

| 文件 | SHA-256 |
| --- | --- |
| `internal/app/config.go` | `1b6556770f0acea73f773369c6083f81409d8111737653f6ed9df3e4716aa158` |
| `internal/app/web_init.go` | `ad0325a89b6956da28e4af57fd12418df253d2177695b07f02d728b15bb58d18` |

修复后实现及独立测试：

| 文件 | SHA-256 |
| --- | --- |
| `internal/app/config.go` | `ec9c8d27c138ccdcb2e684f855cf33f5d3a27b08eb6cfed265f35b042839609d` |
| `internal/app/web_init.go` | `1d5cebc4397e4c15b7f55581a63470ab5bd1fb2a20f4655ccb18369055eb7367` |
| `internal/app/private_files.go` | `b09c5cdbd088074cafe0203d4f7143f502094414f07e05571bb84bb30baeca65` |
| `internal/app/web_init_security_test.go` | `5e279f318f7fa71d50e7c7e67c6b5322f50a1b034efed3f31d5cf8cf421556c7` |

其他本次读取且审查期间未改变的关键文件：

| 文件 | SHA-256 |
| --- | --- |
| `internal/app/web.go` | `7f676df6e5ec498fb6146a246aca75e09df056074a6335e325647b2786b41b79` |
| `internal/carrier/web.go` | `3c608ebb3c35af3ab0e77336bba49f62d4e2146b5be43f295529dc65e4d55572` |
| `internal/carrier/web_tls.go` | `ddeae5b4d071d7b9392edf14b4c407c43c8e7725ea682d42c9aa4b12ed97a33b` |
| `internal/app/client.go` | `37116a369b8b286917059d719016ece7d9e800df64842acb34fdeeb19da28c2f` |
| `internal/cover/site.go` | `8d8073bfb477f6e087f5fd56f3e7a55cdb7a1e2774f55f0e7a9e8f43f64d62f5` |
| `scripts/deploy-test.sh` | `216e1df3368689818276f32807bc373fc8a8ea95437f40650e02ecfbfec96d63` |
