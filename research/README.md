# 研究变体、源码与重跑

这里保存已实现、实测或完成正确性检查的独立变体。部署主线为
`0.1.1-experimental`；下面的变体均从原基线 `5d80253` 派生，**没有与主线
心跳/退出修订合并，也没有部署到测试 VPS**。不能把各分支的结果相加。

| 变体 | 源码身份 | 已有证据 | 保留方式 |
| --- | --- | --- | --- |
| 稀疏 DATAGRAM 副本 | `research/hints`，`9b60c69` | 字节/恢复检查；15 项筛选；3×90 秒独立验证，有局部交互收益和明确成本 | [补丁](patches/sparse-copies.patch)、[源码包](hints/protox-sparse-copies-source.tar.gz)、[机制](hints/hints-prototype.md)、[评审](hints/hints-review.md) |
| Hysteria 旧 QUIC fork CC | `research/cc`，`a7a3334` | Linux 包级 CC 消融及窗口诊断；未解决综合交互表现，迁移会重置 CC | [完整来源与复现](cc/README.md)、[补丁](patches/cc-hy-fork.patch) |
| 官方 quic-go 0.65 CC 扩展 | `research/cc65`，`5959fe0` | 迁移/NAT/MTU/并发安装/承载恢复检查；Linux 仅交叉编译，未做性能比较 | [完整来源与复现](cc/README.md)、[补丁](patches/cc65.patch) |

这些补丁是从指定基线到各研究分支的完整差异，不是可任意叠加的增量包。CC
代码复用 Hysteria 的 MIT 实现，源码与许可一并保留，不称为 PROTO-X 原创拥塞算法。

## 稀疏副本的构建与配置

在含本项目 Git 历史的仓库根目录执行；目标工作树路径须未存在：

```sh
protox_repo=$(pwd)
git worktree add --detach .local/replay-hints 5d80253
git -C .local/replay-hints apply "$protox_repo/research/patches/sparse-copies.patch"
cd .local/replay-hints
go test -race -count=1 -timeout=60s ./...
go vet ./...
go build -trimpath -ldflags '-s -w -X main.version=0.2.0-hints-experimental' \
  -o protox ./cmd/protox
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
  -ldflags '-s -w -X main.version=0.2.0-hints-experimental' \
  -o protox-linux-arm64 ./cmd/protox
```

Go 1.27.1 上，基线加补丁、保持未提交状态的独立重建已实际复现冻结的 Linux
arm64 SHA256 `0b42f0a8fc63165ed1e9e99d4eb650da6af4e3c097a2a08913fa6e50595d98fe`，
见 [重建记录](hints/replay-verification.json)。提交后 VCS 元数据不同，二进制
哈希也会不同；这不等于逻辑变化。无 Git 历史时可解压源码包再构建，源码包没有
私密配置或 `.git`，不能要求它产生包含原 VCS 元数据的同一哈希。

使用新建配置目录运行 `./protox init -dir .local/demo -host 127.0.0.1
-tls-port 14443 -quic-port 14443`，在生成的**两端** JSON 中增加
`"sparse_redundancy": true`，再按[主部署说明](../docs/deployment.md)的 server/client
形式运行。无副本对照两端都设为 false，其他配置与二进制保持相同。示例里的
地址是本机联调；连接已授权远端时换成实际端点。配置与 token 保持私密。

该开关不属于主线 v0.1.1 的 JSON 字段；主线会拒绝未知字段。研究版本另有
40 ms 仅在提交前生效、内部队列未必及时过期、退出日志计数可能缺失等限制，
见上述机制与评审。实验冻结版不用于替换现有客户端。

## 实验与证据入口

- [筛选](../results/hint-screening-20261106/ANALYSIS.md)与
  [独立验证](../results/hint-confirmation-s307-20261107/ANALYSIS.md)：全部失败/截尾、
  源码与二进制身份、网络模型、CPU/RSS、外层字节、原始事件及复算工具。
- [CC 筛选](../results/cc-screening-20261106/ANALYSIS.md)与
  [窗口诊断](../results/cc-window-diagnostic-20261106/ANALYSIS.md)：同 fork 内的 CC
  消融，以及更大信用窗口只释放吞吐、未降低交互尾部的反例。
- [CC 导出校验](cc/ARTIFACTS.json)和 `python3 research/cc/verify_exports.py`：
  来源、补丁、许可证、已完成测试与原始失败/跳过记录。
- [实验室](../docs/lab.md)：重建 namespace / netem、基线版本、冻结二进制、矩阵命令。
  运行原冻结矩阵前按其脚本检查 SHA；源码变更应建立新的 run，不重写历史结果。

seed 307 已用于独立验证，不能再次标成未见数据。研究的当前结论与下一轮优先级
见[总报告](../docs/RESULTS.md)。没有俄罗斯移动现场或抗识别验证。
