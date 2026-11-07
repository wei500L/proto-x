# 可复现的包级网络实验室

实验室在 macOS arm64 上运行一个专用的 Debian 13 arm64 虚拟机。它使用真实 Linux TCP/UDP 栈、`veth`、网络命名空间和 `tc netem`；TCP 字节流延迟代理不能代替这里的丢包实验。

## 已建立的环境

- Lima **2.3.0**，Apple Virtualization，2 vCPU、1 GiB RAM、8 GiB 稀疏磁盘；首次安装实际占用约 1.4 GiB。
- 内核 `6.12.115+deb13.1-cloud-arm64`，iproute2 `6.15.0`，iperf3 `3.18`。
- Lima 下载版本及 SHA256 固定于 `scripts/lab/bootstrap.sh`；Debian 镜像 `20261103-2651` 的 SHA512 固定在 `scripts/lab/protox-lima.yaml`。若上游移除该日期镜像，需明确选择、记录新版本，不会自动改用未固定的每日镜像。
- SSH、虚机磁盘和密钥仅在 `.local/lab/`。未挂载用户家目录或仓库；关闭普通端口的自动转发，只保留 Lima 管理 SSH。主机系统代理和网络规则未修改。
- 专用 VPS 没有 `CAP_NET_ADMIN`/`CAP_NET_RAW`；因此在本地虚拟机做包级仿真，在 VPS 另做真实路径互通，二者不能混写。

## 拓扑与隔离

```text
px-client                         px-server
10.203.0.1/30 -- impaired veth -- 10.203.0.2/30
pxlinkc         (two directions)   pxlinks
  | separate default route          | separate default route
  +----------- VM root NAT ---------+
              guest management NIC / SSH (unshaped)
```

代理客户端和业务测试器在 `px-client`，代理服务端、受控 HTTP/SSE/回显源站在 `px-server`。代理外层必须连接 **10.203.0.2**，才会穿过实验链路。业务源站可绑定 `px-server` 中的 `127.0.0.1`。Xray 新版默认出站策略会拒绝环回目标；基线生成器需显式 `--allow-test-cidr 127.0.0.1/32`，参见 `baselines.md`。

两个命名空间各有不受损伤的独立默认路由，只供取包、DNS或外部 REALITY cover 目标。实际业务应使用受控本地源站；否则源站路径成为额外变量。`ip route get 10.203.0.2` 可核实实验路径。脚本只修改自己创建的命名空间、`px*` veth 和专用 nft 表，不给 guest 管理 NIC 或 macOS 添加 qdisc。

## 启动及操作

```sh
# 第一次安装，下载开源工具/镜像并启动虚机、配置命名空间。
scripts/lab/bootstrap.sh

# 之后使用；停止再启动 VM 后需重新 init 命名空间。
scripts/lab/vm.sh start
scripts/lab/vm.sh shell uname -a
scripts/lab/vm.sh copy tools/lab/netlab.py protox-lab:/tmp/netlab.py
scripts/lab/vm.sh shell sudo python3 /tmp/netlab.py init

# 复制 Linux arm64 可执行文件或私密配置。
scripts/lab/vm.sh copy path/to/binary protox-lab:/tmp/binary
scripts/lab/vm.sh shell sudo python3 /tmp/netlab.py server /tmp/binary server --help
scripts/lab/vm.sh shell sudo python3 /tmp/netlab.py client /tmp/binary client --help

# 参数：Mbps；rtt/jitter/queue-ms 单位毫秒；loss 为每方向独立概率百分数。
scripts/lab/vm.sh shell sudo python3 /tmp/netlab.py profile \
  --up 2 --down 8 --rtt 60 --jitter 5 --loss 1 --queue-ms 100 --seed 42

# 突发损伤，替代独立 loss：Gilbert–Elliott 参数 1%,25%,95%,0.1%。
scripts/lab/vm.sh shell sudo python3 /tmp/netlab.py profile --burst --seed 43

# 在运行期间改变 profile 可模拟容量突降；每次改动必须记到 run 事件。
scripts/lab/vm.sh shell sudo python3 /tmp/netlab.py profile --up 0.6 --down 2 --rtt 80 --seed 44
scripts/lab/vm.sh shell sudo python3 /tmp/netlab.py block-udp
scripts/lab/vm.sh shell sudo python3 /tmp/netlab.py unblock-udp

# 每个运行开始/结束都存一份，差值用于包数、外层字节和丢弃统计。
scripts/lab/vm.sh shell sudo python3 /tmp/netlab.py state > .local/lab/before.json
scripts/lab/vm.sh shell sudo python3 /tmp/netlab.py state > .local/lab/after.json

# 清理会终止实验命名空间内进程，不影响管理 SSH。
scripts/lab/vm.sh shell sudo python3 /tmp/netlab.py cleanup
scripts/lab/vm.sh stop
```

`init` 会拒绝接管非本工具创建的同名命名空间或 nft 表。恢复入口是 `vm.sh start`；若虚机重启但磁盘中保留旧所有权记录，先 `cleanup` 再 `init`。密钥和实例保留，停止不会删除磁盘。

## 模型和计量口径

netem 对每方向加入半个指定 RTT、独立延迟抖动和丢包；每方向独立随机种子。此内核已实测支持 `seed`。即使种子相同，TCP/QUIC发包时序和包数不同，损伤序列也不会与某一业务消息逐个对应。

带宽由 netem `rate` 控制，附加每包 24 字节串行化开销。GSO/GRO/TSO 已关闭，并额外明确关闭 `tx-udp-segmentation` 和 `tx-gso-list`，避免把巨大的分段聚合包当成单个网络包。`queue-ms` 以 1200 字节数据包估算“传播驻留 + 额外排队”的队列包数，**不是字节级 AQM或精确的延迟上界**；`--limit` 可直接指定包数，具体值写入 profile。默认 8/2 Mbps、60 ms RTT、额外100 ms名义排队得到下行109包、上行28包。

`tc qdisc replace` 可能保留累计计数，不能假设改 profile 后归零。每轮必须取 `state` 前后差值。`state` 同时保存接口字节、qdisc 的内核 SKB 字节/包/丢弃、offload状态和命名空间 TCP `nstat` 计数。qdisc 字节不是应用 goodput，也不是包含无线链路全部开销的账单字节；如需逐包解析用该命名空间内 `tcpdump -i pxlinks` 并明确捕获层。

## 已运行的基础核验

`scripts/lab/quickcheck.sh` 使用固定 8/2 Mbps、60 ms RTT、0随机丢包、seed42/43，运行回显、双向短 iperf3 和 UDP 黑洞/恢复。它会改 profile，**只能在协议矩阵未运行时调用**。输出目录含原始 JSON、monotonic UDP RTT样本、ping、每次吞吐前后的tc/nstat快照、失败UDP诊断。

运行 `link-check-20261106T222250Z`：

| 项目 | 实际结果 |
|---|---:|
| UDP回显，30次，先预热3次，单调时钟 | min 62.00 / median 71.86 / max 81.02 ms |
| TCP上行 receiver goodput，约6秒测量窗 | 1.985 Mbps |
| TCP下行 receiver goodput，约6秒测量窗 | 7.515 Mbps |
| UDP故障注入 | 正常可回显；阻断超时；解除后可回显 |
| 阻断UDP期间ICMP | 仍可达 |

这是链路工具核验，**不是协议优劣结果**。短 iperf 窗口的省略预热/末端排队会影响发送与接收窗口边界；应使用长测试和原始字节/时间解释吞吐。iperf报告的测量窗无重传不代表预热阶段或其他流无重传，原始 `nstat` 保留全窗口信息。

虚拟机调度噪声明显：名义60 ms实际通常约62–81 ms。`ping`还曾给出不可能的0 ms样本，原始数据未删除；原因可能涉及 guest realtime时钟调整或iputils计时，而非链路真正零延迟。所有协议时延/停顿必须使用单调时钟，例如Go `time.Since` 保留单调部分；不要用两端墙上时钟相减。先预热ARP与进程，按随机或轮转协议顺序重复，并保留分布、超时及失败。不得将本机虚拟化实验推广为整个俄罗斯网络的表现。

## 协议比较矩阵

`scripts/lab/run-matrix.sh RUN_ID [选项]` 使用已构建的 `bin/{protox,pxbench}-linux-arm64` 及下载并校验的三份基线程序，生成私密配置并复制至虚机。固定的三方实现版本、SHA256、Go build info、参数、随机执行顺序和资源口径写入运行manifest。源码变更后须明确重建并冻结二进制；同一批次中不会更新运行中的程序。

跨多个批次比较同一实现时，把两个 Linux 二进制复制至独立目录，以 `PROTOX_LAB_BIN_DIR=.local/matrix/frozen-v01/bin` 指定读取来源；每次核对 manifest 中的 SHA256。开发者可以同时更新普通 `bin/`，不改变已冻结的实验版本。包装脚本启动时也冻结自身文本，避免运行中编辑文件改变 shell 的后续读取偏移。

```sh
# 明确先做发现集，读完结果才决定确认集；两次都保留完整数据。
scripts/lab/run-matrix.sh discovery-UNIQUE --stage discovery --seed 101
scripts/lab/run-matrix.sh confirmation-UNIQUE --stage confirmation --seed 307

# 只检查互通；参数样本过小，不据此给稳定p99结论。
scripts/lab/run-matrix.sh smoke-UNIQUE --stage smoke --seed 17 \
  --duration 6 --warmup 1 --profiles healthy \
  --variants px-priority px-fifo xray-vision hy-bbr-standard

# 单独测通用源站限速的影响，对所有协议同样设定。
scripts/lab/run-matrix.sh paced-UNIQUE --stage discovery --seed 101 \
  --background-mbps 6
```

默认每轮25秒另加3秒预热、HTTP POST每秒5个、持久echo最小间隔100ms、SSE源端50ms、一个不限速后台下载、交互超时3秒。源站为验证自有CA的HTTPS1.1，所有代理及fixture/workload进程 `GOMAXPROCS=1`。预热调用与正式业务连接分开，但代理进程及可复用外层会话继续存在。每轮新建代理、源站进程，末尾清理；仅两个实验namespace受损伤，管理不受影响。

变体为 PX priority / FIFO / adaptive、Xray REALITY+Vision、Hy BBR standard / conservative、Brutal8/2和Brutal6/1.5。链路先采用healthy和每方向1%随机丢包+5ms抖动，均名义RTT60ms、8/2Mbps；按seed打乱协议/场景顺序。PX在共同物理链路上另有自己的应用帧pacer；因此必须通过相同源端限速、调度消融和不同吞吐点继续归因，不能把所有差异直接归功于新协议机制。

冻结的 PX v0.1 使用 **quic-go v0.65.0 的默认 Reno**。虽然内部构造函数名为 `NewCubicSender`，[`sent_packet_handler.go:155–163`](https://github.com/quic-go/quic-go/blob/v0.65.0/internal/ackhandler/sent_packet_handler.go#L155-L163) 实际传入 `true // use Reno`，由 [`cubic_sender.go`](https://github.com/quic-go/quic-go/blob/v0.65.0/internal/congestion/cubic_sender.go) 选择 Reno 分支；不能只凭函数名把本轮标成 CUBIC。新拥塞算法须单独编译、记录 SHA 并作为新变体比较，不能追溯修改旧结果的实现身份。

每项数据包含所有HTTP/echo/SSE事件、失败和结束截尾、warmup原始数据、外链tc前后快照和差值、namespace全部TCP nstat、100ms进程CPU/RSS样本。`nstat`包含环回源站/SOCKS TCP，**不能当作QUIC重传率**。源端限速是每下载worker的应用字节预算，不是加密代理的总外层字节上限。

完成的v0.1共同限速/多下载调度消融见 `results/mechanism-ab-v01-20261106/ANALYSIS.md`。`tools/lab/summarize.py` 重新核对原始事件数量、状态、HTTP/echo分位数及SSE间隙分位数，生成不合并种子的CSV/JSON；原始失败运行不会被剔除。

## 独立拥塞控制筛选

`scripts/lab/run-cc-matrix.sh` 在 `/tmp/pxlab-cc` 使用单独的程序、配置与结果目录，但仍共享两个实验命名空间，**不可与其他矩阵同时运行**。它核对冻结v0.1、冻结CC分支、benchmark与Hysteria的SHA，再复用已核验的自有TLS配置。须先通过普通矩阵建立 `.local/matrix/stage/private`，并准备 `.local/matrix/frozen-v01/bin`、`.local/cc-matrix/frozen/protox-cc-linux-arm64`；具体冻结SHA写在脚本与manifest中。

```sh
scripts/lab/run-cc-matrix.sh cc-training-211-UNIQUE --seed 211
scripts/lab/run-cc-matrix.sh cc-training-223-UNIQUE --seed 223
```

候选为稳定PX priority、旧fork Reno、旧fork Hy BBR standard、旧fork Hy Brutal6/1.5、正式Hysteria Brutal6/1.5。默认每项25秒加3秒预热，一个不限速后台下载，1%丢包/5ms抖动，物理8/2Mbps。211/223只作为训练/发现数据；脚本明确拒绝预留307，不自动进入确认阶段。

实验分支使用Hysteria 2.13.0固定提交的拥塞控制实现及其固定的 `apernet/quic-go`；CC逻辑没有作为PROTO-X原创机制报告。分支还显式使用QUIC v1，因此稳定版与fork间的收益不能只归因于CC；同一个fork的Reno/BBR/Brutal才是CC消融。JSON保持相同PX优先调度参数，通过进程环境选择算法，在认证后安装。每次采集并检查两端实际安装日志、Brutal速率及QUIC连接日志，错误或回退会标记验证失败；记录脱敏完整配置、原配置SHA及源码来源。

此轮没有注入路径迁移。已知旧fork在迁移时可能把拥塞控制重置为Reno，不能把静态路径筛选结果当作迁移正确性证明。CC选择结果与恢复、会话调度和其他冗余机制保持分开记录。

两种子完整CC筛选见 `results/cc-screening-20261106/ANALYSIS.md`。追加的单种子信用窗口诊断见 `results/cc-window-diagnostic-20261106/ANALYSIS.md`：通过 `PROTOX_LAB_CC_WINDOW_BYTES` 取值65536、131072或262144 在单独的CC staging配置中改变窗口，普通矩阵输入与部署默认不变。

## 稀疏副本消融

`scripts/lab/run-hint-matrix.sh` 使用 `.local/hint-matrix/frozen/protox-hints-linux-arm64` 中的同一个冻结程序，生成双方明确打开/关闭 `sparse_redundancy` 的两组配置，再与正式Hy Brutal6对比。窗口64KiB、priority=true、adaptive=false、应用pacer8/2Mbps及默认Reno均相同；只改布尔开关。程序、私密配置和原始数据存于独立 `/tmp/pxlab-hints`，仍共享实验namespace，不能与其他实验同时跑。

```sh
scripts/lab/run-hint-matrix.sh hints-unpaced-311-UNIQUE --seed 311
scripts/lab/run-hint-matrix.sh hints-unpaced-313-UNIQUE --seed 313
scripts/lab/run-hint-matrix.sh hints-paced-311-UNIQUE --seed 311 --background-mbps 2.5
scripts/lab/run-hint-matrix.sh hints-paced-313-UNIQUE --seed 313 --background-mbps 2.5

# 观察训练数据后预先声明的更高丢包场景；仍属于探索集。
scripts/lab/run-hint-matrix.sh hints-loss5-paced1-317-UNIQUE --seed 317 \
  --profiles loss5-jitter5 --background-mbps 1

# 仅在筛选完成并书面释放留出集后使用；参数由运行器锁定。
scripts/lab/run-hint-matrix.sh hints-confirm-loss5-paced1-307-UNIQUE \
  --stage confirmation --seed 307 --duration 90 --warmup 3 --queue-ms 100 \
  --profiles loss5-jitter5 --background 1 --background-mbps 1 \
  --variants px-hints-off px-hints-on hy-brutal6
```

311/313和追加317为训练种子，完整15项筛选见 `results/hint-screening-20261106/ANALYSIS.md`。筛选结束后，307按 `results/hint-confirmation-s307-20261107/PREDECLARED.json` 的书面方案释放，独立测量每项90秒而非筛选的25秒，三项已完成；结果和完整代价见 `results/hint-confirmation-s307-20261107/ANALYSIS.md`。不允许根据确认结果补调、更换seed或只保留有利指标。运行器默认仍为discovery，只有显式confirmation且全部参数匹配才接受307；它不防止使用另一个run-id重跑，研究者仍须遵守预声明停止规则。

运行器保存退出时的每一条 `sparse redundancy counters` 日志；多个记录不直接相加，日志缺失记为缺失。冻结实验程序的客户端退出存在listener先关闭、主循环可能先返回的竞态，筛选集中on组客户端计数全部缺失；off组正常不输出计数。计数覆盖包含预热在内的会话生命周期，与测量窗的tc字节不同。`sent_datagrams` 仅说明成功交给QUIC队列，`first_delivered_bytes` 仅说明副本先交付，均不自动证明真实丢包恢复；QUIC对datagram的打包或调度也可能产生收益。分析必须同时看成功/失败、有效吞吐与外层字节，而不只看“副本先到”的计数。

`tools/lab/verify_hints.py results/AGGREGATE` 在 `summarize.py` 汇总后复核二进制/源码和配置SHA、双方只差开关、原始qdisc前后差值、实际损伤参数及QUIC承载，并对当前实验凭据/私钥做精确扫描，只报告命中路径和数量。它不把缺失计数补成零，也不检验真实网络抗识别。
