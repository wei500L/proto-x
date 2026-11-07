# HTTP carrier observation tools

这些工具独立观察 PROTO-X 的 HTTP 承载和同栈普通站点。它们能核对声明的握手特征与未认证请求回落；没有训练分类器，也不把某条旧识别规则消失解释成“不可识别”。

## 已实现的测量

- `relay.py` 转发并记录实际 TCP 字节与 UDP 数据报。TCP 记录保留字节顺序，**不是主机 pcap**，不保留 TCP 分段、重传、IP 包或网卡时间戳。UDP 记录保留完整数据报。它本身会改变拓扑和时序。
- `analyze.py` 从 TLS record 重组 ClientHello；对 QUIC v1/v2 Initial 按公开 Initial 密钥移除头保护、验证 AES-GCM 并重组 CRYPTO。AEAD 失败、缺少片段与截断均保留。后续加密数据与 ECH 内层没有解密。
- `recognition probe` 用真实 H2/H3 客户端发出指定请求；ALPN 协商结果来自主动客户端的 TLS 状态，与字节观察所得的 **offered ALPN** 分开记录。
- `recognition ordinary` 直接使用 `cover.Site`，不经过 `Gate` 或 `WebHub`。证书、站点文件、Go/QUIC 栈及服务端窗口/监听限制可与候选保持一致。这个对照隔离认证入口的作用，不能代表所有普通网站。
- `recognition visitors` 用标准 `crypto/tls` 与 `net/http` 序列化/解析 HTTP/1.1，分别省略 ALPN 和显式提供 `http/1.1`，各运行 GET、HEAD、无认证 POST 与错误认证 POST。省略 ALPN 的客户端不经过可能自行注入 ALPN 的 HTTP Transport。
- `openssl_visitors.py` 使用已安装的 OpenSSL `s_client`，独立进行 CA/名称校验并请求根路径 GET/HEAD。原始 OpenSSL 输出含证书身份，只写私有目录。它与 Go 探针不同，不额外应用 leaf pin。
- `compare.py` 按 case/repeat 比较状态码、协议、选定响应头、响应体散列和脱敏错误类型。时间样本保留但不参与“响应匹配”。缺失样本、失败、超时、重复索引都不能静默丢弃。

可见 SNI 只输出 `configured_cover_name`、`configured_legacy_name` 或 `other_present_name`。ClientHello 的 ECH 扩展存在性单独列出，**不代表 ECH 被接受**。QUIC CID、token、地址值不导出。

## 构建与工具校验

在仓库根目录运行；需要仓库 Go 版本、Python 3.9+ 及 `cryptography`。

```sh
mkdir -p .local/recognition/bin
GOFLAGS=-mod=readonly go build -o .local/recognition/bin/recognition ./tools/recognition
python3 -m unittest discover -s tools/recognition -p 'test_*.py' -v
python3 tools/recognition/local_smoke.py \
  --binary .local/recognition/bin/recognition \
  --private .local/recognition/NEW-SMOKE-RUN \
  --out results/recognition-NEW-SMOKE-RUN
```

`local_smoke.py` 生成私有本地 CA 与随机保留域名证书，只通过显式 CA 文件信任它，不修改系统信任库。证书有效期 7 天。程序启动普通站点、relay 和主动探针，退出时回收自己启动的进程，并保留私有二进制及命令。它不启动候选代理，因此成功只说明测量夹具可用。

`testdata/` 是 RFC 9001 附录 A.2 和 RFC 9369 附录 A.2 的公开测试向量，不是现场抓包。`SOURCES.json` 保存来源与数据散列。测试覆盖 v1/v2 已知密钥、AEAD 损坏、截断、TLS record 分片、CRYPTO 乱序/重复/冲突及比较器的失败分母。

## 候选与普通站点比较

候选服务必须已经由负责人启动。将实际值放入忽略目录中的私有配置；下面只描述键：

```json
{
  "candidate_tcp": "LOOPBACK_IP:OWNED_H2_PORT",
  "candidate_udp": "LOOPBACK_IP:OWNED_H3_PORT",
  "server_name": "OWNED_CERTIFICATE_NAME",
  "ca_file": ".local/PRIVATE_CA.pem",
  "pin_sha256": "OPTIONAL_ADDITIONAL_CERTIFICATE_PIN",
  "cert_file": ".local/PRIVATE_SERVER_CERT.pem",
  "key_file": ".local/PRIVATE_SERVER_KEY.pem",
  "site_root": ".local/PUBLIC_SITE_FILES",
  "protocol_path": "/api/sync?carrier=recognition&stream=1",
  "reference_profile": "candidate_options",
  "repeats": 3
}
```

可以只提供一种承载；额外 pin 可省略，但常规 CA/主机名校验始终启用。`site_root` 必须仅含可公开内容。为了限制这个自动夹具的作用域，`pair_check.py` 只接受回环候选地址，不管理候选进程。

`reference_profile` 可选 `candidate_options`（匹配候选 TLS 辅助函数和 HTTP 窗口）或 `stock_go`。后者直接使用标准 `crypto/tls`、`net/http` 默认 HTTP/2 配置及 quic-go 默认 QUIC 配置，不调用候选 TLS 验证函数；仍保留本实验的 TLS 1.3 下限、超时和监听限制，不是所有参数都默认。这是额外的标准库参照，仍是 Go 实现，不能代表 Chrome、nginx、OpenSSL 等全部实现。使用不同 run-id 分别运行两种参照。

```sh
python3 tools/recognition/pair_check.py \
  --binary .local/recognition/bin/recognition \
  --config .local/PRIVATE-PAIR-CONFIG.json \
  --private .local/recognition/NEW-PAIR-RUN \
  --out results/recognition-NEW-PAIR-RUN
```

每轮、每种承载有 13 个 case：根路径 GET/HEAD，协议路径 GET/HEAD，协议路径 POST 无认证/错误认证/格式错误认证，协议路径 PUT，未知路径 GET/POST，根路径 OPTIONS，以及旧自定义 ALPN、标准 ALPN 下的旧裸记录。错误认证使用当前 57 字节 envelope、版本、时间和随机 nonce，加上故意错误的全零 MAC。它不测试合法 MAC、过期合法认证或合法认证重放。

若提供 TCP 候选，`pair_check.py` 另运行并比较每轮 8 个 HTTP/1.1 visitor case，报告在 `*-visitors.json`。这些连接也进入主动探针抓取；没有 ALPN 扩展必须由实际 ClientHello 再核对。

默认还运行每轮 4 个 OpenSSL 访客 case（无 ALPN/显式 `http/1.1` × GET/HEAD），报告在 `*-openssl.json`。需要已安装的 OpenSSL；私有配置可用 `"openssl_visitors": false` 显式跳过。`normalized_match` 可能是两边都失败，必须同时检查 `candidate_status_counts` / `reference_status_counts`，不能把匹配数当成成功率。

旧裸记录是 32 字节空 HELLO；它是故意无效的旧入口探针，不是有效的旧代理会话。**主动探针抓取中必然包含有意提供旧 ALPN 的连接，不得把它算作新原生客户端的指纹。**

完整配置、实际域名、pin、私钥、命令、原始观察和详细错误只放在 `.local/`。公开 `results/recognition-*` 保存脱敏响应与握手特征。HTTP 头中 Date 被忽略，未列入通用白名单的值被隐藏；这里的响应匹配只覆盖报告声明的字段。

## 单独捕获原生客户端

```sh
python3 tools/recognition/relay.py \
  --out .local/recognition/NEW-NATIVE-CAPTURE \
  --label candidate-native \
  --tcp-target LOOPBACK_IP:OWNED_H2_PORT \
  --udp-target LOOPBACK_IP:OWNED_H3_PORT
```

监听地址和 PID 写入私有 `ready.json`。让真实客户端的连接地址指向这个 relay，保留它原来的证书主机名和信任策略；用实际代理业务确认成功。对 **该 relay 进程** 发送 SIGTERM 后再分析，以便统计尾部和截断状态完整：

```sh
python3 tools/recognition/analyze.py \
  --capture .local/recognition/NEW-NATIVE-CAPTURE/capture.jsonl \
  --label candidate-native \
  --names-private .local/PRIVATE-NAME-CATEGORIES.json \
  --out results/recognition-NEW-RUN/native-clienthello.json
```

名字配置格式是 `{"cover_names": ["PRIVATE_NAME"], "legacy_names": []}`。直接 `probe`、`ordinary` 命令需要的 JSON 键可查 `main.go`；错误消息可能包含名称，所以工具将详细错误写入私有配置旁边的 0600 sidecar，终端只输出错误类型。

`relay.py --capture-bytes 0 --capture-packets 0` 可只转发和累计每方向完整字节/数据块数；正常 SIGTERM 后写出计数。此时内容没有留存，`capture_truncated` 会如实标记，不能用于声称完成了握手内容分析。

## 原生 H2/H3 与 ECH 开关夹具

```sh
python3 tools/recognition/native_check.py \
  --binary .local/PROTOX-CANDIDATE-BINARY \
  --measurement-binary .local/recognition/bin/recognition \
  --server-config .local/PRIVATE-REFERENCE-SERVER.json \
  --client-config .local/PRIVATE-REFERENCE-CLIENT.json \
  --private .local/recognition/NEW-NATIVE-RUN \
  --out results/recognition-NEW-NATIVE-RUN
```

参考配置只读。工具生成独立 CA、分别用于内层/外层的随机保留域名、同时覆盖两者的证书、认证 token 和 ECH 密钥，在独立回环端口启动自己的代理服务和客户端；退出时回收这些进程。每个客户端只启用一个承载，强制 CA/名称验证并加上 pin，不使用实验 pin-only 模式。本地生成 CA 的验证不解决公网证书身份。

四种组合为 H2/H3 × ECH 开/关，每组经 SOCKS5 访问受控目标：3 个 32 KiB 响应和 16 个按 20 ms 间隔生成的 SSE 事件。保存源端产生时间、客户端到达时间、响应散列、失败及分母；这只是短功能检查。独立服务器允许 8 个驻留会话，避免四个顺序客户端的恢复保留期挤满会话配额。

原生抓取与主动探针分开。ECH 名字映射用私有 `inner_names` / `outer_names`，公开只输出 `configured_inner_name` / `configured_outer_name`。原生配置的 ECH 由候选客户端强制接受；另外 `recognition tlscheck` 在**单独直连**中记录真实 TLS `ECHAccepted`、ALPN 和证书链验证结果。这个状态诊断不冒充原生客户端回调，也不会混入原生 relay 抓取。

## 解释限制

- 普通 HTTP 回落相同、未见旧自定义 ALPN，只是对应探针/规则的结果。TLS/QUIC 实现、握手结构、包长、HTTP 用法和流量节奏仍可提供识别线索。
- 这里没有多站点/多应用 cover 语料、会话/主机隔离的训练测试集、TPR/FPR、真实 DPI 或俄罗斯现场可达性证据。
- 原生认证代理互通、流恢复、有效 ECH 接受，以及新承载的弱网性能都须分别测试。
- 本机时间是校验和诊断样本，不能推导隐蔽性或公网时延。首次 smoke 中的异常和后续修复记录均保留，不能选择性丢弃。
- TCP 捕获前缀和 UDP 包数均有界。QUIC 分析遇到未处理的 coalesced 包型会停止解析该数据报剩余部分；未解码计数保留，不能当作无指纹。

结果索引：`results/recognition-smoke-20261107-01` 保留首轮失败；`-02` 是显式 UDP bind 后的校验；`-03` 增加回流/端口隔离检查并执行四轮。各轮只对实际完成的范围作结论。

当前完整实验索引和失败历史见 `results/recognition-http-v02-20261107/ANALYSIS.md`；最新原生功能与 ECH 记录在 `results/recognition-native-final2-full-20261107/`。公开文件在交付前使用 `redaction_check.py` 按私有值索引扫描；该工具只报告类别、计数和脱敏路径，不输出私有值。
