# PROTO-X v0.2 Web 承载

更新：2026-11-07。实现为 `internal/carrier/web*.go`、`internal/cover/` 与 `internal/app/web.go`。本页描述已实现机制；检测效果见[实验证据与限制](recognition-v02.md)。

## HTTP 映射与时序

H2 使用一条真实 TLS/TCP HTTP/2 连接，H3 使用一条真实 QUIC HTTP/3 连接。TCP 同一入口也接受普通 HTTP/1.1，包括未提供 ALPN 的正常 TLS 访客。仅在完成 TLS 1.3 后认证，不使用 0-RTT。

每个 Link 包含一个控制 POST 和每个应用 Flow 的独立双向 POST，由 HTTP 库执行标准 HEADERS / DATA 和 QPACK / HPACK 编码。客户端 URI 为配置路径（默认 `/api/sync`），query 包含随机 128 位 hex `carrier` 与十进制 `stream`；控制 ID=0，其余是 Session 的递增奇数 ID。认证后响应为 200、`application/octet-stream`，请求与响应 body 分别携带两个方向的记录。

客户端把 HELLO / OPEN 随 POST body 发送，不为首记录额外等待 200。TLS 已完成且认证头已生成，这不是早期数据。服务端只在控制流 HELLO/WELCOME 完成后受理数据流，且要求相同 TLS exporter 绑定；不能从另一条 TLS 连接挪用 carrier ID。新 Link 可以重新认证并恢复同一 Session。

## 认证和普通网站

流程为 TLS → HTTP 认证 → HELLO/WELCOME → Session。HTTP 认证使用共享 256 位 token、HMAC-SHA256、Unix 时间和 128 位 nonce，绑定 method、authority、完整 RequestURI 与此连接的 TLS exporter。默认时窗 ±30 秒；有界 nonce 缓存满时拒绝新认证，不逐出仍有效 nonce。详见 [cover-auth.md](cover-auth.md)。

未认证、错误认证、重放与无效 carrier/stream 请求进入同一 `cover.Site`，由真实静态文件 handler 决定 200/404/405、HEAD、Range 等行为。通过 HTTP Gate 但 HELLO 错误的请求会结束通道，没有 Session 或目标连接。凭据持有者属于同一信任主体；没有多租户隔离或分用户撤销。

静态根目录由 `os.Root` 限定，必须只含公开内容。共用默认网页本身可能成为站点指纹，应换成实际自有内容。新认证要求 PROTO-X 直接终止客户端 TLS，**不能直接放在终止 TLS 的 CDN/nginx 后**；透明 TCP 转发可以保留 exporter，终止再加密则会改变它。

## body 封套与成本

每条 body 记录按大端序编码：

```text
uint16 inner_length | uint16 padding_length | wire.Frame | random_padding
```

`wire.Frame` 沿用[会话协议](PROTOCOL.md)的 32 字节头和最多 4096 字节 payload。解码先检查长度，内层尾部剩余字节会拒绝。允许 padding≤255；发送上限 `web_padding` 只可为 0、63、127、255，v0.3 新配置默认 0（v0.2 为 127），在选定区间内均匀随机。不等待凑包，不发独立填充流量，不改变可靠字节语义。

选择 padding127 时每记录平均额外 67.5 字节。对 2048 字节 DATA，约为原有 2080 字节记录的 3.25%；对短 ACK、心跳比例更高。TLS/HTTP 打包会影响可见包长；这并不产生浏览器分布保证。

发送预算预扣 `inner_length + 4 + max_padding + 64`；最后 64 字节沿用旧调度估算。实际 padding 常较小，因此预算偏保守。控制心跳、HTTP 头、握手、加密和重传还另有成本，不是精确整链路字节上限。Link 分别计数封套/填充和内层记录；外部工具统计实际 TLS 字节或 UDP payload。

## TLS 身份与 ECH

Web 客户端默认验证 CA 链、有效期与 `server_name`。`ca_file` 为空时用系统根，非空时用显式 PEM 根；`pin_sha256` 可额外约束叶证书，换证书需同步更新或移除该可选 pin。

`init` 生成开发自签并显式设置 `experimental_pin_only:true`。也可在受控测试中提供私有 CA、关闭 pin-only。两者都不提供普通公网访客认可的 HTTPS 身份。公网部署需实际自有域名、有效完整证书链和私钥、公开站点内容；客户端设置 `experimental_pin_only:false`，公网 CA 可省略 `ca_file`。不要保留开发证书的旧 pin。

示例客户端（域名均为占位符，其余参数用默认值）：

```json
{
  "socks_listen": "127.0.0.1:1088",
  "token_file": "token",
  "experimental_pin_only": false,
  "web_padding": 127,
  "endpoints": [
    {"network": "h3", "address": "test-endpoint.example:443", "server_name": "notes.example"},
    {"network": "h2", "address": "test-endpoint.example:443", "server_name": "notes.example"}
  ]
}
```

实际 TCP/UDP 映射必须可达；NAT 非标准端口并不自动支持 ACME 验证。项目不会凭空取得域名或公网证书。

ECH 使用标准 Go TLS 和 RFC 9849 格式，HPKE 来自标准库：

```sh
bin/protox ech-keygen -dir .local/ech -public-name cover.example
```

服务端配置 `ech_keys_file: "ech-keys.json"`，客户端配置 `ech_config_file: "ech-config.bin"`。只有 `.bin` 是公开配置，JSON 含私钥。证书应正确服务 outer public name 与 inner server name。生成命令不设置 DNS、不签发证书，也不改已有配置。

配置 ECH 的客户端要求 ECHAccepted；错误/空配置、拒绝或错误证书均失败。不会静默重试不带 ECH 的连接，也拒绝混入旧原生 QUIC/TLS fallback。错误角色的 ECH 字段在启动时拒绝。普通无 ECH 网站访客仍可连接服务端。

目前没有自动查询 HTTPS DNS 记录、ECH 轮换调度或旧配置迁移工具。配置需独立安全分发；轮换需保留仍在使用的旧 key。ECH 隐藏内层 ClientHello，不隐藏 IP、外层域名、使用 ECH 的事实或访问行为。

本轮测试证书同时覆盖 inner / outer 名称。普通无 ECH 访客可以取得该证书并枚举 SAN，因此被动观察中的内层 SNI 隐藏不等于主动探测也无法获知内层名称。当前应用只加载一套叶证书，没有按 ECH 状态隔离证书或站点身份，也没有验证足够大的匿名集。

## 恢复、资源和实现边界

ACK、偏移、FIN、目标 socket 与有界缓存仍保存在两端进程内。H3↔H2 替换只改变载体，不重新拨目标；进程死亡、TTL 到期或目标关闭仍会结束旧连接。H2 有 TCP 跨流队头阻塞，H3 仍共享拥塞控制和线路。

每个 Web Link 最多 129 个槽，协议并发流上限另为 128。H2 每连接接收窗口 512 KiB、每流 128 KiB，读帧上限 16 KiB；H3 继承有限 QUIC 窗口。每个 TCP/QUIC 入口最多 16 个应用可见连接，HTTP header 上限 16 KiB，Session 和 Flow 还有原上限。这不是总 RSS 或连接洪泛保证。

Go 1.27 H2 使用标准库单连接 Transport 与一次性 TLS dialer，避开本轮复现的 x/net 兼容 wrapper 锁重入；Go 1.26 用 x/net 旧实现。HTTP handler 返回前终止并等待其 I/O，防止访问失效 ResponseWriter。已确认流正常结束，故障才中止，避免普通回收导致整条载体重连。

整包部署处理证书、站点、ECH 与配置的一致性，激活失败恢复旧整包。命令和已验证边界见 [deployment-web.md](deployment-web.md)。


## v0.3 恢复扩展

`adaptive` 客户端在已认证 HELLO 中发送非零单调 `attempt`，包括首次激活及失败后的重试；TLS/ECH 准备阶段不发送 HELLO。WELCOME 必须精确回显。服务端发布新承载时原子检查 attempt 严格递增；已有 fenced 会话拒绝重复、更小或零 attempt。legacy HELLO/WELCOME 保持兼容，但启用 adaptive 的客户端不静默接受不支持该扩展的服务器。

只读准备连接可以取消而不替换会话；激活后的 WELCOME 丢失仍会留下两端状态不确定窗口，更高 attempt 用于继续恢复。ACK 合并不改记录格式、窗口上界或去重语义。详细状态机、实验配置与限界见 [v0.3 研究报告](research-v03.md)。
