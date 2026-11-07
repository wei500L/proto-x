# HTTP 承载认证与普通站点

更新：2026-11-07。实现位于 `internal/cover/`，只负责认证与普通文件站点；HTTP/2、HTTP/3、流调度、会话恢复由承载层和会话层实现。

## 集成约定

`NewGate(token, Config)` 接收已解码的 32 字节随机共享密钥，并复制密钥。已有 64 字符十六进制 token 应先由调用方解码。`Config.Path` 必须显式配置，例如 `/api/sync`；不能是根路径、相对路径、非规范路径或包含百分号转义的路径。最长 1024 字节，且必须可以原样表示为 ASCII URL 路径。

客户端为每个 HTTP POST 调用一次 `SignRequest(req, &state)`。先完成 TLS 1.3 握手并选定实际发送请求的单个 HTTP/2 或 HTTP/3 ClientConn，再取得该连接的 TLS state。该方法显式使用 `state`，不依赖通常为空的客户端 `req.TLS`。普通自动连接池不能先任选一条连接签名，再把请求发送到另一条连接。

```go
// token 已由调用方解码；state 来自即将使用的 ClientConn 的 TLS 连接。
gate, err := cover.NewGate(token, cover.Config{Path: "/api/sync"})
if err != nil {
    return err
}
req, err := http.NewRequest(http.MethodPost,
    "https://public.example/api/sync?carrier=0123456789abcdef0123456789abcdef&stream=1", body)
if err != nil {
    return err
}
if err := gate.SignRequest(req, &state); err != nil {
    return err
}
// 随后在刚才选定的 ClientConn 上发送 req。
```

签名完成后不得更改方法、Host 或完整 URL。authority 必须是已经编码的 ASCII / punycode，并保留端口及大小写原样；签名不替 HTTP 客户端进行域名转换。发生重试或换连接时重新建立请求并签名。重签只是授权一个新 HTTP 请求，已有代理字节的确认、去重和恢复仍归会话层负责。

服务端在任何代理会话或流分配之前调用 `Authorize`。任一否定结果都交给同一个普通站点，包括没有认证、错误认证、错误路径、重复 nonce、时间过期和缓存已满。

```go
handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    if !gate.Authorize(r) {
        site.ServeHTTP(w, r)
        return
    }
    tunnel.ServeHTTP(w, r)
})
```

`Authorize` 不读取请求体、不写响应、不记录日志，也不分配代理会话。它只验证 `POST` 与配置路径，以及下面列出的签名字段；`carrier`、`stream` 参数的语法、存在性和所有权由承载层继续检查。控制流 `stream=0` 也必须单独签名。

每个 Gate 的寿命必须覆盖它服务的 TLS 连接。不能保持 TLS 连接而重新创建空的 Gate，否则该连接上仍在时间窗口内的旧认证头可能再次被接收。停止旧连接后才能替换整套 Gate。认证值、密钥和完整已认证请求头不得进入访问日志、错误日志或公开实验数据。

客户端与 Gate 必须看到同一个 TLS 连接。若 CDN 或 nginx 在前方终止 TLS，后端 `req.TLS` 的 exporter 不再匹配客户端；当前实现不能直接放在这种 TLS 终止代理后面。四层透传不改变这个绑定。不要把客户端自报的 exporter 放进 HTTP 头来代替真实连接状态。

## 认证格式

请求头只有一个 `Authorization` 值，严格形式为：

```text
Authorization: Bearer <raw-base64url(payload)>
```

payload 为 57 字节，编码后 76 个字符，无 `=` 填充；连同 `Bearer ` 的头值总长 83 字节。

| payload 字节位置 | 长度 | 内容 |
|---|---:|---|
| 0 | 1 | 版本 `0x01` |
| 1–8 | 8 | Unix 秒，unsigned 64-bit big-endian |
| 9–24 | 16 | 每次请求由 `crypto/rand` 产生的新 nonce |
| 25–56 | 32 | HMAC-SHA256 |

只接受已完成的 TLS 1.3 连接。exporter 使用 Go `ConnectionState.ExportKeyingMaterial`，label 为 `EXPORTER-PROTO-X-HTTP-AUTH-v1`，context 为 nil，输出 32 字节。不使用 early exporter，也不在握手完成前签名。

MAC 输入按以下顺序拼接，所有长度均以字节计：

```text
ASCII("PROTO-X HTTP authentication v1") || 0x00
|| payload[0:25]
|| exporter[0:32]
|| u32be(len(method))    || method
|| u32be(len(authority)) || authority
|| u32be(len(uri))       || uri
```

`method` 是原样 `POST`。`authority` 优先取 `req.Host`，为空时取 `req.URL.Host`；最长 512 字节。`uri` 是 `req.URL.RequestURI()`，包括完整且未经排序的 query，最长 4096 字节；服务端非空的 `req.RequestURI` 必须与它逐字节相等。query 参数顺序和 `%31` / `1` 等不同拼写都产生不同的 MAC。长度前缀避免字段拼接歧义。

请求体未包含在这个头部 MAC 中：流式请求的完整请求体在发头时还不可用。后续请求体由同一条 TLS 连接保护，应用帧仍须通过承载层的边界和状态机校验。认证不赋予新应用操作“恰好一次”的语义。

## 有界防重放与时钟

默认窗口为包含端点的正负 30 秒，可设置为 1–300 的整数秒。已认证时间戳超出窗口时拒绝。客户端时间戳必须非负，且加上窗口后不能溢出有符号 64 位范围。

Gate 的 map 加最小堆保存已成功接收的 nonce。默认最多 4096 个，可配置为 1–65536。只有方法、路径、头部格式、TLS exporter、MAC 和时间窗口均通过后才写入缓存；未认证输入不占用 nonce 容量。每个 nonce 的截止时间为签名时间加窗口，仅当截止时间严格小于当前有效时间时删除。并发重复请求只允许一个写入。

容量耗尽时拒绝新的认证，不淘汰仍有效的旧项。这样保留防重放语义，但高连接创建率下会暂时无法建立新 HTTP 流，已有流不受该缓存判断影响。一个将来时间戳可能使缓存占用接近两倍窗口的时长；容量应按整个 Gate 上所有连接的新 HTTP 请求总量选择，不能只按外层连接数量估算。

Gate 维护不会倒退的有效秒数：在通过 MAC 校验后，采用本地墙钟与已见最大秒数的较大值。此策略防止墙钟回拨后，已过期并移除的 nonce 重新变得有效。代价是较大的时钟修正可能暂时拒绝新认证；普通站点和已经接收的 HTTP 流不因此关闭。

URL 的原始路径、query 和 RequestURI 先做长度检查，再生成签名输入，避免超长字段在 Gate 中造成无界临时分配。缓存和这一层的单次认证输入有界，不等于整个 HTTP/TLS 服务器没有资源开销；握手、头部大小、连接数、并发流数和超时仍需由承载层限制。

## 普通站点与识别边界

`NewSite(root)` 使用 `os.OpenRoot` 和 `http.FileServerFS`。GET / HEAD 保留正常文件服务的目录跳转、index、Content-Type、Last-Modified、Range、条件请求和错误行为。其他方法返回普通 `405 Method Not Allowed`，带 `Allow: GET, HEAD`。没有专用认证 challenge、诊断正文或 session cookie。回落服务与普通对照服务器必须使用同一 Site 或相同文件树、相同设置。

在目标 Linux / macOS 平台上，os.Root 限制路径和符号链接解析在公开根目录内；相对链接仍可指向根目录内的文件。该目录只能放公开文件。os.Root 不防止管理员把敏感内容、设备节点、`/proc` 或外部 bind mount 放进公开目录，也不会隐藏目录内已有的文件名。HTTP 服务完全停止后再调用 `Site.Close()`。

固定路径和 Bearer 值都位于加密后的 HTTP 请求内。随机路径本身不是抗 DPI 证据。普通站点回落也不能消除证书、Go TLS / QUIC / HTTP 参数特征，或长连接的流量长度与时序特征。响应内容相同不代表处理时间或资源消耗相同，更不代表对任意主动探测器不可区分。本组件不声明已通过俄罗斯运营商环境的抗识别验证。

## 已执行验证

2026-11-07，本地 macOS arm64，Go 1.27.1；证据见 `results/cover-auth-20261107/`。没有把这些组件测试计为 VPS、俄罗斯真实网络或 H2/H3 端到端通过。

```sh
go test ./internal/cover
go test -race -count=10 ./internal/cover
go test ./internal/cover -run '^$' -fuzz '^FuzzGateAuthorizationHeader$' -fuzztime=5s -parallel=2
go vet ./internal/cover
```

已通过真实 TLS 1.3 握手得到的客户端/服务端 exporter 匹配、跨连接重放拒绝、密钥复制与隔离、64 并发重复请求只接收一次、完整 query / authority / 时间戳 / nonce / MAC 篡改、错误头部不读取 body 和不分配 nonce 状态、时钟边界、缓存容量、过期清理与回拨、时间戳溢出、静态文件标准行为和路径/链接逃逸测试。

回落等价测试比较普通 Site 与带 Gate 的 handler 在无认证、错误认证、重放、不同 TLS 连接、错误路径、GET / HEAD / Range / OPTIONS 下的状态码、正文和全部响应头，并核对负例没有创建代理会话。该测试在 handler 层运行；独立 H2/H3 在线主动探测另由识别实验工具负责。

竞态检测重复 10 次通过。认证头模糊测试运行约 5 秒，执行 315998 次，未发现失败；短时模糊测试不能证明不存在缺陷。未在此组件验证 TLS 终止 CDN、进程重启后的会话恢复、真实运营商封锁或流量分类器表现。
