# 初次端到端 smoke，不能用于正式性能结论

这是 2026-11-06 22:36 UTC 实际执行的四项 6 秒测量（每项另有 1 秒预热），固定名义 8/2 Mbps、RTT60ms、随机丢包0、一个后台下载。版本、程序SHA、原始事件和计数均保留在本目录。HTTP为验证证书的HTTPS，Xray使用REALITY+Vision和自有TLS cover；PX和Hysteria使用QUIC。

四项均实际完成HTTP、持久echo、SSE及后台下载，未发现字节校验、SSE序列或源端队列错误。该短样本用于确认互通与测量脚本，不构成稳定尾延迟比较。

此时的工作负载工具发现两个问题，正式矩阵必须用修复版本：

1. SSE源端计划/产生时间使用墙钟。虚拟机墙钟在Xray这轮发生回拨，`source_generation_delay_ms` 中位数为不可能的 -102.3ms。原始数据未改写；源端delay、source gap及excess gap的归因不可信。接收端采用单调时钟的receipt gap仍可作互通诊断。
2. 部分最终echo请求的socket deadline比父context完成通知先到，在测试结束边界被记作timeout，实际请求仅持续46.9ms或266.8ms，之后的即时失败也被记timeout。它们应作为结束截尾核对，不应当作完整3秒的网络超时。原始状态未修改。

配置和认证材料只保存在忽略的 `.local/matrix/` 与虚拟机私密目录，本目录不含认证密钥。链路qdisc丢弃即使随机丢包为0也可能发生，因为突发填满有限队列；相关计数均保留。

随后检查发现通用GSO关闭后，ethtool仍显示专门的`tx-udp-segmentation`标志为on。正式矩阵会额外显式关闭该标志及`tx-gso-list`；本次smoke不用于与新配置下的结果混合统计。
