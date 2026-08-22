# P2P 数据面研究笔记 — 2026-08-22

## 实测基准（EasyTier v2.3.1 vs meshdesk）

同拓扑（txcloud首尔 ↔ AMD首尔/ARM伦敦，均无 VCN 入站规则）：

| 路径 | EasyTier P2P | meshdesk punched | 延迟对比 |
|------|-------------|------------------|---------|
| txcloud→AMD | 33.7 Mbps / 2.1ms | 12.6 Mbps / 2.9ms | ✅ 相当 |
| txcloud→ARM | 29.4 Mbps / 260ms | 0.75 Mbps / 261ms | ❌ 40x 差距 |

EasyTier 全部 P2P 直连成功，证明 Oracle VCN 不开入站规则也能打洞。

## 已落地的架构（v1.9, HEAD=8fd2829）

1. **RegisterPunchedStream** — 打洞成功的 UDP socket 直接注册为 ARQ transport，
   跳过 kx（kx 的 ~160B 消息被 VCN drop）
2. **双向 probe** — 注册后双方互发 reserved-seq probe，建立双向 conntrack
3. **TUN delivery** — punched stream 包装 connWithPeer 送 TUN forwarder accept
4. **coordinator key offset 修复** — +12→+8（截断4字符致 anti-spoof 全丢）
5. **keepalive (20s) + stale 自愈 (60s 无入站自动关闭)**

## 关键实验结论

### RAW 无 ARQ 模式 = 更差（已禁用）
实测 ARM 路径：ARQ 6Mbps vs RAW 1Mbps。
原因：任何 UDP 帧丢失损坏 in-flight TCP 段 → TCP 重传整段 → 0.1% 丢包率
雪崩成吞吐崩溃。ARQ 层是丢包环境的正确设计。EasyTier 能用 datagram 转发
是因为其可靠性模型不同。

### ARQ 窗口不能直接扩大
- 512/1024 窗口：TestUDPStream_LargeTransfer 挂死
- 根因：接收端 recvBuf 无限增长 + delayed-ACK(ackCount>=2) 饿死发送端窗口排空
- 需要 batched-ACK + bounded-recvBuf 重设计后才能扩窗

### ARM 路径带宽瓶颈定位（待验证）
ARM 只有 0.75Mbps ≈ 128帧×40B/260ms 的理论上限 → **MTU probe 从未成功**
→ 路径只跑 40B 小帧。疑似 ARM 的 Oracle VCN 限制 UDP payload ≤~200B。
EasyTier 当时 165B 包能过但未测 >500B。
**下一步**：从 ARM mux socket 分级发送 100-1500B 探测包 + tcpdump 定位阈值；
若确认 VCN 限制，考虑分片（IP 层或应用层拆帧）。

### 其他发现
- punched stream 与 relay 切换偶发抖动（getOutboundStream 每包重查 map）
- punchpoller 日志只在 MESHDESK_DEBUG=1 输出
- TestUDPStream_LargeTransfer 在 localhost 有 ~20% flaky 基线（UDP 丢包触发）

## 下一步优先级
1. 验证 ARM VCN UDP 包大小限制（分级 probe + tcpdump）
2. 若有限制：punched stream 应用层分片（>200B 拆多帧，接收端重组）
3. batched-ACK + bounded recvBuf → 窗口扩到 512+
4. 目标：ARM 路径 ≥10Mbps（EasyTier 的 1/3 即可用，追平需分片+扩窗）
