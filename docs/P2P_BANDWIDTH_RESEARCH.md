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

### ARM 路径带宽瓶颈（已定位，2026-08-22 深夜联调）
tcpdump 双端抓包确凿证据：txcloud↔ARM punched stream 上只有 13B/11B/
6B 的 keepalive probe 帧双向流动；**51B 的 TUN ARQ 数据帧一个都没出现**
（txcloud 出站抓包 0 帧，ARM 入站抓包 0 帧）。

结论：ARM 路径的 VCN 过滤 UDP 包大小，阈值在 13B～51B 之间（13B probe
通过，51B 数据帧被 drop）。这与 v1.8.3 时代"kx msg2 (~160B) 被 drop"完全
一致——不是 kx 特有问题，是路径对包大小的持续过滤。

推论：MTU probe (1211B) 必然失败 → payloadSize 锁死 40B → 即使窗口扩大
也无法提升吞吐（512×40B/0.26s ≈ 0.6Mbps）。**分片是唯一出路**：
- 应用层分片：ARQ 帧拆成 ≤13B 的子帧（开销 116%，但可行）
- 或确认真实阈值后按最大可行帧大小分片（若阈值是 32B，开销 44%）
- IP 层分片不可行（VCN drop 发生在分片重组前）

EasyTier 当时 165B 包能过的原因待查：可能其 socket pair 的 VCN flow
状态不同，或有端口/协议特征差异。值得用 EasyTier 复现并抓包对比。

**下一步实验**：
1. 二分定位 ARM 路径的精确包大小阈值（从 meshdesk mux socket 发 14~50B）
2. 若阈值 ≥40B：检查为何 51B 帧 drop 而 40B+11B=51B 应该等价……重新验证
3. 分片实现：punched=true 时 Write 按 (阈值-11B) 切片，每片独立 seq 空间

### 其他发现
- punched stream 与 relay 切换偶发抖动（getOutboundStream 每包重查 map）
- punchpoller 日志只在 MESHDESK_DEBUG=1 输出
- TestUDPStream_LargeTransfer 在 localhost 有 ~20% flaky 基线（UDP 丢包触发）

## 深夜联调最终定论（2026-08-23 凌晨）

tcpdump 三重验证（txcloud出站/ARM入站/ARM routeUDPPacket日志）：

1. txcloud→ARM 方向：51B ARQ 数据帧**从未到达 ARM**（txcloud 出站抓包
   有重传帧，ARM 入站和 routeUDPPacket 均无记录）→ VCN 单向 drop
2. ARM→txcloud 方向：13B/11B keepalive 双向正常流动
3. 降 payload 到 16B（27B 帧）依然不通 → 阈值极小或非纯大小问题
4. EasyTier 能通的核心差异：**200ms 双向高频 ping-pong 从不间断**，
   VCN flow 永远新鲜；且其 28B 帧 + 高频互发的组合恰好存活

### 可能的突破方向
A. 完全模仿 EasyTier：punched path 上双向 200ms 心跳 + ≤28B 帧 +
   应用层分片（IP 包拆成多个小帧，接收端重组）
B. 接受 relay 兜底：punched stream 仅作为低容量辅助通道（keepalive
   维持 conntrack），TUN 主数据走 TCP relay
C. 研究 EasyTier 源码中 UdpSocketArray 的端口预测策略（对 symmetric
   NAT 的 port hopping），可能有额外的 flow 特性

### 当前建议
方案 B 最务实：meshdesk 的 TCP relay 在同路径实测 ~2-8Mbps（260ms RTT
双跳），已经优于 punched path 的实际表现。把 punched stream 保留为
"conntrack 预热 + 快速切换通道"，等方案 A 的分片实现后再启用为主数据面。

## 下一步优先级
1. 验证 ARM VCN UDP 包大小限制（分级 probe + tcpdump）
2. 若有限制：punched stream 应用层分片（>200B 拆多帧，接收端重组）
3. batched-ACK + bounded recvBuf → 窗口扩到 512+
4. 目标：ARM 路径 ≥10Mbps（EasyTier 的 1/3 即可用，追平需分片+扩窗）
