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

## 深夜联调最终定论（2026-08-23 凌晨，五节点 EasyTier 对照）

tcpdump 三重验证（txcloud出站/ARM入站/ARM routeUDPPacket日志）：

### v4 打洞路径（meshdesk punched stream）
1. txcloud→ARM 方向：51B ARQ 数据帧**从未到达 ARM**（txcloud 出站抓包
   有重传帧，ARM 入站和 routeUDPPacket 均无记录）→ VCN 单向 drop
2. ARM→txcloud 方向：13B/11B keepalive 双向正常流动
3. 降 payload 到 16B（27B 帧）依然不通 → v4 打洞路径对本项目不可用

### EasyTier 基准数据全部推翻
- iperf3/echo 测的 29-34Mbps 是**发送端假象**（send() 写内核缓冲即返回，
  数据实际被路径丢弃）。bw_strict 校验模式揭穿：多数传输 ACK 超时。
- EasyTier peer 表的 "p2p udp" 标签是隧道协商标记。10MB 传输期间
  双端物理网卡只有几十个小包——**数据实际走 IPv6 直连或 TCP relay**
- EasyTier 真正能通的原因：ARM 有公网 IPv6 且 easytier 监听 11010，
  txcloud 直接通过 **IPv6 直连**（1412B 大包 tcpdump 确认到达 ARM）

### meshdesk 的正确出路：IPv6 直连优先
txcloud↔ARM 都有公网 IPv6 且实测互通（v4+v6 TCP/UDP 全通）。
- meta exchange 需要广播各节点的 IPv6 endpoint（advertise_endpoints）
- TUN forwarder / session dialer 优先尝试 v6 直连，失败再打洞/relay
- punched stream 保留为 v4-only 环境的兜底

### 实施状态
- ARM config 已加 v6 advertise_endpoints（2603:c020:...:52888）
- meshdesk mux transport 已有 [::] v6 socket（随机端口，coordination 交换）
- 待实现：v6 endpoint 的 session dial + TUN forwarder 直连优先级

## 下一步优先级
1. 验证 ARM VCN UDP 包大小限制（分级 probe + tcpdump）
2. 若有限制：punched stream 应用层分片（>200B 拆多帧，接收端重组）
3. batched-ACK + bounded recvBuf → 窗口扩到 512+
4. 目标：ARM 路径 ≥10Mbps（EasyTier 的 1/3 即可用，追平需分片+扩窗）
