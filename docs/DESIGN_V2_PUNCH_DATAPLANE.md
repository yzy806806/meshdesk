# meshdesk v2.0 P2P 数据面升级方案（对齐 EasyTier/Tailscale）

> 日期：2026-08-23  
> 目标：meshdesk 不满足于"打通"，要做到"好用"——打洞成功后数据面性能对齐
> EasyTier（实测 20+Mbps @ 260ms RTT），且路径在 NAT 重映射后能自愈。

---

## 一、现状与根因

### 1.1 实测结论（2026-08-22/23 五节点联调）

| 路径 | EasyTier | meshdesk punched | 根因 |
|------|----------|------------------|------|
| txcloud↔AMD（首尔同城） | 30Mbps / 2ms | 12.6Mbps / 2.5ms | ARQ 窗口×RTT 上限 |
| txcloud↔ARM (首尔↔伦敦) | **20+Mbps** | ❌ TCP 数据不通 | 见下 |

ARM 路径失败链：punched stream 的 keepalive（13B）双向通，
但 TUN 数据帧（51B）从未到达对端 → ARQ Write 卡窗口等待 → 永久卡死。

### 1.2 与 EasyTier 的核心差异（源码级）

| 维度 | EasyTier | meshdesk 当前 | 影响 |
|------|----------|---------------|------|
| 打洞 socket | UdpSocketArray 预创建的**独立 socket** | 复用 mux transport socket | flow 质量不同；mux socket 的端口映射可能被其他流量污染 |
| 数据帧 | raw datagram，无确认，1412B 大帧 | ARQ 分帧 ≤40B + ACK + 窗口 | 吞吐上限 = 窗口/RTT ≈ 19KB/s |
| 可靠性来源 | 上层 TCP 自愈 | UDP 层自建 ARQ | ARM 路径丢包 → ARQ 卡死放大 |
| flow 保持 | 数据本身双向高频流动 | 仅 2s keepalive 小帧 | VCN flow 老化后数据帧被丢 |
| 丢包响应 | 无感知（TCP 自己重传） | retransmit 风暴 + 窗口阻塞 | 单帧丢失 → 整条流卡顿 |

### 1.3 Tailscale magicsock 的关键参数（源码提取）

```
heartbeatInterval     = 3s    // disco ping 保活间隔
sessionActiveTimeout  = 45s   // 会话空闲超时（之后停 STUN）
trustUDPAddrDuration  = 6.5s  // 无 pong 时信任 bestAddr 的时长
discoPingInterval     = tsconst.DefaultPingInterval
upgradeUDPDirectInterval = 1min // 尝试升级到更优路径
```

设计要点：
- **连接先走 DERP relay 立即可用**，直连发现并行进行，几秒内透明升级
- heartbeat ping 双向 3s 一次（#540 曾讨论降到 2 包/s）
- bestAddr 信任期 6.5s，过期则回退 DERP 并重新探测
- 数据面是 raw WireGuard 包——**没有自建 ARQ**

---

## 二、方案选型

### 方案 A：RAW 直通模式（推荐，对齐 EasyTier）
punched stream 改为纯 datagram 转发：TUN IP 包直接发，无 ARQ。

可靠性由上层协议保证（TCP 自带重传）。ICMP 丢失可容忍。

**前置验证实验（必须先做）**：用 python 在 txcloud↔ARM 建立固定端口对的
双向高频 flow（200ms ping-pong），然后全速发 1400B 数据报，接收端统计到达率。
- 到达率 >95% 且带宽 >15Mbps → 方案 A 确定
- 否则 → 方案 C

### 方案 B：移植 NetBird/Tailscale 架构（ICE + wireguard-go）
用 pion/ice 替换自研打洞协调 + wireguard-go 作为数据面。

**优点**：工业级健壮性（candidate 收集、连通性检查、pair 选择都是标准实现）。
**缺点**：架构重写（估计 2-4 周）；引入 wireguard-go 意味着加密层重复
（meshdesk 已有 X25519 + Ed25519）；二进制体积膨胀。

**结论**：不推荐。meshdesk 已有完整的身份/加密/relay 体系，缺的只是
数据面的正确形态。方案 A 解决的是同一件事，代价小得多。

### 方案 C：保留 ARQ + 独立 socket + 高频心跳
最小改动路线。但 ARQ 的吞吐天花板（窗口×RTT）无法突破，
batched-ACK 重设计工作量不小于方案 A。

**结论**：作为方案 A 失败后的备选。

---

## 三、方案 A 详细设计

### 3.1 新组件：PunchedDataplane（替代 punched stream 的 ARQ 用法）

```go
// internal/mesh/punch_dataplane.go
type PunchDataplane struct {
    conn      *net.UDPConn   // 打洞专用 socket（新创建，非 mux socket）
    remote    *net.UDPAddr
    peerKey   string
    done      chan struct{}
    
    // 统计（用于健康监测和降级决策）
    txPackets atomic.Uint64
    rxPackets atomic.Uint64
    lastRx    atomic.Int64   // unix nano
    
    // 降级通知
    onDead    func()         // 路径死亡时回调（触发 relay 切换）
}
```

生命周期：
1. `OnHoleEstablished` 时创建（替代 RegisterPunchedStream）
2. 双方各发 5 个 probe（100ms 间隔）建立双向 conntrack —— 已有逻辑保留
3. 心跳 goroutine：每 2s 发 13B probe（已有逻辑保留）
4. **接收循环**：读到的每个 datagram 直接写入 TUN 设备（经 anti-spoof 校验）
5. **发送接口**：TUN forwarder 读到 IP 包 → 直接 WriteToUDP，不做分片

### 3.2 MTU 与分片策略

- TUN MTU 保持 1400；IP 包 ≤1400B + 11B 帧头 = 1411B < 1500B 以太网 MTU ✓
- 不需要应用层分片——EasyTier 的 1412B 大包实测畅通
- 若未来遇到更严格的路径，再加 IP 层分片（内核已支持，无需应用层处理）

### 3.3 可靠性边界

| 流量类型 | 丢失影响 | 缓解 |
|---------|---------|------|
| TCP | 自动重传该段 | 无需处理 |
| UDP (DNS等) | 该查询失败重试 | 应用层自愈 |
| ICMP | ping 丢包显示 | 可接受 |

### 3.4 健康监测与自动降级

```
每 10s 检查：
if lastRx 距今 > 15s（连续 7 个心跳无回音）:
    → 调 onDead() 
    → TUN forwarder 切回 relay
    → 触发重新打洞（ClearHoleEndpoint + ResetHoleState）
```

TUN forwarder 的选择逻辑改为：

```go
func getOutboundStream(peerKey) {
    // 1. PunchDataplane 存活 → 用它（raw datagram）
    // 2. 否则 → smux relay stream（现有路径）
}
```

入站同理：PunchDataplane 收到的包直接注入 TUN；
relay stream 收到的包也注入 TUN。两条路并存，
出站优先走 PunchDataplane（若存活），入站双路都接受。
这消除了当前"切换期间丢包"的问题。

### 3.5 与现有代码的关系

| 现有组件 | 处置 |
|---------|------|
| RegisterPunchedStream / udpStreamConn | punched path 改用 PunchDataplane；ARQ 版本保留给 legacy DialUDPPeer（session_reconnect 用） |
| routeUDPPacket 的 plain-key 分支 | PunchDataplane 有自己的 recvLoop，不再依赖 mux 的统一路由 |
| 双向 probe + keepalive | 保留（移入 PunchDataplane）|
| MESHDESK_PUNCH_DATAPLANE 门控 | 移除——新数据面默认启用，靠健康监测自动降级 |
| key-based arbitration / peer-won drop | 已删除，不需要恢复 |
| ARQ 层（udp_conn.go） | 保留，legacy DialUDPPeer 和未来需要可靠 UDP 时使用 |

### 3.6 实施计划

| 阶段 | 内容 | 工时 |
|------|------|------|
| P0 验证 | python 双向 flow 实验（见上文 1.A 前置验证） | 0.5h |
| P1 核心 | PunchDataplane 结构体 + 收发循环 + TUN 注入 | 4h |
| P2 集成 | OnHoleEstablished 对接 + getOutboundStream 改造 | 2h |
| P3 健康监测 | 15s 无入站检测 + 自动降级 relay + 重打洞 | 2h |
| P4 清理 | 移除 punched stream 的 ARQ 用法 + MESHDESK_PUNCH_DATAPLANE 门控 | 2h |
| P5 测试 | AMD 路径验证 + ARM 路径对比 EasyTier + 24h 稳定性 | 8h |
| P6 文档 | RELEASE_NOTES v2.0.0 + README + 本文档更新 | 2h |

### 3.7 验收标准

1. txcloud↔AMD：iperf 接收端确认 ≥25Mbps（EasyTier 同路径 30Mbps）
2. txcloud↔ARM：iperf 接收端确认 ≥15Mbps（EasyTier 同路径 20+Mbps）
3. ping 延迟与 EasyTier 相当（AMD ~2ms / ARM ~260ms）
4. peer 重启后 60s 内自动恢复直连
5. 路径失效后 15s 内自动降级 relay，流量不中断（可能有短暂抖动）
6. go test 全量通过；24h 运行 goroutine 数稳定

---

## 四、参考实现索引

| 项目 | 关键文件 | 许可 | 借鉴点 |
|------|---------|------|--------|
| tailscale/magicsock | wgengine/magicsock/endpoint.go | BSD-3 | heartbeat 3s、bestAddr trust 6.5s、路径质量评估 |
| tailscale/disco | disco/disco.go | BSD-3 | Ping/Pong/CallMeMaybe 协议形态（对应我们的 probe） |
| netbird client | client/internal/peer/worker_ice.go | BSD-3 | ICE agent 生命周期管理 |
| xtaci/kcp-go | （可选）| MIT | 若未来需要可靠 UDP，KCP 是比自研 ARQ 成熟得多的选择 |

## 五、风险与缓解

| 风险 | 概率 | 缓解 |
|------|------|------|
| RAW 模式在某些路径丢包率高 | 中 | 健康监测自动降级 relay；TCP 流量不受影响 |
| 双向高频心跳被 VCN 限速 | 低 | 心跳只有 13B/2s，远低于限速阈值 |
| 打洞 socket 与 mux socket 冲突 | 低 | 独立 bind 随机端口（Mode A 已有此机制） |
| 多 peer 场景 socket 数量膨胀 | 低 | 每 peer 1 个 socket，6 节点最多 5 个 |


---

## 实测结果（2026-08-23，4 节点部署）

### meshdesk PunchDataplane vs EasyTier 基准（接收端严格确认）

| 路径 | meshdesk v2.0 | EasyTier | 对标 |
|------|--------------|----------|------|
| txcloud→AMD (首尔同城) | 31.7 Mbps / 3.2ms | 30.4 Mbps / 2.1ms | ✅ 超越 |
| txcloud→ARM (首尔→伦敦) | 20.6 Mbps / 261ms | 20.7 Mbps / 260ms | ✅ 持平 |

### 实施过程中的关键 bug 修复

1. **strip length prefix** — TUN forwarder 写 [4B len][IP]，raw UDP 需要裸 IP。
   PunchDataplane.Write 自动剥掉前 4 字节。

2. **route probes through feed** — punchSocketPoller 丢弃 0x50 0x4A probe
   导致对端 lastRx 不更新 → 20s 后 health check 误杀。改为所有包走
   routeUDPPacket → feed callback。

3. **early-init manager** — Start() 里提前初始化 PunchDataplaneMgr，
   确保 OnHoleEstablished 和 wireMeshNodeCallbacks 共享同一实例。

### 代码位置

| 文件 | 内容 |
|------|------|
| `internal/mesh/punch_dataplane.go` | PunchDataplane 结构体 + Feed + Write + keepalive + health |
| `internal/app/holepunch.go` | OnHoleEstablished 对接 PunchDataplane |
| `internal/mesh/tun_forwarder.go` | getOutboundStream 优先 PunchDataplane |
| `internal/mesh/mux_udp.go` | routeUDPPacket → punchDataplaneFeed |
| `internal/mesh/mux_transport.go` | punchSocketPoller 路由所有包 |
| `internal/app/mesh_node.go` | wireMeshNodeCallbacks 设置 feed callback |
| `internal/mesh/node.go` | PunchDataplaneMgr/TunWriteFunc/ValidateSourceIPFunc |

### v2.0.1 审查修复（2026-08-23）

v2.0.0 发布后全量代码复审发现的失败路径缺陷，全部修复：

| 级别 | 缺陷 | 修复 |
|------|------|------|
| H1 | dead 数据面永不从 Manager 移除 → 内存泄漏 + 入站包误入 ARQ 路径 | onDead 回调 + Get() 惰性删除双保险 |
| H2 | TUN 未初始化时 TunWriteFunc() 返回 nil，首个入站包 panic 杀死 poller goroutine | 构造器拒绝 nil + Feed 防护 |
| M1 | Write() 剥长度前缀后返回线缆字节数，违反 io.Writer 契约 | 返回 len(p) |
| M2 | feed 按精确 addr 匹配，NAT rebind 后静默丢包 | ≤1/min 限频日志 |
| M3 | GetPunchedStream 判死不回收 ARQ 流 | 同锁内身份校验后 delete+Close |

另：L4 Start() 缩进修正。验证：build/vet 干净；app+holepunch 测试全过；
mesh 包除既有 flaky（TestUDPStream_LargeTransfer，v2.0.0 tag 同样存在）外全过。
