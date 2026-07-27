# EasyTier Peer 管理架构调研 — MeshDesk 需要抄什么

**Date:** 2026-07-27
**Source:** DeepWiki + EasyTier 源码分析

---

## EasyTier 的核心设计

EasyTier 不用 WireGuard 做 mesh。它有自己完整的网络栈：

### 层次结构

```
PeerManager (中央调度器)
  ├── PeerMap (按 PeerId 存储活跃 peer)
  │     └── Peer (一个远端节点)
  │           └── PeerConn (一条 tunnel 连接 + Noise 握手 + ping/pong)
  ├── RouteAlgoInst (OSPF 路由)
  ├── ForeignNetworkManager (跨网络转发)
  ├── RelayPeerMap (中继会话管理)
  └── PeerRpcManager (RPC over peer link)
```

### 关键机制

1. **Tunnel trait** — 抽象传输层。每种传输(TCP/UDP/WS/QUIC)实现 Tunnel trait。节点间连接就是一条 Tunnel。

2. **PeerConn** — Tunnel + Noise 协议握手 + PeerConnPinger 保活。每个 PeerConn 直接知道远端的 source address（从 TCP accept 或 UDP recv 获得的地址）。

3. **Peer.select_conn()** — 同一个 peer 可以有多条 PeerConn（不同传输），按延迟选最优。后台任务定期清除选择强制重新评估。

4. **PeerMap.add_new_peer_conn()** — 当新 PeerConn 建立时，自动注册。共享节点收到连接时，直接从连接的 source address 获得远端 endpoint。

5. **OSPF 路由 (PeerRoute)** — 动态路由协议，拓扑同步。节点传播自己的直连 peers + 延迟，全网计算最优路径。

6. **RelayPeerMap** — 直连不通时通过中继节点转发。有独立的 Noise XX 握手加密。但这是 fallback，不是默认模式。

### 连接建立流程

```
节点A → 连接共享节点S (TCP/UDP/WS tunnel)
         ↓
    PeerConn 建立握手 (network_name + network_secret_digest)
         ↓
    PeerMap.add_new_peer_conn() → 共享节点S知道了节点A的endpoint
         ↓
    OSPF路由同步 → 全网知道了节点A的endpoint
         ↓
    节点B收到节点A的endpoint → 尝试直连 (UDP hole punch 或 TCP)
         ↓
    直连成功 → PeerConn 直接 A↔B
    直连失败 → RelayPeerMap 通过S中继
```

## MeshDesk 当前的问题

MeshDesk 用两套独立系统：
1. **WireGuard (wireguard-go)** — 做 mesh IP 路由和加密
2. **memberlist (hashicorp)** — 做 gossip 发现

两套系统之间没有同步 endpoint 信息：
- memberlist 通过 gossip 传播 NodeMeta（包含 Endpoints 字段）
- 但 `SetLocalEndpoints()` 从未被调用 → Endpoints 始终为空
- wgDelegate.AddPeer() 添加 peer 时用 `firstNonEmpty(meta.Endpoints)` → 空字符串
- WireGuard peer 没有 endpoint → 无法发握手

**核心差距：EasyTier 的 Tunnel 层直接从连接获得 source address，不需要额外填充。MeshDesk 的 WireGuard 和 memberlist 是分离的——WireGuard 从 UDP 包学习 endpoint，但 gossip 传播的 endpoint 信息没人填充。**

## 需要抄的改进

### 1. 从 WireGuard endpoint 学习填充 gossip Endpoints

WireGuard 在收到 peer 的握手包时能学到 source endpoint。需要在 obfuscatingBind 的 Receive 路径里，从收到的 UDP 包 source address 提取 endpoint，调用 `SetLocalEndpoints()`。

但更简单的方式：节点自己知道自己的 endpoint（配置文件里共享节点的 endpoint 是公网 IP，普通节点可以也配置自己的公告地址）。

### 2. 或者：抄 EasyTier 的 Tunnel + PeerConn 模型

更彻底的方案——放弃 WireGuard 做 mesh，改用 EasyTier 的模型：
- Tunnel = 传输层连接（TCP/UDP/WS/Reality TLS）
- PeerConn = Tunnel + 加密 + 保活
- PeerManager = 管理 PeerConn + 包分发 + 路由
- endpoint 从连接的 source address 自动获得

但这等于重写 MeshDesk 的 mesh 核心。工作量极大。

### 3. 最小修复：让共享节点学习 endpoint 并通过 gossip 传播

这是当前架构下的最小修复：
1. 共享节点的 WireGuard 收到普通节点的握手包 → 从 source address 学习 endpoint
2. 通过 `wgDelegate` 回调把学到的 endpoint 传给 gossip layer
3. gossip 传播更新后的 NodeMeta.Endpoints
4. 其他节点收到 gossip 更新 → 通过 `events.go` 更新 WireGuard peer 的 endpoint

这需要在 `obfuscatingBind` 的 receive 路径加一个回调——收到 peer 包时通知 gossip layer 更新该 peer 的 endpoint。

## EasyTier 关键文件参考

| EasyTier 文件 | 功能 | MeshDesk 对应 |
|---|---|---|
| peers/peer_manager.rs | PeerManager 中央调度 | peer_manager.go (已有但不同模型) |
| peers/peer_conn.rs | PeerConn + Noise 握手 + ping | obfuscatingBind (部分) |
| peers/peer_map.rs | PeerMap 按 PeerId 存储 | routing.go (静态 map) |
| peers/peer.rs | Peer + select_conn() 多连接 | peer_manager.go (部分) |
| peers/peer_ospf_route.rs | OSPF 路由 | ❌ 无 |
| peers/relay_peer_map.rs | 中继会话管理 | relay_*.go (有但未接线) |
| peers/peer_conn_ping.rs | 连接保活 + 延迟测量 | peer_manager.go (部分) |
| peers/peer_session.rs | Noise 会话密钥 | WireGuard 内置 |
| peers/secure_datagram.rs | 密钥轮换 + 重放保护 | WireGuard 内置 |
| tunnel/ | Tunnel trait + 各种传输实现 | transport.go (新加的抽象) |
