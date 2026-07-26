# MeshDesk 架构重构方案：传输层抽象 + Reality + PeerManager

**Date:** 2026-07-26
**Status:** Approved by user — proceed with implementation

---

## 核心决策

MeshDesk 保持 Go 单二进制，通过抄两个来源实现完整 mesh + Reality：

1. **抄 EasyTier 的架构设计**（Rust→Go 翻译，抄设计不抄代码）
   - 传输层抽象（Transport trait → Go interface）
   - PeerManager（自动重连 + 多传输 fallback + 延迟探测 + 最优路径选择）
   - 动态路由（gossip 传播路由信息 + 延迟感知选路）

2. **抄 xray-core 的 Reality TLS 实现**（Go→Go，可直接参考代码）
   - `transport/internet/reality/` 的 ServerHello 劫持
   - uTLS 指纹模拟（MeshDesk 已有 utls 基础）
   - fallback 机制（认证不通过转发给真实网站）

---

## 目标架构

```
┌─────────────────────────────────────────┐
│  Dashboard (x-ui, 拓扑, WebSSH, 监控)     │  ← MeshDesk 已有
├─────────────────────────────────────────┤
│  应用层 (gossip, monitor, file transfer)  │  ← 已有
├─────────────────────────────────────────┤
│  Mesh 层 (WireGuard + gVisor netstack)    │  ← 已有
├─────────────────────────────────────────┤
│  传输层 (Transport interface)             │  ← 重点重构
│   ├── UDP Transport (原始, LAN)           │     已有
│   ├── Reality Transport (抄 xray-core)    │     新增 P0
│   └── WS Transport (已有, fallback)       │     已有
├─────────────────────────────────────────┤
│  PeerManager (抄 EasyTier 设计)           │  ← 重点新增
│   ├── 自动重连 + 多传输 fallback           │
│   ├── 延迟探测 + 最优路径选择              │
│   └── 动态路由 (gossip 传播)              │
└─────────────────────────────────────────┘
```

---

## 实现计划

### Phase 1: 传输层抽象重构 (P0)

当前 MeshDesk 的 obfuscatingBind 紧耦合 WireGuard UDP。需要抽象出通用 Transport interface：

```go
package transport

type Transport interface {
    Connect(addr string) (net.Conn, error)
    Listen(port int) (net.Listener, error)
    Name() string
}

// 已有实现
type UDPTransport struct{}    // 原始 WireGuard UDP (LAN)
type WSTransport struct{}     // WebSocket + utls (已有 obfuscation.go)

// 新增实现
type RealityTransport struct{} // Reality TLS (抄 xray-core)
```

WireGuard 的 obfuscatingBind 改为调用 Transport interface，根据 peer 配置选择传输。

### Phase 2: Reality Transport (P0)

参考 xray-core 的 `transport/internet/reality/` 实现：

**服务端 (Listen):**
1. TCP 监听 443
2. 收到连接 → 读 ClientHello
3. 作为客户端连真实网站 (apple.com:443) → 拿真实 ServerHello + 证书
4. 在证书中注入 HMAC 认证信息 (X25519 + shortId)
5. 发给客户端
6. 验证通过 → mesh 管道
7. 验证不通过 → 透传给真实网站 (fallback)

**客户端 (Connect):**
1. TCP 连接目标
2. uTLS 模拟 Chrome TLS 指纹
3. SNI = www.apple.com
4. 在 TLS 扩展里携带 shortId + publicKey
5. Reality 握手完成 → 返回 TLS 连接作为管道

关键依赖：
- `github.com/refraction-networking/utls` — TLS 指纹模拟 (MeshDesk 已用)
- `crypto/tls` — TLS 1.3 基础
- `crypto/hmac` + `crypto/sha512` — Reality 认证
- `golang.org/x/crypto/curve25519` — X25519 密钥交换

参考文件：
- xray-core: `transport/internet/reality/reality.go`
- xray-core: `transport/internet/reality/config.go`

### Phase 3: PeerManager (P1)

参考 EasyTier 的 PeerManager 设计：

```go
package mesh

type PeerManager struct {
    peers    map[PeerID]*PeerConnection
    node     *MeshNode
    routes   *RouteTable  // 动态路由表
}

type PeerConnection struct {
    id         PeerID
    transports []transport.Transport  // 按优先级排序
    conn       net.Conn               // 当前活跃连接
    latency    time.Duration
    lastSeen   time.Time
    mu         sync.RWMutex
}

// PeerManager 负责：
// - 自动重连（连接断开后按 fallback 顺序重试）
// - 多传输 fallback（UDP 不通 → Reality → WS）
// - 延迟探测（定期 ping，选最优路径）
// - 动态路由（通过 gossip 传播已知 peers + 延迟）
```

**连接 fallback 顺序:**
1. UDP 直连 (LAN，最低延迟)
2. Reality TLS (跨墙，GFW 对抗最强)
3. WebSocket+TLS (fallback，已有实现)
4. 共享节点中继 (NAT 后的节点)

### Phase 4: 动态路由 (P2)

参考 EasyTier 的延迟优先路由：

```go
type RouteTable struct {
    routes map[MeshIP]RouteEntry
}

type RouteEntry struct {
    NextHop   PeerID      // 下一跳
    Latency   time.Duration
    Hops      int          // 跳数
    Transport string      // 传输方式
    UpdatedAt time.Time
}

// 通过 gossip 传播：
// - 自己的直连 peers + 延迟
// - 收到信息后更新路由表
// - 按延迟选最优路径（非最短跳数）
```

简化版 OSPF——不需要完整的链路状态算法，用 gossip 累积式传播就够。

---

## 不做的事情

1. ❌ 不 fork EasyTier（只抄架构设计，Go 重新实现）
2. ❌ 不 fork xray-core（只抄 Reality TLS 代码片段）
3. ❌ 不用子进程管理 xray（Reality 内嵌在 MeshDesk 内）
4. ❌ 不写 Rust（全 Go）
5. ❌ 不删现有 padded/websocket 混淆（保留作为 fallback）
6. ❌ 不做 OSPF 完整实现（用 gossip 传播简化路由）

---

## 配置模型

```yaml
mesh:
  port: 51820
  
peers:
  - public_key: "..."
    endpoint: "203.0.113.10:443"
    obfuscation: "reality"     # ← 新增选项
    reality:
      server_name: "www.apple.com"
      public_key: "..."        # 服务端 X25519 公钥
      short_id: "0123456789abcdef"
    allowed_ips:
      - "10.10.108.221/32"
  - public_key: "..."
    endpoint: "10.0.0.26:51820"
    obfuscation: "none"        # LAN 直连
    allowed_ips:
      - "10.10.9.227/32"

# Reality 服务端配置 (本节点是共享节点时)
reality:
  enabled: true
  listen_port: 443
  target: "www.apple.com:443"
  server_names: ["www.apple.com"]
  private_key: "..."          # xray x25519 生成
  short_ids: ["0123456789abcdef"]
```

---

## 优先级

```
P0: 传输层抽象重构 → Reality Transport → 修复 mesh TCP
P1: PeerManager (自动重连 + fallback)
P2: 动态路由 (gossip 传播)
P3: x-ui 面板 (依赖 Reality Transport)
```

Phase 1+2 可以并行——传输层抽象和 Reality Transport 代码可以同时写。
