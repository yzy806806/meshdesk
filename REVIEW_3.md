# meshdesk 第三次全量代码审查报告

## 审查范围
- internal/tun/tun.go — TUN 设备 syscall
- internal/tun/router.go — VirtualIP → PublicKey 路由表
- internal/tun/route_manager.go — 内核路由表管理
- internal/ipam/ipam.go — 确定性 IP 分配 + 冲突解决
- internal/mesh/tun_forwarder.go — TUN 数据收发 + 源 IP 防伪
- internal/mesh/tun_integration.go — MeshNode 集成 + 路由管理
- internal/mesh/session_reconnect.go — 重连后恢复 TUN 路由
- cmd/meshdesk/main.go — join/leave/death/reconnect handlers + HasActiveSession guard

## 审查方法
- 全量阅读 8 个优先文件的源代码
- go vet / go build / go test -race 全部通过
- grep 搜索死代码、忽略错误、并发模式
- 手动追踪数据流和锁范围

---

## Critical

### C1. SetLocalIP 不清理旧 IP 条目 — 路由表泄漏 + 错误路由
**文件:** internal/tun/router.go:66-76
**描述:** `SetLocalIP` 在 IPAM 重新分配时被调用（通过 `ReallocateAfterGossip`），但只往 `ipToPeer` 和 `peerToIP` 中添加新 IP，不删除旧 IP 的映射。调用两次后，`ipToPeer` 中同时存在旧 IP 和新 IP，都指向 `localPubKey`。这导致：
1. 旧 IP 的路由条目永远不会被清理（内存泄漏）
2. 发往旧 IP 的包会被 `ResolveIP` 解析到自身，然后被 `IsSelf` 丢弃——正确行为但浪费 CPU
3. `RouteCount` 返回错误值

**修复:**
```go
func (r *Router) SetLocalIP(ip net.IP) {
    r.mu.Lock()
    defer r.mu.Unlock()
    // Remove old self IP entry if present
    if r.localIP != nil {
        oldStr := r.localIP.String()
        if oldStr != ip.String() {
            delete(r.ipToPeer, oldStr)
        }
    }
    r.localIP = make(net.IP, len(ip))
    copy(r.localIP, ip)
    r.ipToPeer[ip.String()] = r.localPubKey
    r.peerToIP[r.localPubKey] = ip
}
```

### C2. Gossip join/leave handler 被覆盖 — NAT 遍历功能丢失
**文件:** cmd/meshdesk/main.go:380-384 (NAT handler) vs 415-431 (TUN handler)
**描述:** 当 `cfg.P2P.NatTraversal` 和 `cfg.Mesh.TunEnabled` 同时为 true 时：
1. NAT 遍历块（line 380）调用 `gl.Events().SetJoinHandler(...)` 注册 NAT 连接初始化 handler
2. TUN 集成块（line 415）调用 `gl.Events().SetJoinHandler(...)` **覆盖**了 NAT handler
3. 同样，`SetLeaveHandler` 在 line 387 和 432 也被覆盖

`SetJoinHandler` / `SetLeaveHandler` 是赋值语义（覆盖，不链式），不是追加。结果是 NAT 遍历的 join/leave 回调永远不会被执行，NAT 对等体的连接建立和清理完全失效。

**修复:** 将两个 handler 合并为一个，或修改 `meshEventDelegate` 支持多 handler 链式调用：
```go
// 方案一：合并 handler
gl.Events().SetJoinHandler(func(meta *p2p.NodeMeta) {
    // NAT traversal
    if natTraversal != nil {
        natTraversal.InitiateConnection(meta.PublicKey, meta.Endpoints, p2p.NatType(meta.NatType))
    }
    // TUN routing
    if cfg.Mesh.TunEnabled && meta.VirtualIP != "" {
        ti := node.TUNIntegration()
        if ti != nil && ti.VirtualIP != nil && ti.VirtualIP.String() == meta.VirtualIP {
            // ... IPAM conflict resolution
        }
        node.AddPeerVirtualIPRoute(meta.PublicKey, meta.VirtualIP)
    }
})
```

---

## High

### H1. ti.VirtualIP 数据竞争 — 无锁并发读写
**文件:** internal/mesh/tun_integration.go:333 (写) vs cmd/meshdesk/main.go:419-420, 502-503 (读)
**描述:** `ReallocateAfterGossip` 在 line 333 写入 `ti.VirtualIP = newIP` 时没有持有任何锁（只从 `n.mu` 获取了 `ti` 指针）。同时，main.go 中的 gossip join handler（line 419）和 update handler（line 502）在不同 goroutine 中读取 `ti.VirtualIP`。

虽然 memberlist 的事件回调（join/update）是单线程的，但 main.go 的"re-broadcast"块（line 475-492）在**主 goroutine** 中运行，与 memberlist 事件 goroutine **并发**。主 goroutine 调用 `ReallocateAfterGossip` 写 `ti.VirtualIP`，同时 memberlist goroutine 的 join/update handler 读 `ti.VirtualIP`——这是 Go race detector 可检测到的数据竞争。

**修复:** 将 `ti.VirtualIP` 的读写用 `n.mu` 保护，或给 `TUNIntegration` 添加独立的 mutex：
```go
func (n *MeshNode) ReallocateAfterGossip(peerIPs map[string]net.IP) (net.IP, bool) {
    n.mu.Lock()
    ti := n.tunIntegration
    if ti == nil || ti.Allocator == nil {
        n.mu.Unlock()
        return nil, false
    }
    // ... allocation logic under n.mu ...
    ti.VirtualIP = newIP  // already under n.mu
    n.mu.Unlock()
    // ... kernel updates outside lock ...
}
```

### H2. 子网代理路由重分配不清理旧 peer 的 routes map
**文件:** internal/tun/route_manager.go:84-95
**描述:** 当子网从 peer A 重分配给 peer B 时，`AddPeerSubnets` 更新了 `subnetToPeer` 和 `subnetNets`，但**没有从 peer A 的 `routes[peerA]` map 中删除该子网**。后果：
1. peer A 的 `routes` map 仍然包含该子网条目
2. 当 peer A 离开时，`RemovePeerSubnets("peerA")` 会尝试删除该子网的内核路由——但它现在属于 peer B
3. peer B 的子网代理路由被错误删除

**修复:** 在重分配时，找到旧 peer 并从其 routes map 中删除该子网：
```go
if existingGW, exists := rm.subnetToPeer[cidr]; exists && existingGW != virtualIP {
    log.Printf("[route-mgr] subnet %s re-assigned from %s to %s (peer %s)",
        cidr, existingGW, virtualIP, shortHex(pubKey))
    rm.delKernelRoute(cidr)
    // Find and remove from old peer's routes map
    for oldPub, oldSubnets := range rm.routes {
        if oldSubnets[cidr] {
            delete(oldSubnets, cidr)
            if len(oldSubnets) == 0 {
                // peer has no subnets left, will be cleaned up
            }
            break
        }
    }
}
```

### H3. 源 IP 防伪校验在 peerID 为空时被完全跳过
**文件:** internal/mesh/tun_forwarder.go:476-481
**描述:** 当 `peerID == ""` 时，防伪校验被完全跳过，任何源 IP 的包都会被接受并写入 TUN 设备。在正常 mesh 通信中，所有连接都通过 `virtualPortMux.dispatch` 包装为 `connWithPeer`，所以 `peerID` 不会为空。但如果存在以下情况，则构成安全漏洞：
1. 任何代码路径绕过 `virtualPortMux` 直接连接 TUN 虚拟端口
2. 未来重构引入未包装的连接
3. 测试代码使用的未包装连接（如 `tun_integration_test.go` 中的测试）

这是一个纵深防御缺口。恶意对等体如果能让其连接不被包装，就可以注入任意源 IP 的数据包，绕过防伪校验。

**修复:** 当 `peerID` 为空时，默认拒绝（deny by default）：
```go
if peerID == "" {
    f.packetsSpoofed.Add(1)
    if isDebugLogEnabled() {
        log.Printf("[tun-forwarder] anti-spoof: no peer identity, dropping packet")
    }
    continue
}
if !f.validateSourceIP(packet, peerID) {
    f.packetsSpoofed.Add(1)
    continue
}
```

---

## Medium

### M1. ResolveSubnetProxy 使用互斥锁而非读写锁
**文件:** internal/tun/route_manager.go:145
**描述:** `ResolveSubnetProxy` 是只读操作，但使用 `rm.mu.Lock()`（`sync.Mutex` 写锁）。这会在高流量下成为瓶颈——每个子网代理包都要等待 `AddPeerSubnets`/`RemovePeerSubnets` 释放锁。`RouteManager` 的 mutex 类型是 `sync.Mutex`，没有 `RLock` 可用。

此外，`addKernelRoute` 和 `delKernelRoute` 在持有锁的状态下执行 `fork+exec`，锁持有时间可能长达数十毫秒。

**修复:** 将 `mu` 改为 `sync.RWMutex`，`ResolveSubnetProxy` 使用 `RLock`。或将内核路由命令移到锁外执行。

### M2. IPAM 整数溢出 — IPv6 子网 /64 及更宽无法工作
**文件:** internal/ipam/ipam.go:71
**描述:** `totalAddrs := 1 << hostBits`。对于 IPv6 /64 子网，`hostBits = 64`，`1 << 64` 在 64 位 Go 中为 0（运行时移位超过类型位宽返回 0），导致 `totalAddrs < 2` 为 true，返回错误。任何 hostBits > 63 的 IPv6 子网都会失败。

虽然当前 TUN 功能主要面向 IPv4，但代码注释和测试表明 IPv6 支持是设计意图的一部分。

**修复:** 使用 `uint64` 计算并在 `hostBits > 63` 时拒绝（而非静默返回错误）：
```go
if hostBits > 63 {
    return nil, fmt.Errorf("ipam: subnet %s too large (hostBits=%d > 63)", subnet, hostBits)
}
totalAddrs := 1 << hostBits
```

### M3. ParseCIDR 错误被忽略 — 潜在 nil 解引用
**文件:** internal/mesh/tun_integration.go:103
**描述:** `_, ipNet, _ := net.ParseCIDR(cfg.Mesh.MeshCIDR)` 忽略了错误。如果 `MeshCIDR` 格式无效（虽然 `ipam.NewAllocator` 已经验证过），`ipNet` 将为 nil，后续 `ipNet.Contains(staticIP)` (line 122) 会 panic。

虽然上游 `ipam.NewAllocator` 的验证使得这条路径在实践中不会触发，但忽略错误是脆弱的设计。

**修复:** 显式检查错误：
```go
_, ipNet, err := net.ParseCIDR(cfg.Mesh.MeshCIDR)
if err != nil {
    dev.Close()
    return fmt.Errorf("tun: invalid mesh_cidr %q: %w", cfg.Mesh.MeshCIDR, err)
}
```

### M4. SOCKS5 客户端忽略 io.ReadFull 错误 — 潜在 panic 和数据错误
**文件:** cmd/meshdesk/main.go:1707, 1725, 1729, 1731, 1735, 1742, 1822-1830
**描述:** SOCKS5 客户端代码中多处 `io.ReadFull` 返回的错误被忽略：
- Line 1707: `io.ReadFull(c, methods)` — 忽略错误后 `c.Write` 仍然执行
- Line 1729-1731: `io.ReadFull(c, lb)` 后直接使用 `lb[0]` — 如果读取失败，`lb[0]` 为 0，`fb` 长度为 0
- Line 1822-1830: `skipBindAddr` 函数中所有 `io.ReadFull` 错误都被忽略

如果读取失败（连接断开），后续处理会使用零值数据，导致错误的 SOCKS5 请求被发送到 exit 节点。

**修复:** 检查所有 `io.ReadFull` 的错误返回，失败时 `return`。

### M5. writeFramedPacket 两次 Write 无原子性保证
**文件:** internal/mesh/tun_forwarder.go:581-592
**描述:** `writeFramedPacket` 分两次 Write：先写 4 字节长度前缀，再写 payload。如果未来代码有多个 goroutine 向同一个 outbound stream 写入（当前不会，因为只有 tunReadLoop 写），length prefix 和 payload 可能交错，破坏帧格式。

当前代码是安全的（单 goroutine 写），但缺少防御性注释或断言。

**修复:** 合并为单次 Write 或添加注释：
```go
func writeFramedPacket(w io.Writer, packet []byte) error {
    buf := make([]byte, tunPacketHeaderLen+len(packet))
    binary.BigEndian.PutUint32(buf[:4], uint32(len(packet)))
    copy(buf[4:], packet)
    _, err := w.Write(buf)
    return err
}
```

---

## Low

### L1. backoffDelay 函数是死代码
**文件:** internal/mesh/session_reconnect.go:306-316
**描述:** `backoffDelay` 函数定义但从未被调用。`reconnectLoop` 使用内联退避 `delay = time.Duration(float64(delay) * 1.5)` 而非调用此函数。
**修复:** 删除该函数，或让 `reconnectLoop` 使用它以保持一致性。

### L2. Router/RouteManager 多个方法仅测试使用（死代码）
**文件:** internal/tun/router.go:154 (RemoveByIP), 257 (SyncFromPeers), 226 (RouteCount); internal/tun/route_manager.go:181 (RouteCount); internal/ipam/ipam.go:164 (Allocate), 352 (ResolveConflict)
**描述:** 以下函数在生产代码中无调用者（仅在 `_test.go` 中使用）：
- `Router.RemoveByIP` — 只在 router_test.go 中调用
- `Router.SyncFromPeers` — 只在 router_test.go 中调用
- `Router.RouteCount` — 无任何调用者（包括测试）
- `RouteManager.RouteCount` — 无任何调用者（包括测试）
- `Allocator.Allocate` (无 peers 版本) — 无任何调用者
- `ResolveConflict` — 无任何调用者

**修复:** 删除完全无调用者的函数（RouteCount x2, Allocate, ResolveConflict）。将仅测试使用的函数标记为测试辅助或保留但添加注释。

### L3. teardownTUN 子网代理路由删除命令不一致
**文件:** internal/mesh/tun_integration.go:235
**描述:** `teardownTUN` 删除子网代理路由时使用 `exec.Command("ip", "route", "del", cidr, "dev", ti.IfName).Run()`，忽略了错误，且缺少 `via <gw>` 参数。而 `RouteManager.addKernelRoute` 添加时使用了 `via <gateway>`。Linux 删除路由时，如果路由是通过网关添加的，删除命令也需要匹配网关参数才能成功删除（某些内核版本）。此外，错误被完全忽略（不像 `removeKernelRoute` 至少记录日志）。

**修复:** 使用 `RouteManager.RemovePeerSubnets` 或 `removeKernelRoute` 的模式，至少记录错误。

### L4. VirtualListener acceptCh 无缓冲 — 高负载下丢连接
**文件:** internal/mesh/virtual_listener.go:81
**描述:** `acceptCh: make(chan net.Conn)` 是无缓冲 channel。如果 `streamAcceptLoop` 正在处理上一个连接（如执行 `handleInboundStream`），新的 `dispatch` 调用会阻塞在 `vl.acceptCh <- wrapped`。虽然 `dispatch` 有 `doneCh` 的 select 防止永久阻塞，但在 listener 关闭前，新连接会因为 accept loop 慢而阻塞，可能导致 memberlist 事件 goroutine 被阻塞。

**修复:** 给 acceptCh 添加小缓冲：`acceptCh: make(chan net.Conn, 16)`

### L5. IPAM AllocateWithPeers 逻辑注释冗余且有过时分析
**文件:** internal/ipam/ipam.go:207-232
**描述:** `AllocateWithPeers` 函数中有一段冗长的注释（line 207-232）分析了冲突解决逻辑的设计思路，包含多次"Actually"和"Let's restructure"的自我修正，说明代码经历了多次设计迭代。注释内容部分过时（如提到"we also receive peerPubKeys"但实际参数只有 peerIPs）。
**修复:** 精简注释，只保留最终设计的描述。

---

## 总结

| 严重程度 | 数量 | 关键问题 |
|---------|------|---------|
| Critical | 2 | SetLocalIP 泄漏旧路由；NAT handler 被 TUN handler 覆盖 |
| High | 3 | ti.VirtualIP 数据竞争；子网代理重分配不清理旧 peer；防伪校验 peerID 为空时跳过 |
| Medium | 5 | ResolveSubnetProxy 锁瓶颈；IPv6 溢出；ParseCIDR 忽略错误；SOCKS5 忽略 ReadFull；writeFramedPacket 非原子 |
| Low | 5 | backoffDelay 死代码；6 个仅测试函数；teardownTUN 路由删除不一致；acceptCh 无缓冲；注释冗余 |

### 建议优先修复顺序
1. **C2 (handler 覆盖)** — 影响功能正确性，NAT 遍历完全失效
2. **C1 (SetLocalIP 泄漏)** — 影响路由正确性，IPAM 重分配后路由表污染
3. **H3 (防伪跳过)** — 安全漏洞，纵深防御缺口
4. **H1 (数据竞争)** — 并发安全，go test -race 可能检测到
5. **H2 (子网代理泄漏)** — 影响路由正确性，peer 离开时错误删除其他 peer 的路由

### 前两次审查修复验证
前两次审查修复的 Critical/High/Low 问题未在本次审查中复现，确认修复有效。
