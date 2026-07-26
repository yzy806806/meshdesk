# MeshDesk 实机测试报告 + 遗留问题 + 新功能需求

**Date:** 2026-07-26
**Tester:** Hermes (用户指导)
**Environment:** ARM(10.144.144.3) + AMD1(10.144.144.1) + AMD2(10.144.144.2) + 阿里云(10.144.144.10)
**Binary:** 最新 main 分支 (commit 3d2ef42)

---

## 已修复的 Bug（已 push 到 GitHub）

### Bug 1: WireGuard 握手不触发
- **问题:** peers 在 `dev.Up()` 之前添加，wireguard-go 不触发 handshake timer
- **修复:** `internal/mesh/node.go` — peer 添加移到 `Start()` 中 `dev.Up()` 之后
- **修复:** 添加 `persistent_keepalive_interval=10` 到每个 peer 的 IPC 配置
- **验证:** ARM↔aliyun, AMD1↔aliyun, AMD2↔aliyun 握手成功，keepalive 双向正常

### Bug 2: MeshTransport packet/stream 混淆
- **问题:** `WriteTo`(packet) 和 `DialTimeout`(stream) 都走同一 TCP listener，StreamCh 吞掉所有连接，memberlist 报 `invalid msgType`
- **修复:** `internal/p2p/memberlist_transport.go` — packet 数据加 0xFF sentinel + 4字节长度前缀，接收端 peek 第一字节判断 packet vs stream
- **验证:** 阿里云端 `invalid msgType` 错误消除，AMD2 stream 连接正常建立

---

## 遗留问题（需团队修复）

### Problem 1: mesh TCP 连接不通
- **现象:** WireGuard 握手成功（UDP 层通），但 gVisor netstack 的 TCP 拨号到 mesh IP:port 超时
- **复现:** ARM gossip join 10.10.108.221:7946 → `context deadline exceeded`
- **复现:** 阿里云 TCP ping 到 AMD2:7946 → `i/o timeout`
- **可能原因:**
  1. WireGuard allowed_ips 路由不完整 — gVisor netstack 发 TCP 包到 mesh IP，但 WireGuard 不知道发给哪个 peer
  2. 共享节点（阿里云）配置里普通节点 endpoint 为空，WireGuard 从收到的包学习 endpoint，但学习到的可能是 mesh IP 而非真实 IP
  3. gVisor netstack 的路由表和 WireGuard 的 allowed_ips 不匹配
- **优先级:** P0 — 阻塞所有 mesh 内通信

### Problem 2: 共享节点重启后丢失 endpoint
- **现象:** 阿里云重启后报 `Failed to send handshake initiation: no known endpoint for peer`
- **原因:** 共享节点配置里普通节点 endpoint 为空，WireGuard 运行时学习的 endpoint 在重启后丢失
- **影响:** 共享节点重启后需要等普通节点重新发包才能恢复
- **优先级:** P1

### Problem 3: 拓扑显示不完整
- **现象:** Topology API 只显示直连 peer，非直连节点不可见
- **原因:** gossip 没成功 join，节点互相发现不了
- **依赖:** 修复 Problem 1 后自然解决

### Problem 4: 监控数据上报未验证
- **配置:** ARM 和 AMD2 配了 collectors 指向 AMD1
- **状态:** 未验证监控数据是否到达 AMD1（因为 mesh TCP 不通）

---

## 测试环境配置（供团队参考）

```
阿里云 (共享节点):
  mesh IP: 10.10.108.221
  endpoint: 115.29.235.24:51820
  peers: ARM + AMD1 + AMD2 (endpoint 为空)

ARM (普通节点):
  mesh IP: 10.10.9.227
  peer: aliyun (115.29.235.24:51820)
  gossip seed: 10.10.108.221:7946

AMD1 (普通节点 + Dashboard):
  mesh IP: 10.10.63.207
  peer: aliyun
  gossip seed: 10.10.108.221:7946
  web: :18080

AMD2 (普通节点):
  mesh IP: 10.10.190.34
  peer: aliyun
  gossip seed: 10.10.108.221:7946
```

UFW 已在所有节点放行 51820/udp。

---

## 新功能需求

### Feature 1: Dashboard 集成 x-ui 面板

用户要求在 Dashboard 中增加 x-ui 功能，作为：
- **内网入口管理** — 统一管理 mesh 内节点的入口配置
- **翻墙节点管理** — 可视化配置和管理翻墙代理节点
- **一键配置节点** — 从 Dashboard 一键完成 xray/VLESS/VMess 节点配置，不需要手动编辑 JSON

核心价值：用户不想在每台机器上手动配置 xray。通过 Dashboard 集成，选择一个 mesh 节点 → 选择协议（VLESS/VMess/Trojan）→ 填入参数 → 一键生成配置并部署。

### Feature 2: 公网互联使用 xray Reality + TLS

用户重新评估后认为：
- **公网互联部分（节点间跨墙通信）应该用 xray 的 Reality 协议**
- Reality 的 TLS 伪装比 MeshDesk 自己的 padded/websocket 混淆更强
- GFW 主动探测时看到的是访问真实网站，无法区分
- 内网 mesh 通信继续用 WireGuard（已经加密了，不需要额外混淆）

架构调整：
```
内网 mesh: WireGuard (gVisor netstack, obfuscation=none)
跨墙互联: xray Reality (TLS 伪装, 替代 padded/websocket 混淆)
用户入口: SS/xray → CF Tunnel → 入口节点 (保持不变)
```

这意味着 MeshDesk 的 obfuscation shim（padded/websocket 模式）在公网互联场景下可以被 xray Reality 替代。obfuscation shim 仍然保留作为 fallback，但主力方案切换到 Reality。

需要团队讨论：
1. xray-core 嵌入 vs 子进程管理？
2. Reality 配置如何集成到 MeshDesk config.yaml？
3. Dashboard x-ui 面板的 API 设计
4. 一键配置的工作流
