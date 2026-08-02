# MeshDesk v2 设计文档 — 自研核心协议 + 全功能 Dashboard

**Date:** 2026-07-27
**Status:** Approved by user — proceed with full rewrite
**Decision:** 砍掉 WireGuard/gVisor/mesh IP，自研全新 mesh 协议

---

## 核心决策

1. **砍掉 WireGuard (wireguard-go)** — 所有 endpoint/握手/路由问题的根源
2. **砍掉 gVisor netstack** — 只为 WireGuard 提供虚拟 IP，不需要
3. **砍掉 obfuscatingBind (none/padded/websocket)** — 只保留 Reality
4. **砍掉 mesh IP (deriveMeshIP + routing table)** — 用 peer ID + smux
5. **自研全新协议** — Reality TLS 握手 + TCP/UDP 双传输 + AES-GCM 加密
6. **任意节点可当入口/出口/中继** — 角色动态，不写死
7. **智能选路** — 延迟+带宽+连通性自动评分，多路径分散2条
8. **Dashboard 远程管理所有节点** — 配置/代理/分流远程下发
9. **WebSSH + 文件管理是核心功能** — 走 smux stream，不依赖虚拟 IP
10. **CF Tunnel 部署** — 用户侧部署，不增加代码

## 架构

```
┌─────────────────────────────────────────────────────┐
│                 Dashboard (任意节点:18080)             │
│  概览│终端│文件│节点│代理管理│配置│监控               │
│  (远程管理所有节点, 远程配置入口/出口/分流)            │
├─────────────────────────────────────────────────────┤
│              HTTP API + RPC Layer                     │
├─────────────────────────────────────────────────────┤
│              Mesh Services (内置)                     │
│  WebSSH │ 文件传输 │ 监控采集 │ RPC(远程配置) │ 代理转发│
├─────────────────────────────────────────────────────┤
│              smux 多路复用                            │
├─────────────────────────────────────────────────────┤
│              智能选路 (自动)                          │
│  入口→选最快2条→出口 │ 延迟+带宽+连通性评分           │
│  多路径分散 │ relay fallback                         │
├─────────────────────────────────────────────────────┤
│              PeerManager                             │
│  TCP/UDP自动切换 │ NAT打洞 │ 自动重连                 │
├─────────────────────────────────────────────────────┤
│              自研协议                                 │
│  握手: Reality TLS (伪装大站)                        │
│  TCP: TLS 1.3 加密                                  │
│  UDP: QUIC 伪装 + AES-GCM                           │
├─────────────────────────────────────────────────────┤
│              Gossip 发现                              │
│  peer ID + endpoints + 延迟 + 带宽 + 出口能力         │
└─────────────────────────────────────────────────────┘

没有 WireGuard
没有 gVisor
没有虚拟 IP
没有 mesh port
```

## 自研协议设计

### 握手 (TCP, Reality TLS)

1. Client → Server:443 发 TLS ClientHello (SNI=www.apple.com)
2. Server 代理到真实 apple.com → 获取真实 ServerHello + 证书
3. Server 在证书中注入 HMAC 认证 (X25519 + shortId)
4. Client 验证 HMAC → 共享会话密钥协商完成
5. 如果验证失败 (GFW 探测) → 转发给真实 apple.com → 探测看到真实响应

### 数据传输

握手完成后，会话密钥用于加密所有后续数据。

**TCP 模式 (Reality TLS):**
- 数据在 TLS record 里传输
- GFW 看到的是访问 apple.com 的 TLS 1.3 流量
- 适合跨墙场景

**UDP 模式 (QUIC 伪装):**
- 同一会话密钥加密
- UDP 包头伪装成 QUIC Short Header
- GFW 看到的是 HTTP/3 QUIC 流量
- 适合墙内节点间直连，延迟更低带宽更高
- 支持 UDP NAT 打洞

**自动切换:**
- 默认 TCP (握手后保持)
- 如果双方 endpoint 可达 → 尝试 UDP 直连
- UDP 不通 → 继续 TCP
- UDP 被干扰 → 切回 TCP
- TCP 断了 → 快速重连

### 加密

```
握手: Reality TLS (ECDH 协商 session_key)
数据: nonce(8B) + ciphertext(AES-256-GCM) + tag(16B)
TCP: 封装在 TLS record (标准 TLS 流量)
UDP: 封装成 QUIC Short Header (标准 QUIC 流量)
```

不用 WireGuard 的 Noise IK，不用 wireguard-go。完全自研，完全可控。

### NAT 穿透

**TCP 打洞:**
- 共享节点协调，双方同时向对方发 SYN
- 利用 SO_REUSEPORT + 同步时序
- 成功率 ~60% (对称 NAT 失败)

**UDP 打洞:**
- 共享节点协调，双方同时向对方发 UDP
- 成功率更高 (~80%)
- 打洞成功后切换到 UDP 模式

**失败 fallback:**
- 走共享节点 relay (io.Copy 两个连接)

## 节点角色

所有角色动态，不写死：

| 角色 | 说明 | 何时充当 |
|------|------|---------|
| 入口 | 接收用户代理请求 | 配置了 inbound 监听 |
| 出口 | 连目标网站 | exit.enabled=true 且目标可达 |
| 中继 | 转发流量 | 两节点间直连不通时 |
| 共享节点 | 帮助发现+relay | 配置了 listen + 有公网IP |
| Dashboard | 管理面板 | --web 标志 |

### 智能选路

```go
// 入口节点收到代理请求，选出口
func selectExit(target string) []Path {
    // 1. 查全网节点状态 (gossip 同步)
    candidates := []
    for node in gossip.AllNodes() {
        if node.IsExit() && node.CanReach(target) {
            candidates.append(Path{
                Via: node,
                Latency: node.LatencyTo(target),
                Bandwidth: node.AvailableBandwidth,
                Score: computeScore(node),
            })
        }
    }
    // 2. 按延迟×带宽评分排序
    sort(candidates)
    // 3. 选最快的2条
    return candidates[:min(2, len(candidates))]
}
```

## Dashboard

### 功能模块

```
Dashboard
├── 概览 (Overview)
│   ├── 全网拓扑 (anime.js 3D动画)
│   ├── 节点状态卡片 (角色/延迟/带宽/流量)
│   └── 实时选路可视化
│
├── 终端 (WebSSH) ← 核心功能
│   ├── xterm.js 终端
│   ├── 选目标节点 → 开终端
│   ├── 多标签页
│   └── smux stream 传输
│
├── 文件管理 (Files) ← 核心功能
│   ├── 远程文件浏览器
│   ├── 上传/下载/预览
│   └── smux stream 分块传输
│
├── 节点管理 (Nodes)
│   ├── 添加/删除节点
│   ├── 编辑 peer 配置
│   └── 连接状态查看
│
├── 代理管理 (Proxy)
│   ├── 远程配置入口节点 (SOCKS5/Reality)
│   ├── 分流规则
│   ├── 选路策略 (自动/手动)
│   ├── SOCKS5 客户端配置
│   └── 流量统计
│
├── 配置 (Config)
│   ├── Reality 设置
│   ├── 传输设置
│   ├── 出口设置
│   └── 热重载
│
└── 监控 (Monitor)
    ├── CPU/内存/磁盘/网络
    ├── 连接质量
    └── 告警
```

### WebSSH 实现

```
浏览器 → WebSocket → Dashboard → smux stream("ssh") → 远端 meshdesk → 本地 SSH
```

不需要虚拟 IP，不需要 mesh port。一切走 smux stream。

### 文件管理实现

```
列目录: GET /api/files/list?peer=node1&path=/root
下载:   GET /api/files/download?peer=node1&path=/root/file.tar.gz
上传:   POST /api/files/upload?peer=node1&path=/root/
预览:   GET /api/files/preview?peer=node1&path=/root/config.yaml
```

全部通过 smux stream 传输，分块+断点续传。

### 远程配置入口节点

```
Dashboard(AMD1) → smux stream("rpc") → N1
RPC: { cmd: "enable_socks5", port: 77, exit: "exit-node-hostname" }
N1 执行 → 返回结果 → Dashboard 更新 UI
```

## 配置 (简化)

```yaml
node:
  identity: "private-key-hex"
  hostname: "node1"
  listen: ":443"          # 有公网IP的监听，NAT后的留空

reality:
  dest: "www.apple.com:443"
  server_names: ["www.apple.com"]
  private_key: "..."
  short_ids: ["..."]

udp:
  port: 51820             # UDP 打洞端口

peers:
  - endpoint: "1.2.3.4:443"  # 共享节点或已知peer
    public_key: "..."

exit:
  enabled: true
  allowed_ports: [80, 443]

web:
  port: 18080
  users:
    - username: admin
      password_hash: "..."
```

6 个区块。WebSSH、文件传输、监控不需要单独配置——内置 smux 服务。

## 可复用的已有代码

| 组件 | 代码量 | 复用方式 |
|------|--------|---------|
| Reality TLS Transport | 841 行 | 直接复用 (cert fix 已提交) |
| PeerManager | 1273 行 | 简化：去掉 WG 依赖，只管 TLS/UDP 连接 |
| Dashboard config API | ~3000 行 | 复用 + 扩展 RPC |
| SOCKS5 代理管理 | ~800 行 | 新增 Dashboard UI + smux 虚拟端口监听 |
| anime.js + anim.js | ✅ | 直接复用 |
| gossip 发现 | ~800 行 | 简化：去掉 mesh IP 依赖 |

## 需要新写的

| 组件 | 行数(估) | 说明 |
|------|----------|------|
| smux 多路复用 | ~400 | TLS/UDP 连接上的多流 |
| UDP Transport (QUIC伪装) | ~800 | QUIC header + AES-GCM |
| TCP NAT 打洞 | ~300 | 共享节点协调 |
| UDP NAT 打洞 | ~400 | 共享节点协调 |
| Relay 转发 | ~200 | io.Copy |
| 智能选路 | ~300 | 延迟+带宽+连通性评分 |
| RPC 远程配置 | ~300 | 入口/出口/分流远程下发 |
| WebSSH (smux版) | ~200 | xterm.js + WebSocket + smux |
| 文件管理 (smux版) | ~400 | 浏览/上传/下载/预览 |
| gossip 简化 | ~300 | 去掉 mesh IP |
| 砍旧代码 | -8000 | WireGuard/gVisor/obfuscatingBind 等 |

总计约 3700 行新代码 + 复用 ~10000 行。

## 开发 Phase

| Phase | 内容 | 依赖 |
|-------|------|------|
| 1 | 砍旧代码，清理依赖 | 无 |
| 2 | 自研协议核心 (握手+加密+TCP/UDP) | Phase 1 |
| 3 | smux 多路复用 | Phase 2 |
| 4 | gossip 发现 + endpoint 传播 | Phase 2 |
| 5 | NAT 打洞 (TCP+UDP) + relay | Phase 2+4 |
| 6 | PeerManager (选路+多路径) | Phase 3+5 |
| 7 | WebSSH + 文件管理 (smux) | Phase 3+6 |
| 8 | Dashboard 重构 (远程配置+RPC) | Phase 6+7 |
| 9 | SOCKS5 代理管理 (远程配置入口) | Phase 8 |
| 10 | 实机测试 (全功能覆盖) | 全部 |

## 测试要求

**严格测试，所有功能必须可用：**

1. 阿里云当共享节点 (有公网IP, 监听 443)
2. ARM/AMD1/AMD2 当普通节点 (0端口, 主动连出)
3. 所有功能必须实测通过：
   - gossip 发现 + endpoint 传播
   - TCP 直连 + UDP 打洞
   - Reality TLS 握手
   - WebSSH (从 Dashboard 远程连任意节点)
   - 文件管理 (上传/下载/浏览)
   - Dashboard 配置管理 + 热重载
   - 代理入口 (SOCKS5 + Reality)
   - 智能选路 (多路径分散)
   - anime.js 动画
   - 监控数据上报

** tester 质量要求：**
- 不能只看单元测试通过就标记通过
- 必须在真实机器上验证完整功能链路
- 发现的问题必须记录并修复后再标记通过
- 每个功能必须有实际执行截图或日志证据
