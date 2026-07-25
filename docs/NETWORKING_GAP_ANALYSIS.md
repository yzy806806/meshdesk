# MeshDesk P2P 组网差距分析 — 核心功能缺失

**Status:** Critical — 阻塞 stop condition
**Created:** 2026-07-25
**Priority:** P0 — 高于代理功能收尾、3D拓扑、Dashboard打磨

---

## 核心问题

MeshDesk 的 P2P 组网本质是**静态 WireGuard + 混淆层**。混淆层（AmneziaWG padded + WebSocket+utls）做得很好，但 mesh 组网的核心能力——动态发现、NAT穿透、共享节点中继——完全缺失。

**没有这些能力，MeshDesk 不是 mesh VPN，只是一个带混淆的 WireGuard 配置工具。**

---

## 参照：EasyTier 的成熟组网能力

EasyTier 的核心能力（用户实际在用）：

| 能力 | EasyTier 实现 | MeshDesk 现状 |
|------|-------------|-------------|
| 自动节点发现 | Gossip协议，连上一个共享节点就发现全网 | ❌ 纯手动config.yaml配peer |
| NAT穿透 | STUN打洞 + 中继自动选择 | ❌ 没有 |
| 共享/中继节点 | 共享节点暴露端口，普通节点--no-listener连入 | ❌ 没有 |
| 多协议传输 | TCP+UDP+KCP+QUIC，多路并行 | 🟡 UDP(WG原生)+TCP(WebSocket) |
| 漫游/IP变化 | 自动检测+重连 | 🟡 WireGuard原生有限漫游 |
| 拓扑感知 | 全网拓扑+延迟感知+选路 | ❌ 只知道config里的peer |
| 心跳/连接质量 | 多协议心跳+质量感知 | 🟡 WG keepalive(20s) |
| 新节点加入 | 填网络名+密钥即可加入 | ❌ 要在所有节点手动加配置 |

### 用户实际部署模型（EasyTier）

```
共享节点(3个): N1(fn.fxxkccp.top), 阿里云(固定IP), DS716(synology.me)
  暴露端口: 11010-11012 (TCP+UDP)
  帮助普通节点入网

普通节点(5个): ARM, AMD1, AMD2, Dell, 手机
  --no-listener, 主动连共享节点
  连上后自动发现全网, 建立P2P直连
  NAT后的节点通过共享节点中继
```

MeshDesk 现在无法实现这个模型。每个节点必须手动配置所有peer，NAT后的节点无法被访问，新节点加入需要全网改配置。

---

## 需要补的核心件

### 1. Gossip 节点发现协议 (P0)

连上一个节点就能发现全网。mesh TCP 上跑 gossip，交换 peer 列表。

**最小实现：**
- 节点连上任意已知 peer 后，发送 `PEER_LIST` 消息
- 收到 `PEER_LIST` 后更新本地路由表，对新发现的 peer 发起连接
- 定期交换完整 peer 列表（增量 + 全量同步）
- 网络名+密钥作为 mesh 准入凭证（类似 EasyTier 的 network-name + network-secret）

**复用现有代码：**
- routing table 已有 AddPeer/RemovePeer/AllPeers
- mesh TCP Dial 已可用
- 需新增：gossip 消息协议 + peer 交换逻辑 + 自动连接管理器

### 2. NAT 穿透 + 共享节点中继 (P0)

NAT 后的节点（Dell/N1/手机/DS716 在家庭网络 NAT 后）需要通过共享节点中继入网。

**最小实现：**
- 共享节点暴露 1 个 TCP 端口（设计已确定）
- 普通节点不暴露端口，主动连出
- STUN 探测 NAT 类型 + 公网地址
- 同 NAT 的节点直连，不同 NAT 的通过共享节点中继
- WireGuard endpoint 自动更新（漫游）

**复用现有代码：**
- obfuscating bind 已有 WebSocket 模式（TCP）
- 需新增：STUN client + NAT 类型检测 + 中继路由逻辑

### 3. 连接管理器 (P0)

管理多条 peer 连接，自动重连，质量感知。

**最小实现：**
- 心跳：定期 ping/pong，RTT 测量
- 自动重连：连接断开后指数退避重连
- 连接质量：RTT + 丢包率 + 带宽感知
- 路径选择：延迟优先（为代理功能的多路径选路提供基础）

**复用现有代码：**
- routing table 的 peer 列表
- 需新增：connection manager + 心跳协议 + 重连逻辑

### 4. 多协议传输 (P1)

至少 TCP + UDP 并行，可选 KCP/QUIC。

**现状：** WireGuard 原生 UDP + WebSocket TCP 模式已有。但缺少：
- UDP 被 GFW 限速时自动切换到 TCP
- 多路并行（同时 UDP + TCP，选质量更好的）

### 5. 动态配置/自动入网 (P1)

新节点填网络名+密钥即可加入，不需要手动配全网。

**最小实现：**
- `meshdesk join --network <name> --secret <key> <共享节点Endpoint>`
- 自动完成：密钥生成 → 连接共享节点 → gossip发现 → 配置 WireGuard peers
- 现有 `--config` 模式保留给高级用户

### 6. 共享节点 Endpoint 多格式兼容 (P0)

共享节点的 endpoint 必须支持三种格式，跟 EasyTier 一致：

| 格式 | 示例 | 场景 |
|------|------|------|
| **IPv4** | `115.29.235.24:51820` | 固定公网IP节点（如阿里云） |
| **IPv6** | `[240e:360:...]:51820` | IPv6 DDNS节点（如N1 fn.fxxkccp.top → AAAA） |
| **域名** | `yzy806806.synology.me:51820` | DDNS动态域名节点（如DS716） |

**实现要求：**
- endpoint 解析：自动检测 IPv4 / IPv6 / 域名格式
- 域名解析：支持 A + AAAA 记录，优先尝试直连可达的地址族
- IPv6 支持必须贯穿全链路：WireGuard bind、gVisor netstack、STUN、gossip
- 域名定期重新解析：DDNS 节点 IP 会变化，需定期刷新 DNS → 更新 WireGuard endpoint
- 配置文件示例：
  ```yaml
  peers:
    - public_key: "abc..."
      endpoint: "115.29.235.24:51820"        # IPv4
    - public_key: "def..."
      endpoint: "[240e:360:...]:51820"        # IPv6
    - public_key: "ghi..."
      endpoint: "yzy806806.synology.me:51820"  # 域名(DDNS)
  ```

**用户的实际部署场景**（参照 EasyTier）：
- N1: `fn.fxxkccp.top:51820`（域名→IPv6 DDNS，路由器放行端口）
- 阿里云: `115.29.235.24:51820`（固定IPv4）
- DS716: `yzy806806.synology.me:51820`（域名→v4+v6 DDNS）

三种格式必须同时支持，不能只做IPv4。

---

## 实现优先级

| 阶段 | 内容 | 阻塞代理功能？ |
|------|------|--------------|
| **P0-A** | Gossip 发现 + 连接管理器 | ✅ 代理的多路径选路依赖拓扑感知 |
| **P0-B** | NAT穿透 + 共享节点中继 | ✅ NAT后节点无法参与relay |
| **P0-C** | 动态入网(join命令) | 否但影响可用性 |
| P1 | 多协议传输 + 自动切换 | 否，优化项 |

P0-A 和 P0-B 必须在代理功能收尾之前完成——代理的多路径选路依赖拓扑感知，relay 节点需要自动发现。没有这些，代理功能只是空中楼阁。

---

## 对团队的要求

1. **Researcher**: 深入评估 EasyTier 的组网机制（gossip协议、NAT穿透、中继选择、多协议传输），输出技术调研报告
2. **Architect**: 基于 EasyTier 经验和 MeshDesk 现有架构，设计动态组网方案
3. **Developer**: 实现 gossip 发现 + 连接管理器 + NAT穿透 + 共享节点中继
4. **Tester**: 多节点组网测试（模拟 NAT 后节点、共享节点中继、新节点加入）

**核心原则：组网是MeshDesk的根基。混淆和代理是加分项，不是替代品。**
