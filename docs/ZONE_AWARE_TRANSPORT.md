# Zone-Aware Transport（区域感知传输）

**版本:** 1.0
**最后更新:** 2026-08-11（v1.5.8）

## 概述

MeshDesk 节点可携带一个**自由字符串 zone 标签**（如 `cn`、`us`、`uk`，任何值都行）。
传输策略由 zone 决定：

| 对端 zone | 数据面 | 会话/打洞 |
|-----------|--------|-----------|
| **同 zone**（值相等且非空） | UDP 多路径（快） | UDP 直连 / 0x4D / NAT 打洞 |
| **跨 zone**（值不同） | Reality TLS only | Reality（不 0x4D、不打洞） |
| **未知**（空 / 未标） | Reality TLS only（保守） | Reality / 中继 |

**设计意图**：同 zone = 同侧网络（如都墙内），UDP P2P 快且无检测压力；
跨 zone = 过墙（如墙内 ↔ 海外），必须 Reality TLS 伪装——**UDP 过墙会被
QoS 限速且特征可识别，是明确禁止的**。未知 zone 保守走 Reality（Reality
在墙内也能用，只是稍慢；UDP 过墙才是真风险）。

## 配置

```yaml
# 本节点 zone（自由字符串）
mesh:
  zone: cn

# peer zone（可选——不标则视为未知 → 保守 Reality）
peers:
  - public_key: 0d4bf4b15779008ce29072f0447697b0030e1d113bfc068593db228358ad7c0f
    endpoint: 115.29.235.24:52888
    zone: cn          # 同 zone → UDP P2P
  - public_key: 7eb1844e0077f35003cae62b2b2267968aa8fd11696869055d60670ba1e55921
    endpoint: 161.118.141.101:52888
    zone: us          # 跨 zone → Reality only
```

**建议**：所有节点配 `mesh.zone`，静态 peers 配 `zone`。gossip 会广播 zone
（NodeMeta.Zone），新节点入网后其他节点自动学到它的 zone。

## 拓扑可视化（Dashboard 3D）

浏览器打开 `http://<node>:8080/topology`（或经 CF Tunnel）：

- **节点环色 = zone**（同 zone 同色环；标签显示 `hostname [zone]`）
- **连线颜色 = 传输方式**：
  - 🟢 绿色 = Reality TLS（跨 zone——过墙线一目了然）
  - 🔵 蓝色 = UDP p2p（同 zone 直连）
  - 🟡 黄色 = 0x4D 直连
  - ⚪ 灰色 = 中继
- **悬停连线**：显示 transport / ping（ms）/ 带宽（Mbps）
- **悬停节点**：显示 zone / role / status / CPU / Mem

后端数据：`GET /api/topology`（含 `zone`、`transport`、`latency_ms`、`bandwidth_mbps`）。

## 实现要点

- 判定函数：`MeshNode.SameZone(peerKey)`（config peer zone 优先，gossip 兜底）
- 策略落点：
  1. `tun-forwarder.getUDPStream` —— 跨/未知 zone 直接跳过 UDP（走 Reality TCP）
  2. NAT 打洞 —— 跨/未知 zone 不发起
  3. auto-connect（0x4D）—— 跨/未知 zone 不自动拨（等 Reality 会话/手动 AddPeer）
- 传输追踪：每 peer 会话建立方式（reality / 0x4d / udp）供拓扑展示

## 运维注意

- **所有节点二进制版本必须一致**（混合版本会断数据面）
- 改 config 用文本编辑精确改（**禁止 yaml 全量重写**——会丢字段）
- zone 标签可随时改（改后重启生效）
