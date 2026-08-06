# MeshDesk

**去中心化服务器 mesh 网络 + 监控 + WebSSH + SOCKS5 代理 — 单一二进制。**

[English](./README.md) | [发布说明](docs/RELEASE_NOTES.md)

> **当前版本: v1.2.1** (`a83c9f8`, 2026-08-06) + 补丁 `fef481a` (2026-08-07) — 12 项新功能：systemd 集成、version 命令、日志轮转、配置校验、Mesh DNS、流量统计、告警 UI、信号处理、配置热重载、CI 流水线、单端口 HTTP 复用、端口 52888 上的 /api/join 入网。详见[发布说明](docs/RELEASE_NOTES.md)和[已知问题](https://github.com/yzy806806/meshdesk/issues/1)。

---

## MeshDesk 是什么？

MeshDesk 将五个工具合为一体：

1. **Mesh VPN** — P2P 去中心化网络互联，不依赖 EasyTier
2. **服务器监控** — CPU、内存、磁盘、网络、服务状态
3. **Web 终端** — 浏览器直接 SSH
4. **SOCKS5 代理** — Reality TLS + smux 中继到出口节点，标准 SOCKS5 客户端
5. **Dashboard** — 全功能节点管理、一键入网、配置编辑、代理控制

每个节点运行同一个二进制。任意节点加 `--web` 即可成为控制面板。

### 为什么不用 Nezha + EasyTier？

| | Nezha | EasyTier | MeshDesk |
|---|---|---|---|
| 服务器监控 | ✅ | ❌ | ✅ |
| Mesh VPN | ❌ | ✅ | ✅ |
| WebSSH | ✅ | ❌ | ✅ |
| 单一二进制 | ❌ | ✅ | ✅ |
| 一键入网 | ❌ | ❌ | ✅ |
| Dashboard 配置管理 | ❌ | ❌ | ✅ |
| SOCKS5 代理 | ❌ | ❌ | ✅ |

## 快速开始

### 共享节点（有公网端口）

```bash
meshdesk gen-identity > /etc/meshdesk/identity.pem
meshdesk gen-reality > keys.txt

# 配置文件见 README.md
meshdesk --web --config /etc/meshdesk/config.yaml
```

### 普通节点（不暴露端口）

seed 指向共享节点即可：

```yaml
p2p:
  enabled: true
  seeds:
    - "共享节点IP:52888"
  gossip_probe_interval: 5
reality:
  enabled: false
```

### 一键入网（从 Dashboard）

1. 打开 Dashboard → **Join** 页面
2. 点击"生成安装命令"
3. 复制命令到新节点 SSH 执行：

```bash
# 传统 Web 端口（8080）
curl -sSL http://dashboard:8080/join?token=xxx | sudo sh

# 单端口路径（52888）— v1.2.1+
curl -sSL http://dashboard:52888/join?token=xxx | sudo sh
```

程序化入网可使用 `/api/join` 端点（POST），支持质询-响应认证，两种端口均可：

```bash
curl -X POST http://dashboard:52888/api/join \
  -H "Content-Type: application/json" \
  -d '{"token":"xxx","joiner_pubkey":"..."}'
```

自动下载二进制、生成 identity、写入配置、加入集群。

## 架构

### 协议栈

```
Layer 4 — MeshNode（gossip、WebSSH、文件传输、SOCKS5、代理）
Layer 3 — smux 多路复用（所有流量共用一条加密连接）
Layer 2b — AES-256-GCM 加密
Layer 2a — X25519 ECDH 密钥交换
Layer 1 — Reality TLS 握手（端口 52888，伪装 HTTPS 流量）
Layer 0 — Ed25519 身份（PEM 文件持久化）
```

### MuxTransport 单端口复用

端口 52888 通过首字节嗅探分流所有协议：

| 首字节 | 协议 | 虚拟端口 | 说明 |
|--------|------|----------|------|
| 0x16 | Reality TLS | — | TLS ClientHello，加密 mesh 流量 |
| 0x47/0x50/0x48 | HTTP | — | GET/POST/HEAD — Dashboard、入网服务（v1.2.1+） |
| 0x4D | mesh-internal | — | smux session 建立 |
| 0x53 | SOCKS5 入口 | 0x5350 | 手机/客户端代理入口 |
| 0x45 | SOCKS5 出口 | 0x4558 | 出口节点处理 |
| 0x52 | smux 中继 | 0x524C | 跨网络路由 |
| 其他 | gossip | — | memberlist TCP push/pull |

### 节点类型

- **共享节点**（`reality.enabled: true`）：监听 52888 TCP+UDP，唯一暴露公网端口的节点
- **普通节点**（`reality.enabled: false`）：不监听 TCP，仅 UDP gossip，出站连接共享节点

### 反应式中继回退

当两个节点无法直连时，per-pair `NatSession` 状态机自动尝试替代路径（STUN→DirectProbe→RelayFallback），从 gossip 广播的 `CapRelay` 元数据中按 RTT 择优选择中继节点。无需全局路由表，无需手动配置路径。单跳中继（A→relay→B）覆盖四节点拓扑；多跳中继（A→R1→R2→B）列为后续阶段 backlog。详见[设计决策](docs/DESIGN_DECISION_NO_GLOBAL_ROUTING.md)。

### 监控自动路由

- Dashboard 节点通过 gossip 广播 collector 身份
- 其他节点自动发现 collector 并推送监控数据
- Aggregator 之间互相转发（`Forwarded` 标志 + `SourceID+Sequence` 去重防循环）
- `peers.cache` 持久化发现的 endpoint 和 collector 信息
- `identity.pem` 持久化 Ed25519 身份（重启后 public key 不变）

## TUN 虚拟网络

MeshDesk 可以创建 TUN 虚拟网络接口，提供跨 mesh 的 Layer 3 IP 路由。启用 TUN 后，节点之间可以通过虚拟 IP 互相 ping，通过 mesh SSH 登录，以及通过子网代理访问远程子网。

### 配置

```yaml
mesh:
  tun_enabled: true
  mesh_cidr: "10.144.144.0/24"
  subnet_proxy:
    - "172.26.0.0/18"
  tun_name: "mesh0"     # 可选，默认 mesh0
  tun_mtu: 1400         # 可选，默认 1400
```

| 字段 | 类型 | 默认值 | 说明 |
|-------|------|---------|------|
| `tun_enabled` | bool | `false` | 启动时创建 TUN 设备。需要 `CAP_NET_ADMIN` 或 root 权限。 |
| `mesh_cidr` | string | — | TUN 网络的 CIDR 子网。每个节点的虚拟 IP 从此范围中分配。 |
| `subnet_proxy` | []string | — | 本节点宣告可达的本地 CIDR 子网。其他节点会自动添加经由本节点虚拟 IP 的内核路由。 |
| `tun_name` | string | `mesh0` | TUN 接口名称。 |
| `tun_mtu` | int | `1400` | TUN 接口 MTU。设低于 1500 以抵消 mesh 传输层的封装开销。 |
| `static_virtual_ip` | string | — | 强制指定虚拟 IP，不使用 IPAM 分配。必须在 `mesh_cidr` 范围内。 |

### 工作原理

1. **IPAM**：当 `tun_enabled` 为 true 时，每个节点从 `mesh_cidr` 中确定性分配一个虚拟 IP。
2. **路由**：每个节点维护通过 TUN 接口到达各 peer 虚拟 IP 的内核路由。路由表通过 gossip 在 peer 加入和离开时同步更新。
3. **转发**：发往 peer 的 IP 包从 TUN 设备读取后，封装并通过 mesh 传输层（Reality TLS + smux）发送。
4. **子网代理**：配置了 `subnet_proxy` 的节点通过 gossip 宣告其本地子网。Peer 节点自动安装到达这些子网的内核路由，实现对 mesh 网关后方设备的跨网络访问。

### 支持的功能

- **直接 ping**：`ping 10.144.144.2` 通过虚拟 IP 到达另一个 mesh 节点
- **Mesh SSH**：`ssh user@10.144.144.2` 通过加密 mesh 隧道
- **子网访问**：通过配置了 `subnet_proxy` 的 mesh 网关节点访问远程局域网内的设备

## Dashboard

| 页面 | 路径 | 说明 |
|------|------|------|
| 拓扑 | `/topology` | 3D mesh 拓扑，节点状态 |
| 监控 | `/` | 所有节点 CPU/内存/负载 |
| 配置 | `/config` | 编辑所有节点设置（4 级权限） |
| 入网 | `/join` | 生成一键安装命令 |
| 代理 | `/proxy` | SOCKS5 代理状态、入口/出口配置 |
| 节点 | `/nodes` | 节点列表和详情 |
| Peers | `/peers` | 已知 peer 管理 |
| 文件 | `/files` | 文件传输 |
| 终端 | `/terminal` | WebSSH |
| 服务 | `/services` | 远程服务管理 |

## SOCKS5 代理

手机 → 共享节点:52888 → Reality TLS → SOCKS5 (0x5350) → mesh 中继 (0x524C) → 出口节点 (0x4558) → 互联网

- 使用任意标准 SOCKS5 客户端（不需要 VLESS/xray）
- 多路径中继 + 自动 failover
- 出口节点控制允许端口（默认：80, 443）

## 编译

```bash
go build -o meshdesk ./cmd/meshdesk/
GOOS=linux GOARCH=arm64 go build -o meshdesk-arm64 ./cmd/meshdesk/
```

## 文档

- [架构](docs/ARCHITECTURE.md)
- [发布说明](docs/RELEASE_NOTES.md)
- [入网指南](docs/JOIN_GUIDE.md)
- [SOCKS5 代理指南](docs/SOCKS5_PROXY_GUIDE.md)
- [配置清单](docs/CONFIG_INVENTORY.md)
- [代理设计](docs/PROXY_DESIGN.md)
- [前端](docs/FRONTEND.md)
- [威胁模型](THREAT_MODEL.md)
- [设计决策：不建全局路由表](docs/DESIGN_DECISION_NO_GLOBAL_ROUTING.md)
- [中继部署指南](docs/RELAY_DEPLOYMENT.md)

## License

MIT
