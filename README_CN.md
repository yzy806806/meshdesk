# MeshDesk

**去中心化服务器 mesh 网络 + 监控 + WebSSH + SOCKS5 代理 — 单一二进制。**

[English](./README.md)

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
curl -sSL http://dashboard:8080/join?token=xxx | sudo sh
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
| 0x4D | mesh-internal | — | smux session 建立 |
| 0x53 | SOCKS5 入口 | 0x5350 | 手机/客户端代理入口 |
| 0x45 | SOCKS5 出口 | 0x4558 | 出口节点处理 |
| 0x52 | smux 中继 | 0x524C | 跨网络路由 |
| 其他 | gossip | — | memberlist TCP push/pull |

### 节点类型

- **共享节点**（`reality.enabled: true`）：监听 52888 TCP+UDP，唯一暴露公网端口的节点
- **普通节点**（`reality.enabled: false`）：不监听 TCP，仅 UDP gossip，出站连接共享节点

### 监控自动路由

- Dashboard 节点通过 gossip 广播 collector 身份
- 其他节点自动发现 collector 并推送监控数据
- Aggregator 之间互相转发（`Forwarded` 标志 + `SourceID+Sequence` 去重防循环）
- `peers.cache` 持久化发现的 endpoint 和 collector 信息
- `identity.pem` 持久化 Ed25519 身份（重启后 public key 不变）

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

## License

MIT
