# MeshDesk

**去中心化服务器 Mesh——VPN + 监控 + WebSSH + SOCKS5 代理 + TUN 虚拟网络，单个 Go 二进制。**

[English](./README.md) | [发布记录](docs/RELEASE_NOTES.md) | [依赖树](docs/DEPENDENCY_TREE.md)

> **当前版本: v1.6.5** —— META 收集者发现（中继节点自动向 dashboard 上报）、ARQ 窗口 128（300kbps 打洞吞吐）、推送到所有 collectors、打洞从 config peers 自启动、shutdownCh 竞态修复。

---

## 为什么用 MeshDesk？

管理多台服务器通常要跑 Nezha（监控）+ EasyTier/WireGuard（组网）+ 代理工具——三个进程、三份配置。MeshDesk 一个二进制全搞定：

| 功能 | Nezha | EasyTier | WireGuard | MeshDesk |
|------|:-----:|:--------:|:---------:|:--------:|
| 服务器监控 | ✅ | — | — | ✅ |
| Mesh VPN / TUN | — | ✅ | ✅ | ✅ |
| **NAT 打洞** | — | ✅ | — | ✅ |
| WebSSH | ✅ | — | — | ✅ |
| SOCKS5 代理 | — | — | — | ✅ |
| 一键入网 | — | — | — | ✅ |
| 抗 DPI（Reality TLS） | — | — | — | ✅ |
| 单二进制 | — | ✅ | — | ✅ |
| Dashboard 配置 | — | — | — | ✅ |

### 核心设计

- **Reality TLS** —— 所有 mesh 流量伪装成访问真实网站（如 `www.apple.com:443`）的 HTTPS，DPI 无法区分。不用 WireGuard、不用 KCP、无特征 UDP 模式。
- **单端口** —— 所有 mesh 流量跑在一个 TCP+UDP 端口（默认 52888）。MuxTransport 按首字节分流 Reality TLS / mesh smux / SOCKS5 / memberlist gossip。Dashboard **刻意不在此端口提供服务**（抗指纹）：打到 mesh 端口的 HTTP 探测会被转发到 Reality 伪装站点。Dashboard 监听独立的 web 端口（`node.web`，默认 `:8080`）。
- **独立打洞引擎**（`internal/holepunch`，v1.6）—— 脱离 memberlist、对标 EasyTier：
  - 协调走专用虚拟端口 `0x504A`（复用现有 smux/relay 会话——无需中心打洞服务器）
  - UDP 双向打洞（nonce 验证洞，v4 + v6）
  - TCP 打洞（conntrack 源端口交换 + 持续 SYN——状态化安全组放行 ESTABLISHED）
  - **对称 NAT 端口预测**（NAT4E）：STUN 第三次探测检测可预测端口增量；锥型侧扫 50 端口窗口（生日攻击，EasyTier 同款）
  - UDP ARQ 帧分片（<60B）——扛住丢大包的受限链路；流隔离（`|in`/`|out`）保证双向 key exchange 不混淆
  - **自适应 RTO**（RFC 6298 SRTT/RTTVAR）——抖动 WAN 链路上重传不失控，空闲期 session 不掉
  - 洞直接接入 TUN UDP 多路径；relay 兜底保留
  - **生产级稳定已验证**（v1.6.3）：txcloud↔Oracle 双向 0% 丢包 @ ~270ms，空闲 100+ 分钟零掉线
- **端口策略分离**（v1.6.3）：普通节点（NAT 后、无公网入站）UDP 用**随机独立端口**（`UDPPort=-1`，v4/v6 各随机）——绕开 Go 运行时"UDP socket 与 TCP listener 或其他 family 同端口时公网发送静默失败"的坑；共享节点保留**单端口复用**（mesh 端口上一个 `[::]` 双栈 socket）——一条防火墙规则、Reality 伪装不变。打洞协调交换真实端口，无需固定 UDP 端口。
- **零第三方 TUN** —— 裸 `/dev/net/tun` syscall 创建 TUN 设备（~150 行）。无 wireguard-go、无 gVisor、无外部依赖。
- **确定性 IPAM** —— 虚拟 IP = `cidr_base + (pubkey_hash % host_count)`。无 DHCP、无协调、零冲突。
- **响应式中继兜底** —— 直连不通（或链路丢大包）时，按 RTT 排序的 gossip relay 候选自动接管；工作路径缓存 60s（v1.6 CPU 修复——monitor 不再全量重扫）。见[设计决策](docs/DESIGN_DECISION_NO_GLOBAL_ROUTING.md)。
- **自进化** —— 基于 Agora 多智能体框架构建，AI 团队自主实现、测试、审查、部署。

---

## 快速开始

### 1. 构建

```bash
go build -trimpath -ldflags "-s -w" -o meshdesk ./cmd/meshdesk
```

### 2. 共享节点（公网可达、接受入站、`reality.enabled: true`）

```yaml
# /etc/meshdesk/config.yaml
p2p:
    enabled: true
    advertise_endpoints:
        - 1.2.3.4:52888          # 公网 IPv4
        - '[2409:...]:52888'      # 公网 IPv6（可选）
mesh:
    port: 52888
reality:
    enabled: true
    listen_port: 52888
    dest: www.microsoft.com:443
    server_names: [www.microsoft.com]
    private_key: <生成的私钥>
```

### 3. 普通节点（仅出站、`reality.enabled: false`）

```yaml
p2p:
    enabled: true
    seeds:
        - 1.2.3.4:52888
    advertise_endpoints:          # 帮助打洞
        - 6.7.8.9:52888
peers:
    - public_key: <共享节点公钥>
      endpoint: 1.2.3.4:52888
      zone: cn
      reality:
        server_name: www.microsoft.com
        public_key: <共享节点 reality 公钥>
        short_id: 0123456789abcdef
        tls_fingerprint: chrome
mesh:
    port: 52888
    virtual_ip: 10.100.0.3
```

### 4. 运行

```bash
sudo ./meshdesk --web --config /etc/meshdesk/config.yaml
# dashboard: http://localhost:8080  （node.web 端口——不是 mesh 端口）
```

同 zone 且互可达的节点**自动打洞直连**（UDP/TCP）；其余走 relay——无需手动配置路径。

---

## 文档

| 文档 | 内容 |
|------|------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | 总体设计、分层、数据面 |
| [DEPENDENCY_TREE.md](docs/DEPENDENCY_TREE.md) | 外部 + 内部 + 运行时依赖树 |
| [DESIGN_V16_SPLIT_AND_HOLEPUNCH.md](docs/DESIGN_V16_SPLIT_AND_HOLEPUNCH.md) | v1.6 拆分 + 打洞引擎设计与实现状态 |
| [RELAY_DEPLOYMENT_GUIDE.md](docs/RELAY_DEPLOYMENT_GUIDE.md) | 中继节点部署 |
| [ZONE_AWARE_TRANSPORT.md](docs/ZONE_AWARE_TRANSPORT.md) | Zone 感知路由规则 |
| [JOIN_GUIDE.md](docs/JOIN_GUIDE.md) | 一键入网 |
| [SOCKS5_PROXY_GUIDE.md](docs/SOCKS5_PROXY_GUIDE.md) | 代理入口/出口配置 |
| [ACL_GUIDE_v1.1.md](docs/ACL_GUIDE_v1.1.md) | 节点间访问控制 |
| [SYSTEMD_DEPLOY_GUIDE_v1.1.md](docs/SYSTEMD_DEPLOY_GUIDE_v1.1.md) | systemd 服务部署 |
| [RELEASE_NOTES.md](docs/RELEASE_NOTES.md) | 版本历史 |

---

## v1.6 架构一览

```
┌─ cmd/meshdesk（flags/子命令）
├─ internal/app        组合根——三段式 Build → wire → Start/Stop
├─ internal/holepunch  NAT 打洞引擎（Dialer 接口——不 import mesh）
├─ internal/mesh       MeshNode：单端口 mux、UDP ARQ、relay、TUN 数据面
├─ internal/session    X25519 + Ed25519 密钥交换
├─ internal/crypto     AES-256-GCM SecureConn
├─ internal/handshake  Reality TLS
└─ internal/...        config / identity / p2p / tun / web / webssh / dns / proxy / monitor / join
```

完整依赖树见 [DEPENDENCY_TREE.md](docs/DEPENDENCY_TREE.md)。

---

## 许可证

开源项目。基于 Agora 多智能体框架构建——AI 团队自主实现、测试、审查、部署功能。
