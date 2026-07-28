# MeshDesk

**去中心化服务器 mesh 网络 + 监控 + WebSSH + 匿名代理 —— 单二进制。**

[English](./README.md)

---

## MeshDesk 是什么？

MeshDesk 将五个工具合为一体：

1. **Mesh VPN** — 服务器之间 P2P 去中心化组网（替代 EasyTier）
2. **服务器监控** — CPU、内存、磁盘、网络、服务状态（替代 Nezha）
3. **Web 终端** — 浏览器直接进终端，无需 SSH 客户端
4. **多路径匿名代理** — 通过中继节点分散流量，抗 GFW 传输
5. **3D 拓扑可视化** — 浏览器中交互式 3D mesh 拓扑

每个节点跑同一个二进制。任意节点加 `--web` 即可成为控制面板。

### 为什么不用 Nezha + EasyTier？

| | Nezha | EasyTier | MeshDesk |
|---|---|---|---|
| 服务器监控 | ✅ | ❌ | ✅ |
| Mesh VPN | ❌ | ✅ | ✅ |
| WebSSH | ✅（通过 agent） | ❌ | ✅（通过 agent） |
| 架构 | 中心化（agent→dashboard） | 去中心化 P2P | 去中心化 P2P |
| 单二进制 | ❌（dashboard + agent） | ✅ | ✅ |
| 文件传输 | ❌ | ❌ | ✅ |
| 网络拓扑可视化 | ❌ | ✅（仅 CLI） | ✅（3D Web UI） |
| 匿名代理 | ❌ | ❌ | ✅ |
| 仪表盘 2FA | ❌ | ❌ | ✅ |

Nezha 有监控和 WebSSH 但没有 mesh 组网——dashboard 挂了就全没了。EasyTier 有 mesh VPN 但没有监控和 web 终端。MeshDesk 一个二进制全搞定。

## 功能

### Mesh VPN 与 P2P 动态组网

- 自研 Mesh 协议栈替代 WireGuard：**L0–L4 分层架构**，Ed25519 身份、Reality TLS 握手、X25519 ECDH 密钥交换、AES-256-GCM 加密、smux 多路复用
- **Gossip v2 发现** — 基于 hashicorp/memberlist，使用标准 `NetTransport`（真实 TCP），不再使用自定义 MeshTransport；无需手动配置 peer
- **NAT 穿透** — 基于 STUN 的公网端点发现 + UDP 打洞，支持中继回退
- **动态加入协议** — 新节点通过 `meshdesk join <bootstrap-addr>` 加入，使用 Ed25519 身份签名认证
- **端点学习** — 节点连接到种子后，种子检测其真实端点并通过 gossip 广播到全网，其他节点可通过学习到的端点直连（参考 EasyTier 的端点学习机制）——参见[端点学习与共享节点中继](#端点学习与共享节点中继)
- **共享节点中继** — 直连失败（如对称 NAT）时，通过 mesh 节点中继流量，支持自动故障切换：选取前 2 个中继候选、每 30 秒健康检查（PING/PONG）、连续 3 次丢 PONG 则切换至备用中继 ——参见[端点学习与共享节点中继](#端点学习与共享节点中继)
- **Reality TLS 传输** — 所有 mesh 流量通过 443 端口的 REALITY TLS 握手劫持，与访问大型网站（如 apple.com）的 HTTPS 流量无异。被动 DPI 看到的是合法 TLS 1.3。主动探测收到的是真实网站响应
- 细粒度节点权限——限制每个节点能访问哪些功能（监控、SSH、文件传输、服务管理）

### 协议栈架构

MeshDesk v2 采用分层协议栈。每层基于下一层构建，层与层之间接口清晰：

```
┌─────────────────────────────────────────────┐
│ L4 — MeshNode（节点编排）                     │
│   串联所有组件：PeerManager、gossip、        │
│   WebSSH、文件传输、代理                     │
├─────────────────────────────────────────────┤
│ L3 — smux 多路复用器                         │
│   单连接上的流多路复用。WebSSH、文件传输、   │
│   RPC、代理流量共享同一加密链路              │
├─────────────────────────────────────────────┤
│ L2b — AES-256-GCM 加密                       │
│   会话密钥加密所有流量。                     │
│   nonce(8B) + ciphertext + tag(16B)         │
├─────────────────────────────────────────────┤
│ L2a — X25519 ECDH 密钥交换                   │
│   临时密钥交换 + Ed25519 签名绑定。          │
│   Ed25519 身份证明拥有 X25519 临时密钥，     │
│   实现会话认证                               │
├─────────────────────────────────────────────┤
│ L1 — Reality TLS 握手                        │
│   加密字节流。ClientHello SNI=目标域名，     │
│   REALITY 认证基于 X25519 ECDH + HKDF。     │
│   返回 net.Conn                              │
├─────────────────────────────────────────────┤
│ L0 — Ed25519 身份                            │
│   永久节点身份。公钥即节点 ID。用于签名      │
│   和 gossip 真实性校验。crypto/ed25519       │
│   （Go 标准库）                              │
└─────────────────────────────────────────────┘
```

**核心设计原则：**

- **传输与身份解耦：** L1（Reality TLS）产出一个原始 `net.Conn`——它不感知 mesh 身份。L2 通过 Ed25519 对 X25519 临时密钥签名，将身份绑定到连接。
- **无虚拟 IP：** v1 使用从 WireGuard 密钥派生的 mesh IP（10.10.x.y）。v2 通过 Ed25519 公钥和真实端点寻址节点。无 TUN 网卡、无 gVisor netstack、无子网路由。
- **smux 多路复用：** 所有服务（WebSSH、文件传输、RPC、代理）通过 smux 流共享单条加密连接。无需为每个服务配置独立端口。

### Gossip v2

Gossip 层发现节点并将元数据传播到全网：

- 使用 hashicorp/memberlist 的标准 `NetTransport`——真实 TCP 通信在 gossip 端口（默认 7946），不再使用 v1 通过 gVisor 隧道的自定义 `MeshTransport`
- 与 Reality TLS 握手端口（443）分离——与 Consul、Serf、Nomad 的模式一致
- `NodeMeta` 携带：Ed25519 公钥、真实端点（host:port）、NAT 类型、能力（relay/exit/entry）、负载指标（CPU、内存、电路数、带宽）和单调递增序列号
- **无 mesh IP**——节点由真实端点寻址。10.10.x.y 子网和 `deriveMeshIP` 已移除
- 端点传播：STUN 探测和 HandshakeLayer 入站连接将端点信息输入 gossip，gossip 全网广播
- 引导使用真实地址：`seeds: ["203.0.113.10:7946"]`，替代 v1 的 `seeds: ["10.10.0.1:7946"]`

### PeerManager

PeerManager 是每个 mesh 节点的连接生命周期管理器。每个节点拥有一个专用 goroutine，监控所有连接状态、处理故障恢复并选择最佳路径。

- **指数退避自动重连** — 连接断开后自动重试，指数退避（30s → 60s → 120s → 240s → 最高 300s）。连接成功后重置定时器
- **多路径回退** — PeerManager 优先尝试 TCP Reality，然后尝试 UDP（QUIC 伪装）直连。直连不通时通过共享节点中继
- **隔离与逃生** — 重复故障的传输被隔离并按指数冷却。全隔离逃生机制（尝试最近隔离的路径）防止永久断连
- **EWMA 延迟追踪** — 分裂系数 EWMA（α_rise=0.7、α_fall=0.3）追踪每条路径的延迟，用于最优路径选择

### 端点学习与共享节点中继

当节点处于 NAT 后时，直连取决于发现彼此的公网端点。MeshDesk 实现了两种互补机制：

**端点学习（EasyTier 风格）**

- NAT 节点连接到种子后，种子的 HandshakeLayer 检测入站 TCP 连接的源端点
- Gossip 层收到通知，更新本节点元数据（`Endpoints` 列表 + 推断出的 NAT 类型），递增序列号 — 触发自动全网广播
- 其他节点通过 gossip 收到更新后的元数据，可尝试以 NAT 节点的公网端点直连
- 内置去重：重复的端点发现不递增序列号，防止 gossip 风暴
- 默认关闭 — 须显式注册通知器。未注册时端点发现零开销

**共享节点中继（多跳）**

- 直连不可行（如双方均为对称 NAT）时，入口节点通过 RTT 加权评分选取前 K=2 个中继候选，发送 `circuit_setup` 消息
- 中继节点接受电路（容量检查），将目标节点身份加入转发表，开始转发流量
- 健康监控：每 30 秒发送 PING；连续 3 次未收到 PONG 则自动切换至备用中继
- 电路生命周期：`circuit_setup` → `circuit_accept` → 流量传输 → `circuit_teardown`（节点离开）或故障切换
- 调和循环：每 30 秒运行一次，检测无电路覆盖的 NAT 节点

**按中继隔离与重试**

- 故障中继隔离 60 秒，指数冷却
- 调和循环在隔离到期后重新探测

### 监控

- 实时 CPU / 内存 / 磁盘 / 网络 / 负载指标
- 指标推送到采集节点，可配置推送间隔
- 每节点环形缓冲区存储（采集节点断连时缓冲数据）
- 仪表盘实时更新（Server-Sent Events）
- 每台服务器的进程列表

### Web 终端

- 浏览器终端（xterm.js + WebSocket）
- 无需 SSH 密钥或密码——agent 以 root 运行
- 多标签、多服务器
- 通过 smux 流走 mesh 传输——无需虚拟 IP

### 文件传输

- 通过 Web UI 上传/下载文件
- Mesh 内部传输走 smux 流——文件经过加密 mesh，不暴露到公网
- 基于权限的访问控制——限制哪些节点可以发送文件以及可访问的路径
- 可配置单文件大小上限和上传目录

### 服务管理

- 启动/停止/重启 systemd 服务
- 查看服务日志
- 按节点授权——只有具备 `service_manage` 权限的节点才能管理服务

### 多路径匿名代理

内置多路径分散传输代理，抗审查互联网访问：

- **Shadowsocks 入口** — 通过 SS AEAD（chacha20-ietf-poly1305）over WebSocket 接收用户流量
- **Cloudflare Tunnel 伪装** — 入口监听通过 `cloudflared` 暴露，提供 TLS 伪装（呈现为 HTTPS）
- **ECDH 电路建立** — 每连接端到端加密，入口与出口节点之间
- **两条不相交中继路径** — 流量分散到两条节点不相交路径，打散流量特征
- **盲中继转发** — 中继节点不解密负载，仅处理洋葱式转发头
- **抗时序分析抖动** — 中继引入 5-50ms 随机延迟，破坏流量关联
- **可插拔分块器** — 固定 16KB 或随机 4KB-64KB 分块大小，带填充
- **出口重组** — 滑动窗口重组，处理乱序、去重、NACK 重传、孤儿清理
- **动态路径选择** — 基于 RTT 自动探测和选择路径（Dijkstra k-最短路径）
- **审计日志** — 出口节点记录电路→目标映射（不含负载数据）

### 仪表盘安全

- **TOTP 2FA** — RFC 6238 基于时间的一次性密码，支持 QR 码注册
- **加密密钥存储** — TOTP 密钥使用节点本地主密钥（AES-256-GCM）加密存储
- **逐步认证** — 敏感操作（终端、服务管理、文件上传、设置）需要近期 2FA 验证
- **安全告警** — 认证拒绝、节点加入/离开、可疑代理活动的实时告警
- **Webhook 推送** — 异步告警推送到外部端点（Slack、Discord、自定义），3 次重试指数退避
- **TOTP 密钥轮换** — 零停机密钥轮换，旧密钥宽限期
- **恢复码** — 注册时生成 10 个一次性恢复码
- **锁定保护** — 5 次 TOTP 验证失败触发 30 秒锁定

### 仪表盘配置管理

`/config` 页面通过分层访问 API 实现全量配置管理，无需 SSH 手动编辑 YAML。

- **全部配置分区** — 渲染 `node`、`mesh`、`reality`、`peers`、`p2p`、`monitoring`、`webssh`、`auth`、`transfer`、`proxy`、`exit`、`web` 的所有字段于单一仪表盘页面
- **分层字段显示** — 字段按四个访问层级分类，控制可见性和可编辑性：
  - **T0（只读）**：显示但拒绝写入（如 `node.hostname`、`peers[N].public_key`、`auth.totp_store_dir`）
  - **T1（掩码）**：GET 响应中显示为 `***`，写入时接受（若发送 `***` 则无操作）— 用于密钥类字段（如 `node.identity`、`reality.private_key`）
  - **T2（二次验证）**：正常显示，写入需 step-up 2FA 令牌 — 用于安全敏感字段（如 `peers[N].capabilities`、`auth.web_users`、`exit.allowed_ports`）
  - **T3（普通）**：正常显示，标准会话认证即可写入 — 其余所有字段
- **脏字段追踪** — 修改后的字段标记为可热重载或需重启。API 响应中的 `_meta.tier_map` 告知客户端哪些字段需要重启
- **PATCH /api/config** — 通过 JSON merge-patch（RFC 7396）部分保存。仅发送变更字段；服务器合并至当前配置、原子写入磁盘并标记脏字段
- **热重载按钮** — `POST /api/config/reload` 无需重启即可应用所有热重载变更。频率限制为每 5 秒一次
- **重启按钮** — `POST /api/config/restart` 触发守护进程重启以应用需重启的字段。需 step-up 认证。频率限制为每 30 秒一次
- **差异查看器** — `GET /api/config/diff` 比较内存中运行配置与磁盘上保存配置

### 3D 拓扑可视化

- 基于 **Three.js** 的交互式 3D 场景，力导向节点布局
- **动画粒子**沿代理电路路径（边）流动
- **实时 SSE 更新** — 拓扑变化实时反映到浏览器
- **按角色着色** 的节点（入口=蓝色，中继=橙色，出口=绿色，仪表盘=紫色）
- **节点悬停标签** 显示角色、CPU、内存、主机名
- **边粗细** 按延迟调节（延迟越低越亮）
- **OrbitControls** 平移/缩放/旋转
- **性能自适应** — 低 FPS 时减少粒子数量
- 无真实 mesh 节点时使用模拟数据

### 功能成熟度

各功能标注了明确的成熟度标签，让你心中有数：

| 功能 | 成熟度 | 说明 |
|---|---|---|
| v2 协议栈（L0–L4） | **测试版** | Ed25519 身份、Reality TLS 握手、X25519 ECDH、AES-256-GCM、smux——功能完整 |
| Gossip v2（NetTransport） | **测试版** | 标准 memberlist TCP 传输；无 mesh IP 依赖 |
| PeerManager | **测试版** | 自动重连、多路径回退、EWMA 延迟追踪 |
| 监控 | **稳定** | 实时指标、推送到采集节点、SSE 仪表盘更新 |
| Web 终端 | **稳定** | xterm.js + WebSocket、多标签、SIGWINCH 支持 |
| 文件传输 | **稳定** | Web UI 上传/下载、基于权限的路径控制 |
| 服务管理 | **稳定** | systemd 服务启停重启、按节点授权 |
| 仪表盘安全（TOTP 2FA） | **稳定** | TOTP 注册、逐步认证、加密密钥存储、Webhook 告警 |
| 多路径匿名代理 | **测试版** | 电路路由功能完整；分块/重组需要实机验证 |
| 端点学习与共享中继 | **测试版** | 端点学习 + NAT 类型推断 + 中继电路及故障切换；gossip 集成测试通过 |
| 仪表盘配置管理 | **测试版** | 分层配置 API、PATCH merge-patch、热重载、差异查看器 — 集成测试通过 |
| 3D 拓扑可视化 | **测试版** | 节点图 + 延迟边完成；电路粒子动画使用模拟数据 |

**成熟度定义：**
- **稳定** — 功能已实现、已通过单元测试、团队已验证。适合生产使用（遵循标准安全策略）。
- **测试版** — 功能完整且通过所有单元测试，但尚未在物理多节点硬件上验证。谨慎使用；发现问题请在 GitHub 上报告。

成熟度标签在实机验收测试通过后从测试版升级为稳定版——不以提交日期为准。

## 安装

**必须 root 运行。** Agent 需要 root 权限用于：

- 监听特权端口（443 用于 Reality TLS，80 用于 Web 等）
- 执行命令（Web 终端）
- 读取系统指标（磁盘、网络、进程）
- 管理 systemd 服务

**无需 TUN 网卡。** MeshDesk v2 不使用 WireGuard 或 gVisor netstack——无需创建虚拟网络设备。

### 从源码构建

```bash
git clone https://github.com/yzy806806/meshdesk.git
cd meshdesk
go build -o meshdesk ./cmd/meshdesk/
sudo cp meshdesk /usr/local/bin/
```

### 运行

```bash
# 仅 agent 模式（mesh 传输 + 监控上报）
meshdesk --config /etc/meshdesk/config.yaml

# Agent + Web UI（仪表盘、WebSSH、文件传输、服务管理、拓扑）
meshdesk --config /etc/meshdesk/config.yaml --web

# Agent + 中继模式（接受来自 peer 的代理中继电路）
meshdesk --config /etc/meshdesk/config.yaml --relay

# 生成 Ed25519 身份密钥对（输出私钥和公钥）
meshdesk --gen-key

# 通过引导节点加入已有 mesh（动态加入协议）
meshdesk join 203.0.113.5:443 --bootstrap-key <hex-pubkey>
```

### 命令行参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--config` | `/etc/meshdesk/config.yaml` | 配置文件路径 |
| `--web` | `false` | 启用 Web UI 模式（仪表盘、WebSSH、文件传输、服务管理、拓扑） |
| `--relay` | `false` | 启用中继模式（接受来自 peer 的代理中继电路） |
| `--gen-key` | `false` | 生成 Ed25519 身份密钥对后退出 |

**子命令：`join`**

```
meshdesk join <bootstrap-addr> [--bootstrap-key <hex>] [--config <path>]
```

通过引导节点的 Reality TLS 端点（默认 443 端口）加入已有 mesh。引导节点认证加入者（Ed25519 签名验证），然后向集群 gossip 新成员。

设置 `--web` 且未配置 `node.web` 时，Web UI 默认监听 `:8080`。

## 配置

```yaml
# /etc/meshdesk/config.yaml
node:
  identity: ""           # Ed25519 私钥（十六进制，128 字符）；为空则自动生成
  hostname: ""           # 显示名称（为空则自动检测）
  web: ":8080"           # Web UI 监听地址；为空 = 仅 agent 模式
  listen: ":443"         # Reality TLS 监听地址（有公网 IP 的种子节点）
  position:              # 可选：拓扑视图的手动 3D 位置
    x: 0
    y: 0
    z: 0

mesh:
  listen_port: 443       # Reality TLS 握手监听端口
  gossip_port: 7946      # memberlist gossip 端口（TCP，真实网卡）

# Reality TLS 服务端配置（有公网 IP 的种子节点）
reality:
  enabled: false         # 启动 Reality TLS 监听器
  dest: "www.apple.com:443"   # 伪装目标——非认证流量转发到的真实网站
  server_names:               # 接受的 ClientHello SNI 值
    - "www.apple.com"
  private_key: ""             # X25519 私钥（十六进制），用于 REALITY ECDH 认证
  short_ids: []               # 接受的 short ID 列表（十六进制，最长 8 字节）
  tls_fingerprint: "chrome"   # 模拟的浏览器 ClientHello 指纹

# P2P 动态组网（gossip 发现 + NAT 穿透 + 动态加入）
p2p:
  enabled: false
  seeds:                 # 引导节点（真实_ip:gossip_port）
    - "203.0.113.10:7946"
  nat_traversal: true    # STUN 发现 + UDP 打洞
  stun_servers:          # 默认为 Google + Cloudflare STUN
    - "stun.l.google.com:19302"
  relay_mode: "auto"     # auto | manual | disabled
  max_relay_hops: 2
  join_approval: "auto"  # auto（Ed25519 签名）| manual（仪表盘）
  authorized_keys: []    # 预授权加入的 Ed25519 公钥（十六进制）
  gossip_interval: 30    # push/pull 状态同步间隔（秒）
  gossip_probe_interval: 1  # 健康检查间隔（秒）
  direct_reprobe_interval: 120  # 中继模式下重新探测直连的间隔
  max_peers: 256

peers:
  - public_key: "abc123..."         # 节点 Ed25519 公钥（64 十六进制字符）
    endpoint: "relay.example.com:443"  # Reality TLS 监听地址；NAT 节点可留空
    capabilities:                    # 该节点在本机上允许的操作
      - monitor_write               # 推送指标
      - file_transfer               # 发送/接收文件
      - ssh                         # 打开终端会话
      - service_manage              # 管理 systemd 服务
    service_manage:                  # 限制只允许管理特定服务
      - nginx
      - docker
    file_transfer_paths:             # 限制文件传输可访问的路径
      - /var/www/
    # Reality TLS 客户端配置（每节点）：
    reality:
      server_name: "www.apple.com"   # ClientHello SNI，必须匹配服务端的 server_names
      public_key: ""                 # 服务端 X25519 公钥（十六进制），用于 ECDH 认证
      short_id: ""                   # 每客户端 short ID（十六进制，最长 8 字节）

monitoring:
  collectors: []         # 接收指标推送的采集节点 ID 列表
  interval: 15           # 推送间隔（秒）
  port: 4191             # mesh 内部指标推送端口（走 smux）

webssh:
  port: 2222             # 目标节点上 SSH 服务器的 mesh 内部端口
  shell: ""              # 默认 shell（为空则自动检测）
  host_key: ""           # SSH 主机私钥（为空则自动生成）
  dial_timeout: 10       # 连接目标节点的超时时间（秒）
  read_deadline: 300     # 空闲会话的 WebSocket 读超时（秒）
  write_deadline: 10     # WebSocket 写超时（秒）
  max_sessions: 256      # 每节点最大并发终端会话数

auth:
  web_users:             # Web UI 登录账号（留空则为首次运行开放模式）
    - username: admin
      password_hash: "$2a$10$..."  # 密码的 bcrypt 哈希值
  totp_issuer: "MeshDesk"     # QR 码 otpauth:// URI 中的发行者名称
  require_2fa: false          # 强制 TOTP 注册后才能访问仪表盘
  totp_window: 1              # ±时间偏移容差（每步 = 30 秒）
  totp_store_dir: ""          # 加密 TOTP 状态目录（如 /var/lib/meshdesk/totp）
  step_up_timeout: 300        # 逐步认证令牌有效期（秒）
  alert_webhook_url: ""      # 外部安全告警推送 webhook

transfer:
  max_file_size: 1073741824   # 单文件最大字节数（默认 1 GB，0 = 无限制）
  upload_dir: "/tmp/meshdesk-uploads/"  # 接收文件的存储目录

# 多路径匿名代理（见 docs/PROXY_DESIGN.md）
proxy:
  ss:                         # Shadowsocks 入口监听（仅入口节点）
    password: "your-ss-password"
    cipher: "chacha20-ietf-poly1305"
    listen_addr: "127.0.0.1:8388"
  circuit:                    # 电路生命周期参数
    idle_timeout: 300         # 空闲 N 秒后自动拆除
    keepalive_interval: 30    # ping 间隔（秒）
    nack_timeout: 5           # 出口等待 N 秒后发 NACK
    orphan_timeout: 30        # 不完整重组缓冲区清理
    max_reassembly_window: 256
  chunker_strategy: "bounded-4k-64k"  # 或 "fixed-16k"
  path_selection:             # 动态路径选择
    mode: "manual"            # manual | auto
    strategy: "latency"       # latency | random | round-robin
    max_relays_per_path: 2
    probe_timeout_sec: 3
    probe_concurrency: 8
    max_candidates: 10
    probe_cache_ttl_sec: 30
  cf_tunnel:                  # Cloudflare Tunnel（仅入口节点）
    enabled: false
    tunnel_id: ""
    credentials_file: ""
    hostname: "proxy.example.com"
    origin_server: "127.0.0.1:8388"
    binary_path: ""           # cloudflared 二进制路径
  relay:                      # 中继节点配置（仅中继节点）
    enabled: false
    jitter_min_ms: 5
    jitter_max_ms: 50
    max_circuits: 1024
    max_queue_depth: 256
  exit:                       # 出口节点配置（仅出口节点）
    allowed_ports: [80, 443]
    allow_all_ports: false    # 警告：完全法律风险
    destination_filter: []    # CIDR 或 FQDN 模式
    audit_log_dir: ""
    audit_retention_days: 7
```

所有字段均为可选。未填写的字段使用合理默认值。如果启动时配置文件不存在，节点以默认配置运行并自动生成 Ed25519 身份密钥对。

## 架构

```
┌─────────────────────────────────────────────────────┐
│                  MeshDesk 节点                       │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌───────┐  ┌────────┐ │
│  │   Mesh   │  │ 监控      │  │WebSSH │  │ 代理   │ │
│  │ 协议栈   │  │ 采集+推送 │  │ Hub  │  │ 入口/  │ │
│  │ L0–L4    │  │          │  │(SSH  │  │ 中继/  │ │
│  │+ gossip  │  │          │  │ proxy)│  │ 出口   │ │
│  └────┬─────┘  └────┬─────┘  └───┬───┘  └───┬───┘ │
│       │             │            │           │       │
│  ┌────┴─────────────┴────────────┴───────────┴────┐ │
│  │              PeerManager                       │ │
│  │   自动重连 • 多路径回退                        │ │
│  │   EWMA 延迟追踪 • 最优路径选择                 │ │
│  └────┬───────────────────────────────────────────┘ │
│       │                                             │
│  ┌────┴──────────────────────────────────────────┐  │
│  │              smux 多路复用器                   │  │
│  │   WebSSH │ 文件传输 │ RPC │ 代理              │  │
│  └────┬──────────────────────────────────────────┘  │
│       │                                             │
│  ┌────┴──────────────────────────────────────────┐  │
│  │           协议栈（L0–L4）                      │  │
│  │   L4 MeshNode │ L3 smux │ L2 AES-GCM          │  │
│  │   L2a X25519 ECDH │ L1 Reality TLS │ L0 ID    │  │
│  └────┬──────────────────────────────────────────┘  │
│       │                                             │
│  ┌────┴──────────────────────────────────────────┐  │
│  │           HTTP 服务器                          │  │
│  │  (仅 --web 模式)                              │  │
│  │                                               │  │
│  │  • 仪表盘 (htmx + SSE)                       │  │
│  │  • WebSSH 终端                                │  │
│  │  • 文件传输界面                               │  │
│  │  • 服务管理界面                               │  │
│  │  • 3D 拓扑 (Three.js + SSE)                 │  │
│  │  • TOTP 2FA + 逐步认证                       │  │
│  │  • 安全告警 + Webhook                         │  │
│  │  • 配置管理（分层 API）                       │  │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

## 文档

详细设计文档位于 [`docs/`](./docs/)：

- [ARCHITECTURE.md](./docs/ARCHITECTURE.md) — 系统架构概览
- [MESHDESK_V2_DESIGN.md](./docs/MESHDESK_V2_DESIGN.md) — v2 设计方案：自研协议栈、角色模型、智能选路
- [V2_INTERFACE_CONTRACT.md](./docs/V2_INTERFACE_CONTRACT.md) — v2 各层接口契约（L0–L4）
- [LAYER0_LAYER1_SPEC.md](./docs/LAYER0_LAYER1_SPEC.md) — L0（Ed25519 身份）+ L1（Reality TLS 握手）规范
- [LAYER2A_KEY_EXCHANGE_SPEC.md](./docs/LAYER2A_KEY_EXCHANGE_SPEC.md) — L2a X25519 ECDH 密钥交换规范
- [LAYER2_ENCRYPTION_SPEC.md](./docs/LAYER2_ENCRYPTION_SPEC.md) — L2b AES-256-GCM 加密规范
- [LAYER3_SMUX_SPEC.md](./docs/LAYER3_SMUX_SPEC.md) — L3 smux 流多路复用器规范
- [GOSSIP_REDESIGN_SPEC.md](./docs/GOSSIP_REDESIGN_SPEC.md) — Gossip v2 重新设计（NetTransport，无 mesh IP）
- [PEERMANAGER_DESIGN.md](./docs/PEERMANAGER_DESIGN.md) — PeerManager 状态机、隔离、延迟探测、路径选择
- [ENDPOINT_LEARNING_DESIGN.md](./docs/ENDPOINT_LEARNING_DESIGN.md) — 端点学习机制（EasyTier 风格）
- [ENDPOINT_LEARNING_DESIGN_v2.md](./docs/ENDPOINT_LEARNING_DESIGN_v2.md) — 端点学习 v2（gossip 集成 + NAT 类型推断）
- [OBFUSCATION_RESEARCH.md](./docs/OBFUSCATION_RESEARCH.md) — GFW 混淆调研与 Reality 集成方案
- [TRANSPORT_CONTRACT.md](./docs/TRANSPORT_CONTRACT.md) — 传输层接口契约
- [PROXY_DESIGN.md](./docs/PROXY_DESIGN.md) — 多路径匿名代理设计
- [CIRCUIT_MANAGER_SPEC.md](./docs/CIRCUIT_MANAGER_SPEC.md) — 电路生命周期管理
- [CHUNKER_CONTRACT.md](./docs/CHUNKER_CONTRACT.md) — 分块器/重组器接口
- [CONFIG_INVENTORY.md](./docs/CONFIG_INVENTORY.md) — 全量配置字段清单
- [CONFIG_SECURITY_MODEL.md](./docs/CONFIG_SECURITY_MODEL.md) — 分层配置访问模型（T0–T3）与安全原理
- [TOTP_KEY_ENCRYPTION_SPEC.md](./docs/TOTP_KEY_ENCRYPTION_SPEC.md) — TOTP 密钥加密规范
- [3D_TOPOLOGY_DESIGN.md](./docs/3D_TOPOLOGY_DESIGN.md) — 3D 拓扑可视化设计
- [DESIGN.md](./docs/DESIGN.md) — 前端设计系统（颜色、排版、间距）
- [FRONTEND.md](./docs/FRONTEND.md) — 前端架构、JS/CSS 清单与规范
- [SMOKE_TEST_GATES.md](./docs/SMOKE_TEST_GATES.md) — 冒烟测试定义与通过标准
- [V2_MIGRATION_GUIDE.md](./docs/V2_MIGRATION_GUIDE.md) — v1 到 v2 迁移指南
- [RELEASE_NOTES.md](./docs/RELEASE_NOTES.md) — 发布说明与验证状态
- [RELEASE_CHECKLIST.md](./docs/RELEASE_CHECKLIST.md) — 发布 SOP 检查清单
- [THREAT_MODEL.md](./THREAT_MODEL.md) — 安全威胁模型

## License

MIT