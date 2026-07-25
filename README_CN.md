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

- 去中心化 P2P 组网，基于 **WireGuard**（wireguard-go + gVisor netstack）
- **Gossip 发现** — 基于 hashicorp/memberlist 的自动节点发现，无需手动配置 peer
- **NAT 穿透** — 基于 STUN 的公网端点发现 + UDP 打洞，支持中继回退
- **动态加入协议** — 新节点通过 `meshdesk join <bootstrap-addr>` 加入，使用 authorized_keys 认证
- **中继回退** — 直连失败时通过 mesh 节点中继流量
- 传输混淆：填充模式（AmneziaWG 风格）或 WebSocket+TLS 模式（uTLS 指纹模拟）
- 细粒度节点权限——限制每个节点能访问哪些功能（监控、SSH、文件传输、服务管理）

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
- 连接通过 mesh VPN 代理

### 文件传输

- 通过 Web UI 上传/下载文件
- Mesh 内部传输（文件走 VPN，不暴露到公网）
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

## 安装

**必须 root 运行。** Agent 需要 root 权限用于：

- 创建 TUN 网卡（WireGuard VPN）
- 执行命令（Web 终端）
- 读取系统指标（磁盘、网络、进程）
- 管理 systemd 服务

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

# 生成 WireGuard 密钥对（输出私钥和公钥）
meshdesk --gen-key

# 通过引导节点加入已有 mesh（动态加入协议）
meshdesk join 203.0.113.5:51820 --bootstrap-key <hex-pubkey>
```

### 命令行参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--config` | `/etc/meshdesk/config.yaml` | 配置文件路径 |
| `--web` | `false` | 启用 Web UI 模式（仪表盘、WebSSH、文件传输、服务管理、拓扑） |
| `--relay` | `false` | 启用中继模式（接受来自 peer 的代理中继电路） |
| `--gen-key` | `false` | 生成 WireGuard 密钥对后退出 |

**子命令：`join`**

```
meshdesk join <bootstrap-addr> [--bootstrap-key <hex>] [--config <path>]
```

通过引导节点加入已有 mesh。引导节点认证加入者（authorized_keys 检查），然后向集群 gossip 新成员。

设置 `--web` 且未配置 `node.web` 时，Web UI 默认监听 `:8080`。

## 配置

```yaml
# /etc/meshdesk/config.yaml
node:
  identity: ""           # WireGuard 私钥（十六进制）；为空则自动生成
  hostname: ""           # 显示名称（为空则自动检测）
  web: ":8080"           # Web UI 监听地址；为空 = 仅 agent 模式
  position:              # 可选：拓扑视图的手动 3D 位置
    x: 0
    y: 0
    z: 0

mesh:
  port: 51820            # WireGuard 监听端口
  gossip_port: 7946      # memberlist gossip 端口（TCP，mesh IP 上）

# P2P 动态组网（gossip 发现 + NAT 穿透 + 动态加入）
# 禁用时仅使用静态 peer（向后兼容）
p2p:
  enabled: false
  seeds:                 # 引导节点（mesh_ip:gossip_port）
    - "10.0.0.1:7946"
  nat_traversal: true    # STUN 发现 + UDP 打洞
  stun_servers:          # 默认为 Google + Cloudflare STUN
    - "stun.l.google.com:19302"
  relay_mode: "auto"     # auto | manual | disabled
  max_relay_hops: 2
  join_approval: "auto"  # auto（authorized_keys）| manual（仪表盘）
  authorized_keys: []    # 预授权加入的 WireGuard 公钥（十六进制）
  gossip_interval: 30    # push/pull 状态同步间隔（秒）
  gossip_probe_interval: 1  # 健康检查间隔（秒）
  direct_reprobe_interval: 120  # 中继模式下重新探测直连的间隔
  max_peers: 256

peers:
  - public_key: "abc123..."         # 节点 WireGuard 公钥
    endpoint: "relay.example.com:51820"  # host:port；漫游节点可留空
    allowed_ips:                     # 路由到此节点的 mesh IP
      - "10.0.0.2/32"
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
    obfuscation: "padded"            # none | padded | websocket
    obf_config:                        # 每节点混淆参数（AmneziaWG 风格）
      jc: 5                            # junk train：握手前 5 个垃圾包
      jmin: 64                         # 最小垃圾包大小（字节）
      jmax: 256                        # 最大垃圾包大小（字节）
      jitter_max_ms: 20                # 时序抖动，破坏流量分析
      psk: ""                          # 十六进制 32 字节防探测 PSK（空 = 禁用）
      # WebSocket 模式：
      # ws_use_tls: true               # 使用 wss://（TLS）
      # tls_sni: "example.com"         # TLS ClientHello 中的 SNI
      # tls_fingerprint: "chrome"      # chrome | firefox | safari | edge | ios | android

monitoring:
  collectors: []         # 接收指标推送的采集节点 ID 列表
  interval: 15           # 推送间隔（秒）
  port: 4191             # mesh 内部指标推送端口

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
      password_hash: "$2a$10$...""  # 密码的 bcrypt 哈希值
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
  path_selection:             # 动态路径选择（Phase 2）
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

所有字段均为可选。未填写的字段使用合理默认值。如果启动时配置文件不存在，节点以默认配置运行并自动生成 WireGuard 身份密钥。

## 架构

```
┌─────────────────────────────────────────────────────┐
│                  MeshDesk 节点                       │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌───────┐  ┌────────┐ │
│  │   Mesh   │  │ 监控      │  │WebSSH │  │ 代理   │ │
│  │ WireGuard│  │ 采集+推送 │  │ Hub  │  │ 入口/  │ │
│  │ +netstack│  │          │  │(SSH  │  │ 中继/  │ │
│  │ + gossip │  │          │  │ proxy)│ │ 出口   │ │
│  └────┬─────┘  └────┬─────┘  └───┬───┘  └───┬────┘ │
│       │             │            │           │       │
│       └──────┬──────┴────────────┴───────────┘       │
│              │                                      │
│  ┌───────────┴──────────────────────────┐           │
│  │           HTTP 服务器                  │           │
│  │  (仅 --web 模式)                      │           │
│  │                                       │           │
│  │  • 仪表盘 (htmx + SSE)               │           │
│  │  • WebSSH 终端                        │           │
│  │  • 文件传输界面                       │           │
│  │  • 服务管理界面                       │           │
│  │  • 3D 拓扑 (Three.js + SSE)         │           │
│  │  • TOTP 2FA + 逐步认证               │           │
│  │  • 安全告警 + Webhook                │           │
│  └───────────────────────────────────────┘           │
└─────────────────────────────────────────────────────┘
```

## 文档

详细设计文档位于 [`docs/`](./docs/)：

- [ARCHITECTURE.md](./docs/ARCHITECTURE.md) — 系统架构概览
- [PROXY_DESIGN.md](./docs/PROXY_DESIGN.md) — 多路径匿名代理设计
- [CIRCUIT_MANAGER_SPEC.md](./docs/CIRCUIT_MANAGER_SPEC.md) — 电路生命周期管理
- [CHUNKER_CONTRACT.md](./docs/CHUNKER_CONTRACT.md) — 分块器/重组器接口
- [TOTP_KEY_ENCRYPTION_SPEC.md](./docs/TOTP_KEY_ENCRYPTION_SPEC.md) — TOTP 密钥加密
- [3D_TOPOLOGY_DESIGN.md](./docs/3D_TOPOLOGY_DESIGN.md) — 3D 拓扑可视化
- [THREAT_MODEL.md](./THREAT_MODEL.md) — 安全威胁模型

## License

MIT
