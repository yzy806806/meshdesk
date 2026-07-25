# MeshDesk

**去中心化服务器 mesh 网络 + 监控 + WebSSH —— 单二进制。**

[English](./README.md)

---

## MeshDesk 是什么？

MeshDesk 将三个工具合为一体：

1. **Mesh VPN** — 服务器之间 P2P 去中心化组网（替代 EasyTier）
2. **服务器监控** — CPU、内存、磁盘、网络、服务状态（替代 Nezha）
3. **Web 终端** — 浏览器直接进终端，无需 SSH 客户端

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
| 网络拓扑可视化 | ❌ | ✅（仅 CLI） | ✅（Web UI） |

Nezha 有监控和 WebSSH 但没有 mesh 组网——dashboard 挂了就全没了。EasyTier 有 mesh VPN 但没有监控和 web 终端。MeshDesk 一个二进制全搞定。

## 功能

### Mesh VPN

- 去中心化 P2P 组网，基于 **WireGuard**（wireguard-go + gVisor netstack）
- NAT 穿透，支持共享中继节点
- 自动节点发现
- 传输混淆：填充模式（AmneziaWG 风格）或 WebSocket 模式
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

# 生成 WireGuard 密钥对（输出私钥和公钥）
meshdesk --gen-key

# Agent + Web UI（仪表盘、WebSSH、文件传输、服务管理）
meshdesk --config /etc/meshdesk/config.yaml --web
```

### 命令行参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--config` | `/etc/meshdesk/config.yaml` | 配置文件路径 |
| `--web` | `false` | 启用 Web UI 模式（仪表盘、WebSSH、文件传输、服务管理） |
| `--gen-key` | `false` | 生成 WireGuard 密钥对后退出 |

设置 `--web` 且未配置 `node.web` 时，Web UI 默认监听 `:8080`。

## 配置

```yaml
# /etc/meshdesk/config.yaml
node:
  identity: ""           # WireGuard 私钥（十六进制）；为空则自动生成
  hostname: ""           # 显示名称（为空则自动检测）
  web: ":8080"           # Web UI 监听地址；为空 = 仅 agent 模式

mesh:
  port: 51820            # WireGuard 监听端口

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
      password_hash: "$2a$10$..."  # 密码的 bcrypt 哈希值

transfer:
  max_file_size: 1073741824   # 单文件最大字节数（默认 1 GB，0 = 无限制）
  upload_dir: "/tmp/meshdesk-uploads/"  # 接收文件的存储目录
```

所有字段均为可选。未填写的字段使用合理默认值。如果启动时配置文件不存在，节点以默认配置运行并自动生成 WireGuard 身份密钥。

## 架构

```
┌─────────────────────────────────────────┐
│              MeshDesk 节点               │
│                                          │
│  ┌──────────┐  ┌──────────┐  ┌───────┐  │
│  │   Mesh   │  │ Monitor  │  │WebSSH │  │
│  │ WireGuard│  │ Collect  │  │ Hub   │  │
│  │ + netstk│  │ + Push   │  │ (SSH  │  │
│  │          │  │          │  │ proxy)│  │
│  └────┬─────┘  └────┬─────┘  └───┬───┘  │
│       │             │            │       │
│       └──────┬──────┴────────────┘       │
│              │                           │
│  ┌───────────┴───────────────┐           │
│  │       HTTP Server          │           │
│  │  (仅 --web 模式)           │           │
│  │                            │           │
│  │  • 仪表盘 (htmx + SSE)    │           │
│  │  • WebSSH 终端             │           │
│  │  • 文件传输界面            │           │
│  │  • 服务管理界面            │           │
│  └────────────────────────────┘           │
└─────────────────────────────────────────┘
```

## License

MIT
