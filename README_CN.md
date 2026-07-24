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

## 架构

```
┌──────────────────────────────────────────┐
│            单二进制 (Go)                  │
│                                          │
│  ┌──────────┐   ┌─────────────────────┐  │
│  │  Agent   │   │   WebUI (--web)     │  │
│  │          │   │                     │  │
│  │ • 系统状态│   │ • 服务器总览        │  │
│  │ • 命令执行│   │ • 网络拓扑          │  │
│  │ • Mesh   │   │ • Web 终端          │  │
│  │   节点   │   │ • 文件传输          │  │
│  └────┬─────┘   └─────────┬───────────┘  │
│       │                    │              │
│       └─── mesh 层 ───────┘              │
│           P2P / 中继自动选择               │
└──────────────────────────────────────────┘
```

- **每个节点**以 root 运行同一个二进制
- **Agent 模式**（默认）：采集指标、接受命令、参与 mesh
- **Web 模式**（`--web`）：在指定端口提供 Web UI
- **Mesh 层**：P2P 直连优先，NAT 后自动走中继
- **无中心服务器**：任意节点可当面板，任意节点宕机不影响其他

## 功能

### Mesh VPN
- 去中心化 P2P 组网（KCP/QUIC/TCP）
- NAT 穿透，支持共享中继节点
- 自动节点发现
- 加密隧道（ChaCha20-Poly1305）
- Web UI 网络拓扑可视化

### 监控
- 实时 CPU / 内存 / 磁盘 / 网络指标
- 每台服务器的进程列表
- 服务状态（systemd units）
- 历史图表
- 告警（阈值触发，webhook/Telegram 通知）

### Web 终端
- 浏览器终端（xterm.js + WebSocket）
- 无需 SSH 密钥或密码——agent 以 root 运行
- 多标签、多服务器
- 会话录制（可选）

### 文件管理
- 通过 Web UI 上传/下载文件
- 拖拽支持
- 文件浏览器（含权限显示）

### 服务管理
- 启动/停止/重启 systemd 服务
- 查看服务日志
- 启用/禁用服务

## 安装

```bash
# 以 root 安装
curl -fsSL https://raw.githubusercontent.com/yzy806806/meshdesk/main/install.sh | bash

# 或手动：
# 1. 下载对应平台的二进制
# 2. 放到 /usr/local/bin/meshdesk
# 3. 创建 systemd 服务
# 4. 启动

# 仅 agent（默认）
meshdesk --network mynet --secret mysecret

# Agent + Web UI
meshdesk --network mynet --secret mysecret --web :8080
```

**必须 root 运行。** Agent 需要 root 权限用于：
- 创建 TUN 网卡（VPN）
- 执行命令（Web 终端）
- 读取系统指标（磁盘、网络、进程）
- 管理 systemd 服务

## 配置

```yaml
# /etc/meshdesk/config.yaml
network: mynet          # mesh 网络名
secret: mysecret        # mesh 认证密钥
web: ":8080"            # Web UI 端口（空 = 不开 Web UI）
peers:                  # 引导节点（共享中继）
  - relay1.example.com:11010
  - relay2.example.com:11010
hostname: ""            # 显示名称（空则自动检测）
tun: true               # 是否启用 TUN 网卡
tun_ip: ""              # 自动分配（空则自动）
```

## 技术栈

- **语言：** Go（单二进制，跨平台）
- **前端：** React + TypeScript（通过 `embed.FS` 打包进二进制）
- **终端：** xterm.js + WebSocket
- **VPN：** TUN 设备 + ChaCha20-Poly1305
- **传输：** KCP / QUIC / TCP（自动协商）
- **数据库：** SQLite（嵌入式，存历史指标）
- **协议：** gRPC / Protobuf（mesh 通信）

## License

MIT
