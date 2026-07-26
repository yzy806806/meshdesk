# MeshDesk 混淆与传输层调研报告 + xray 集成方案

**Date:** 2026-07-26
**Source:** 用户与 Hermes 联合调研

---

## 1. EasyTier 混淆策略：不混淆

调研 EasyTier 文档和源码后的关键发现：**EasyTier 不做任何抗 GFW 混淆**。

EasyTier 的设计目标是去中心化 mesh VPN，不是翻墙工具。它的传输协议列表（TCP/UDP/WS/WSS/WG/QUIC/FakeTCP）是传输多样性，不是混淆。加密用 AES-GCM 或 WireGuard 原生加密，但加密 ≠ 混淆。

| EasyTier 特性 | 实际作用 |
|---------------|---------|
| 多协议 (TCP/UDP/WS/WSS/QUIC) | NAT 穿透 fallback，不是混淆 |
| AES-GCM / WireGuard 加密 | 数据保密，GFW 可见协议指纹 |
| KCP proxy | 高丢包环境优化 |
| compression (zstd) | 带宽优化 |
| network-name + secret | 网络准入认证 |

EasyTier 的强项在组网能力（动态发现、NAT 穿透、共享节点模型），不在抗检测。MeshDesk 需要学习的是组网能力，不是混淆。

## 2. Xray Reality 抗检测机制

Reality 不伪装成 TLS 流量——它就是真实的 TLS 流量。

工作流程：
1. 客户端发 TLS Client Hello，SNI 填真实网站（如 apple.com）
2. 服务端收到后，自己作为客户端连 apple.com:443，拿到真实 Server Hello + 证书
3. 服务端把真实网站的 Server Hello 转发给客户端，但在证书里嵌入自己的认证信息（HMAC 签名）
4. 客户端验证证书里的 HMAC，确认是自己的 Reality 服务器
5. 验证通过 → 后续走 Reality 加密通道
6. **验证不通过（GFW 主动探测）→ 服务端直接转发给真实网站，GFW 探测到的是真实 apple.com 响应**

| 检测手段 | Reality 表现 |
|---------|-------------|
| 被动 DPI | 完美 TLS 1.3 流量 |
| 主动探测 | 探测到的是真实网站响应 |
| SNI 白名单 | SNI 是白名单内大站 |
| 流量分析 | TLS 1.3 加密，内层特征被覆盖 |
| 证书检查 | 真实网站证书 |
| AI 检测 | 流量模式与正常 HTTPS 一致 |

Reality 弱点：
- 需要目标网站支持 TLS 1.3 且证书足够大
- 服务端要能直连目标网站
- 不能伪装成 CDN 保护的网站（除非 target 也在 CDN 后面）

## 3. MeshDesk 现有混淆 vs Reality 对比

| | MeshDesk padded | MeshDesk websocket+utls | Xray Reality |
|---|---|---|---|
| 被动 DPI | ✅ 可过 | ✅ 可过 | ✅ 完美 |
| 主动探测 | ⚠️ PSK 防探但不完美 | ⚠️ TLS 证书可被分析 | ✅ 真实网站响应 |
| SNI 白名单 | ❌ 无 SNI | ⚠️ SNI 是自己域名 | ✅ SNI 是大站 |
| 证书 | 无 | 自签或 Let's Encrypt | 真实网站证书 |
| 性能 | 高（只加 padding） | 中（TLS 封装开销） | 中（代理真实网站握手） |
| 实现复杂度 | 中 | 高 | 极高 |

## 4. 2026 年 GFW 对抗现状（第三方调研）

来自 lilting.ch 的实测报告（2026 年）：

| 协议 | GFW 对抗 | 2025-2026 状态 |
|------|---------|---------------|
| ShadowSocks | △ | × 被检测，不可单独使用 |
| V2Ray (WS+TLS+CDN) | ○ | △ 有条件可用 |
| WireGuard 裸跑 | △ | × 被检测 |
| WireGuard + AmneziaWG | ○ | △ 有效但有特征 |
| **VLESS + REALITY** | **◎** | **✅ 当前最强** |
| Hysteria2 (QUIC) | ○ | ✅ 伪装为 HTTP/3 |

结论：VLESS+REALITY 是当前 GFW 对抗最强的方案。

## 5. 推荐架构：分层传输

```
┌──────────────────────────────────────────┐
│  MeshDesk 应用层 (gossip, monitor, WebSSH) │
├──────────────────────────────────────────┤
│  WireGuard (wireguard-go + gVisor)        │  ← 加密 + mesh IP
├──────────────────────────────────────────┤
│  传输层选择器 (obfuscation registry)       │  ← 根据配置选传输
│   ├── none: 原始 UDP (LAN)                │
│   ├── padded: AmneziaWG shim (轻量混淆)    │
│   ├── websocket: WS+utls (中等混淆)        │
│   └── reality: xray-core 隧道 (最强混淆)    │  ← 新增
├──────────────────────────────────────────┤
│  网络层 (UDP / TCP)                        │
└──────────────────────────────────────────┘
```

跨墙数据流：
```
ARM → 阿里云 (跨墙):
  1. WireGuard 生成加密包 (gVisor netstack)
  2. obfuscation=reality → xray-core 子进程
  3. xray-core 通过 Reality TLS 隧道发送
  4. GFW 看到的是访问 apple.com 的 TLS 流量

ARM → AMD1 (内网):
  1. WireGuard 生成加密包
  2. obfuscation=none → 直接 UDP
  3. 无混淆开销
```

## 6. xray-core 集成方案：需团队讨论投票

### 方案 A：子进程管理

meshdesk 启动 xray-core 作为子进程，通过 xray gRPC API 控制。

- 优点：隔离性好，xray 升级独立，配置系统成熟
- 缺点：多一个进程，多一份配置，二进制 +15MB
- 实现：meshdesk 内部 `internal/xray/manager.go` 管理子进程生命周期

### 方案 B：Go 库嵌入

import xray-core 作为 Go 库，直接调用。

- 优点：单二进制，无子进程管理
- 缺点：xray-core 不是库设计，import 很重，二进制 +30-50MB，升级困难
- 实现：`import "github.com/xtls/xray-core/..."`

### 方案 C：不集成 xray-core，自实现 Reality

自己在 MeshDesk 里实现 Reality 协议。

- 优点：完全控制，单二进制
- 缺点：Reality 实现极其复杂（TLS 中间人 + 证书伪造 + HMAC 认证），等于重写 xray-core 核心模块
- 不推荐

## 7. x-ui 面板设计

Dashboard 新增 x-ui 标签，功能：
- 节点列表：显示所有 mesh 节点的 xray 运行状态
- 一键配置：选择节点 → 选协议(VLESS/VMess/Trojan) → 填参数 → 自动生成 config.json 并部署
- 用户管理：添加/删除翻墙用户，生成分享链接
- 流量统计：每节点/每用户的流量统计
- Reality 配置：选择伪装目标网站，自动生成密钥对

参考 3x-ui 项目的功能集，但集成到 MeshDesk Dashboard 里，通过 mesh 远程管理各节点的 xray。

## 8. 配置模型

```yaml
xray:
  enabled: true
  binary_path: "/usr/local/bin/xray"
  config_dir: "/etc/meshdesk/xray/"
  api_port: 10085
  
  reality:
    enabled: true
    target: "www.apple.com:443"
    server_names: ["www.apple.com"]
    private_key: ""
    short_ids: ["0123456789abcdef"]
  
  inbounds:
    - protocol: "vless"
      port: 443
      flow: "xtls-rprx-vision"
      reality:
        target: "www.microsoft.com:443"
        server_names: ["www.microsoft.com"]
      users:
        - id: "uuid"
          email: "user@example.com"
```

## 9. 混淆模式选择逻辑

```
LAN 通信 → obfuscation=none (WireGuard 已加密)
跨墙 mesh → obfuscation=reality (xray Reality TLS)
无 xray 环境 → obfuscation=padded (AmneziaWG shim, fallback)
UDP 被限速 → obfuscation=websocket (WS+utls, fallback)
```

现有 padded/websocket 模式保留作为 fallback，不删除。Reality 作为跨墙通信的主力方案。
