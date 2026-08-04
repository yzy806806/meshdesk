# MeshDesk 一键入网使用说明

**版本:** 1.1
**状态:** 生产就绪
**最后更新:** 2026-08-04

## 概述

MeshDesk v1.1 的一键入网功能让你可以用一条命令将新节点加入 mesh 网络——无需手动编辑配置文件，无需生成密钥，无需配置 peer 发现。从 Dashboard 复制一行命令，粘贴到新节点的 SSH 终端，节点即自动加入。v1.1 版本新增了 GitHub Releases 自动下载、架构自适应、版本锁定、systemd 集成等能力。

## 工作原理

```
Bootstrap 节点（Dashboard）              新节点（加入方）
┌──────────────────────────┐           ┌──────────────────────────┐
│ 1. 生成加入 Token         │           │                          │
│    (HMAC-Ed25519 签名)     │           │  curl ... | sh          │
│                          │──token──→ │ 2. 检测架构，下载二进制   │
│                          │          │    生成 Ed25519 身份       │
│                          │←─pubkey──│ 3. POST /join/request     │
│                          │          │    (token + pubkey)       │
│ 4. 验证 Token + 挑战      │──chal───→│ 5. 签名挑战               │
│                          │          │    (Ed25519 私钥)          │
│                          │←─sign────│ 6. POST /join/verify      │
│ 7. 验证签名               │          │                          │
│    返回配置包             │──bundle─→│ 8. 写入 config.yaml        │
│                          │          │    启动 systemd 服务       │
└──────────────────────────┘           └──────────────────────────┘
```

协议为两步 HMAC-Ed25519 挑战-应答：

1. **请求：** 新节点发送加入 token + Ed25519 公钥。Bootstrap 验证 token 的 HMAC 签名和过期时间。
2. **挑战：** Bootstrap 返回随机挑战码。新节点用 Ed25519 私钥签名，证明密钥持有权。
3. **验证：** Bootstrap 验证签名。通过后返回完整配置包：身份、peers、collector、Reality 密钥。

这个协议确保即使 token 被截获，攻击者也无法在没有对应 Ed25519 私钥的情况下完成加入。

## 快速开始（v1.1 推荐方式）

### 从 GitHub Releases 安装

```bash
curl -fsSL https://raw.githubusercontent.com/yzy806806/meshdesk/main/deploy/install.sh | sh
```

脚本自动完成：
- 检测系统架构（amd64 / arm64）
- 从 GitHub Releases 下载对应二进制（默认最新版本）
- 生成默认配置 `/etc/meshdesk/config.yaml`
- 安装 systemd 服务并启用

### 指定版本安装

```bash
curl -fsSL https://raw.githubusercontent.com/yzy806806/meshdesk/main/deploy/install.sh | sh -s -- --version v1.1.0
```

### 带加入参数一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/yzy806806/meshdesk/main/deploy/install.sh | sh -s -- \
  --join-url https://bootstrap.example.com:8443 \
  --join-token eyJhbGciOiJIUzI1NiJ9...
```

这一条命令完成：下载二进制 → 生成身份 → 执行加入协议 → 写入配置 → 启动服务。

### 启用 Web 模式安装

```bash
curl -fsSL https://raw.githubusercontent.com/yzy806806/meshdesk/main/deploy/install.sh | sh -s -- --web
```

systemd 服务会自动以 `--web` 参数启动，开启 Dashboard。

## 安装脚本选项

| 选项 | 说明 | 示例 |
|------|------|------|
| `--version <ver>` | 安装指定版本 | `--version v1.1.0` |
| `--join-url <url>` | Bootstrap 节点 URL | `--join-url https://bootstrap:8443` |
| `--join-token <token>` | Dashboard 生成的加入 token | `--join-token eyJ...` |
| `--web` | 启用 Web UI 模式 | `--web` |
| `--help` | 显示帮助信息 | `--help` |

## 安装后的系统状态

```
Binary:   /usr/local/bin/meshdesk
Config:   /etc/meshdesk/config.yaml
Data:     /var/lib/meshdesk/
Service:  /etc/systemd/system/meshdesk.service
Identity: /etc/meshdesk/identity.pem
```

## Dashboard 操作流程

### 1. 生成加入 Token

1. 打开 Dashboard：`https://<bootstrap-node>:8080`
2. 导航到 **入网** 页面
3. 点击「生成安装命令」
4. 配置（均可选）：
   - **过期时间：** 默认 30 分钟，最长 24 小时
   - **主机名：** 预设新节点的主机名
   - **角色标签：** 预设节点能力（monitor、SSH、文件传输、SOCKS5 出口）
5. 点击「生成」

Dashboard 显示一行安装命令：

```bash
curl -fsSL https://raw.githubusercontent.com/yzy806806/meshdesk/main/deploy/install.sh | sh -s -- --join-url https://bootstrap:8443 --join-token <token>
```

### 2. 在新节点执行

```bash
ssh root@新节点
# 粘贴从 Dashboard 复制的命令
curl -fsSL https://raw.githubusercontent.com/yzy806806/meshdesk/main/deploy/install.sh | sh -s -- --join-url https://bootstrap:8443 --join-token eyJ...
```

### 3. 验证加入

```bash
# 查看服务状态
systemctl status meshdesk
# 查看日志
journalctl -u meshdesk -f
# 验证版本
meshdesk --version
```

在 Dashboard 的 **节点** 页面应该能看到新节点已上线。

## 手动加入（不使用安装脚本）

```bash
# 1. 下载二进制
wget https://github.com/yzy806806/meshdesk/releases/download/v1.1.0/meshdesk-linux-amd64 -O /usr/local/bin/meshdesk
chmod +x /usr/local/bin/meshdesk

# 2. 生成身份（如果还未生成）
meshdesk --gen-key

# 3. 执行加入
meshdesk join https://bootstrap:8443 --token "<Dashboard生成的token>"

# 4. 启动
meshdesk --config /etc/meshdesk/config.yaml
```

`meshdesk join` 命令将自动写入 `/etc/meshdesk/config.yaml`。

## Token 安全

### Token 格式

```
base64(version || expiry_ts || random_nonce || HMAC-SHA256(key, version || expiry_ts || random_nonce))
```

| 字段 | 大小 | 说明 |
|------|------|------|
| version | 1 字节 | Token 格式版本 |
| expiry_ts | 8 字节 | 过期 Unix 时间戳 |
| random_nonce | 16 字节 | 随机数，防止重放 |
| HMAC | 32 字节 | Ed25519 签名 |

### 安全属性

- **时间限制：** Token 在配置的有效期后自动失效（默认 30 分钟）
- **一次性：** 每个 token 包含唯一 nonce，Bootstrap 节点跟踪已使用的 token 并拒绝重放
- **挑战-应答：** 即使 token 被盗，攻击者也无法在没有目标 Ed25519 私钥的情况下完成加入
- **TLS 传输：** 加入协议要求通过 Reality TLS 加密传输

## 撤销加入 Token

在 Dashboard 的 **入网** 页面，点击任何未使用 token 上的「撤销」按钮。已使用 token 在首次成功加入后自动失效。

## 故障排除

### "token expired"

加入 token 有有限的生命周期（默认 30 分钟）。从 Dashboard 生成新 token。

### "token already used"

每个 token 只能使用一次。生成新 token。

### "signature verification failed"

加入方的 Ed25519 私钥与其声称的公钥不匹配。可能原因：
- 身份密钥在其他机器上生成
- 身份文件损坏

清除身份后重试：
```bash
rm -f /etc/meshdesk/identity.pem
meshdesk --gen-key
# 重新运行加入命令
```

### "connection refused" on port 8443

Bootstrap 节点的加入端点未运行。确保 Bootstrap 节点已配置 `join.enabled: true` 且 Reality TLS 正常运行。加入端点通过 mesh 的 MuxTransport 复用端口，使用专用虚拟端口。

### "unsupported architecture"

安装脚本支持 linux/amd64 和 linux/arm64。其他平台请使用手动加入方法从源码编译。

### "Failed to determine latest version"

GitHub API 限流或无网络连接。使用 `--version` 参数指定确切版本号。

## 与 v1.0 的区别

| 特性 | v1.0 | v1.1 |
|------|------|------|
| 二进制来源 | 从 Bootstrap 节点下载 | 从 GitHub Releases 下载 |
| 架构检测 | 无，需手动选择 | 自动检测 amd64/arm64 |
| 版本锁定 | 不支持 | `--version` 指定 |
| systemd 集成 | 手动编辑 unit 文件 | 自动安装 + reload |
| 加入协议参数 | Dashboard URL 模式 | `--join-url` + `--join-token` 参数 |
| 默认配置生成 | 无 | 自动生成含注释的默认 config.yaml |
| 安装信息展示 | 无 | 安装完成显示摘要和下一步操作 |
