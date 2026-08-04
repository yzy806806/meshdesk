# MeshDesk systemd 部署指南

**版本:** 1.1
**状态:** 生产就绪
**最后更新:** 2026-08-04

## 概述

MeshDesk v1.1 提供完整的 systemd 集成，支持开机自启、崩溃自动重启、日志集成等生产级部署能力。systemd unit 文件位于 `deploy/meshdesk.service`，安装脚本 `deploy/install.sh` 会自动完成配置。

## 快速安装

### 使用安装脚本（推荐）

```bash
curl -fsSL https://raw.githubusercontent.com/yzy806806/meshdesk/main/deploy/install.sh | sh
```

脚本自动完成：
1. 下载二进制到 `/usr/local/bin/meshdesk`
2. 创建目录 `/etc/meshdesk/` 和 `/var/lib/meshdesk/`
3. 生成默认配置文件 `/etc/meshdesk/config.yaml`
4. 下载/生成 systemd unit 文件 `/etc/systemd/system/meshdesk.service`
5. 执行 `systemctl daemon-reload`

### 手动安装

```bash
# 1. 下载 systemd unit 文件
curl -fsSL -o /etc/systemd/system/meshdesk.service \
  https://raw.githubusercontent.com/yzy806806/meshdesk/main/deploy/meshdesk.service

# 2. 重载 systemd 配置
systemctl daemon-reload

# 3. 启用开机自启
systemctl enable meshdesk

# 4. 启动服务
systemctl start meshdesk

# 5. 验证状态
systemctl status meshdesk
```

## systemd Unit 文件详解

```ini
[Unit]
Description=MeshDesk Mesh VPN Node
Documentation=https://github.com/yzy806806/meshdesk
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/meshdesk --config /etc/meshdesk/config.yaml

# 启用 Web UI 模式时取消注释：
# ExecStart=/usr/local/bin/meshdesk --config /etc/meshdesk/config.yaml --web

# 重启策略
Restart=on-failure
RestartSec=5
StartLimitBurst=10
StartLimitIntervalSec=60

# 日志
StandardOutput=journal
StandardError=journal
SyslogIdentifier=meshdesk

# 安全加固
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false

# 资源限制
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### 配置项说明

| 配置项 | 说明 |
|--------|------|
| `After=network-online.target` | 确保网络完全就绪后才启动 meshdesk |
| `Wants=network-online.target` | 声明对网络就绪的依赖 |
| `Restart=on-failure` | 仅非正常退出时重启（不包含正常退出和信号终止） |
| `RestartSec=5` | 重启前等待 5 秒 |
| `StartLimitBurst=10` | 60 秒内最多重启 10 次 |
| `StartLimitIntervalSec=60` | 启动限制的统计窗口（秒） |
| `LimitNOFILE=65536` | 文件描述符上限（mesh 网络需要大量连接） |

## 日常运维

### 服务管理

```bash
# 启动
systemctl start meshdesk

# 停止
systemctl stop meshdesk

# 重启
systemctl restart meshdesk

# 重载配置（不中断服务）
systemctl reload meshdesk

# 查看状态
systemctl status meshdesk

# 启用开机自启
systemctl enable meshdesk

# 禁用开机自启
systemctl disable meshdesk
```

### 日志管理

```bash
# 实时查看日志
journalctl -u meshdesk -f

# 查看最近 100 行
journalctl -u meshdesk -n 100

# 查看今天的日志
journalctl -u meshdesk --since today

# 查看最近 1 小时的日志
journalctl -u meshdesk --since "1 hour ago"

# 按级别过滤
journalctl -u meshdesk -p err         # 仅错误
journalctl -u meshdesk -p warning     # 警告及以上

# 导出日志
journalctl -u meshdesk --since today > meshdesk-$(date +%Y%m%d).log
```

### 日志持久化配置

默认情况下，systemd journal 日志存储在 `/run/log/journal/`（内存，重启丢失）。如需持久化：

```bash
# 1. 创建持久化目录
mkdir -p /var/log/journal

# 2. 编辑 /etc/systemd/journald.conf
#    Storage=persistent

# 3. 重启 journald
systemctl restart systemd-journald
```

### 监控服务健康

```bash
# 检查服务是否活跃
systemctl is-active meshdesk

# 检查服务是否启用自启
systemctl is-enabled meshdesk

# 查看最后一次启动时间
systemctl show meshdesk -p ActiveEnterTimestamp

# 查看服务进程 PID
systemctl show meshdesk -p MainPID

# 查看资源使用
systemctl show meshdesk -p MemoryCurrent -p CPUUsageNSec
```

## Web UI 模式

### 启用 Dashboard

修改 systemd unit 文件中的 `ExecStart` 行：

```bash
# 编辑 unit 文件
systemctl edit meshdesk --full
# 或：
vim /etc/systemd/system/meshdesk.service
```

将：
```
ExecStart=/usr/local/bin/meshdesk --config /etc/meshdesk/config.yaml
```

修改为：
```
ExecStart=/usr/local/bin/meshdesk --config /etc/meshdesk/config.yaml --web
```

然后重载并重启：

```bash
systemctl daemon-reload
systemctl restart meshdesk
```

### 使用 --web 参数安装

```bash
curl -fsSL https://raw.githubusercontent.com/yzy806806/meshdesk/main/deploy/install.sh | sh -s -- --web
```

安装脚本会自动修改 systemd unit 文件添加 `--web` 参数。

## 安全加固（可选）

### 非 root 用户运行

创建专用用户并以非特权身份运行：

```bash
# 1. 创建系统用户
useradd -r -s /usr/sbin/nologin -M meshdesk

# 2. 调整目录权限
chown -R meshdesk:meshdesk /etc/meshdesk /var/lib/meshdesk

# 3. 修改 unit 文件
#    User=meshdesk
#    Group=meshdesk

# 4. 如果需要 TUN 功能，添加网络权限
#    AmbientCapabilities=CAP_NET_ADMIN
#    CapabilityBoundingSet=CAP_NET_ADMIN
```

### 资源限制

添加额外的资源控制：

```ini
[Service]
# CPU 限制（允许使用 2 个核心的 80%）
CPUQuota=160%

# 内存限制（512 MB）
MemoryMax=512M

# 进程数限制
TasksMax=256
```

### 安全特性（需评估兼容性）

```ini
[Service]
# 注意：以下选项可能影响 TUN 功能和 mesh 网络操作
# 建议在测试环境先验证

# 禁止创建新权限（需 root 运行 TUN 时关闭）
# NoNewPrivileges=true

# 限制文件系统访问（可能影响 identity.pem 写入）
# ProtectSystem=strict
# ReadWritePaths=/etc/meshdesk /var/lib/meshdesk

# 禁止访问 /home
# ProtectHome=true
```

## 故障排除

### 服务无法启动

```bash
# 1. 查看完整启动日志
journalctl -u meshdesk -n 50 --no-pager

# 2. 手动测试二进制
/usr/local/bin/meshdesk --config /etc/meshdesk/config.yaml --version

# 3. 检查配置文件语法
/usr/local/bin/meshdesk --config /etc/meshdesk/config.yaml
# 如果无法启动，会有错误输出

# 4. 检查权限
ls -la /usr/local/bin/meshdesk
ls -la /etc/meshdesk/
```

### 频繁重启（"start limit hit"）

systemd 检测到服务在 60 秒内崩溃超过 10 次，会停止尝试重启。

```bash
# 重置失败计数器
systemctl reset-failed meshdesk

# 查看崩溃原因
journalctl -u meshdesk -n 200 --no-pager

# 手动启动诊断
/usr/local/bin/meshdesk --config /etc/meshdesk/config.yaml
```

### "code=exited, status=203/EXEC"

二进制文件不存在或无执行权限：

```bash
# 检查二进制
ls -la /usr/local/bin/meshdesk

# 如果缺失，重新安装
curl -fsSL https://raw.githubusercontent.com/yzy806806/meshdesk/main/deploy/install.sh | sh -s -- --version v1.1.0
```

### TUN 设备创建失败

TUN 功能需要 root 权限或 `CAP_NET_ADMIN` capability：

```bash
# 确认是以 root 运行
systemctl show meshdesk -p User

# 或添加 capability（非 root 用户）
# AmbientCapabilities=CAP_NET_ADMIN
```

### Web UI 端口冲突

如果端口 8080 已被占用：

```yaml
# 在 config.yaml 中修改
node:
  web_addr: ":9090"    # 改用 9090 端口
# 注意：必须同时修改 systemd unit 文件
```

## 升级流程

```bash
# 1. 停止服务
systemctl stop meshdesk

# 2. 下载新版本（替换二进制）
curl -fsSL -o /usr/local/bin/meshdesk \
  https://github.com/yzy806806/meshdesk/releases/download/v1.1.1/meshdesk-linux-amd64
chmod +x /usr/local/bin/meshdesk

# 3. 验证版本
/usr/local/bin/meshdesk --version

# 4. 重启服务
systemctl start meshdesk

# 5. 确认运行
systemctl status meshdesk
```

## 完整部署检查清单

- [ ] `/usr/local/bin/meshdesk` 存在且可执行
- [ ] `meshdesk --version` 返回正确版本号
- [ ] `/etc/meshdesk/config.yaml` 配置正确
- [ ] `/etc/meshdesk/identity.pem` 身份文件存在
- [ ] `/etc/systemd/system/meshdesk.service` unit 文件就位
- [ ] `systemctl daemon-reload` 已执行
- [ ] `systemctl enable meshdesk` 开机自启已启用
- [ ] `systemctl start meshdesk` 服务正常启动
- [ ] `systemctl status meshdesk` 显示 active (running)
- [ ] `journalctl -u meshdesk -n 10` 无 FATAL 日志
- [ ] 防火墙规则放行 mesh 端口（默认 52888）
- [ ] Dashboard（如启用）可通过 `http://<ip>:8080` 访问
