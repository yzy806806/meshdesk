# MeshDesk 实机测试报告 v2 — 架构重构后

**Date:** 2026-07-27
**Binary:** commit bbe9cb1 (最新 main)
**Environment:** ARM + AMD1 + AMD2 + 阿里云(共享节点)

---

## ✅ 通过的测试

| 测试项 | 结果 |
|--------|------|
| 二进制编译 | arm64 + amd64 成功 |
| --gen-key | 正常 |
| 四节点启动 | 全部启动成功 |
| Web UI | AMD1:18080 可访问，登录正常 |
| Topology API | 返回 4 节点 JSON |
| Proxy exit node | 激活 (allowed_ports=[80 443]) |
| Service RPC | 监听 mesh port 4192 |
| File transfer | 监听 mesh port 4193 |
| Monitor | reporter active (interval=15s) |
| gossip join | ARM + AMD1 成功 join 集群（首次成功！） |
| gossip 节点发现 | 发现全网 4 节点 |

## ❌ 失败的测试

### Problem 1 (P0): gossip 发现的 peer 无 endpoint，WireGuard 无法通信

**现象：** gossip 成功发现全网节点，但通过 `wgDelegate.AddPeer()` 添加的动态 peer 没有 endpoint。WireGuard 报 `Failed to send handshake initiation: no known endpoint for peer`。

**根因：** gossip 传播的 peer 信息只包含 mesh IP 和公钥，不包含真实网络 endpoint。gossip 发现的 peer 应该通过共享节点中继连接，但 `wgDelegate.AddPeer()` 直接添加了无 endpoint 的 peer 到 WireGuard，WireGuard 不知道怎么中继。

**预期行为：** PeerManager 应该在添加 gossip 发现的 peer 时：
1. 如果 peer 有直连 endpoint → 直接添加
2. 如果 peer 无 endpoint → 设置 relay 路径（通过共享节点中继）
3. WireGuard 的 `allowed_ips` 配置为 peer 的 mesh IP，但 endpoint 设为共享节点

**影响：** 所有非直连节点之间无法通信。这是核心功能缺陷。

### Problem 2 (P0): 阿里云共享节点不学习 endpoint

**现象：** 普通节点的 `persistent_keepalive` 发 UDP 包到阿里云 51820，但阿里云报 `no known endpoint for peer`。说明阿里云的 WireGuard 没有从收到的包学习到 source endpoint。

**可能原因：**
1. WireGuard 的 endpoint 学习依赖于收到正确的握手 initiation 包
2. ARM 的 WireGuard 可能没发出握手包（`persistent_keepalive` 触发了但握手没发出）
3. 需要验证 ARM 到阿里云 115.29.235.24:51820 的 UDP 连通性

### Problem 3 (P1): Topology 显示节点 offline

**现象：** Topology API 显示 4 节点但只有 AMD1 online，其余 offline。edges 为 0。

**原因：** 节点间 mesh TCP 不通，监控数据无法上报。依赖 Problem 1+2 修复。

### Problem 4 (P2): AMD1 TOTP 密钥存储权限

**现象：** `mkdir /var/lib/meshdesk/totp: permission denied — TOTP secrets will be stored unencrypted`

**修复：** 需要 root 权限或预创建目录。小问题。

### Problem 5 (P2): AMD1 audit log 权限

**现象：** `open /var/log/meshdesk-audit.jsonl: permission denied — using stderr`

**修复：** 同上，需要 root 或预创建目录。

---

## 对比上次测试的进步

| 项目 | 上次 (v1) | 本次 (v2) |
|------|----------|----------|
| gossip join | ❌ 全部超时 | ✅ ARM + AMD1 成功 |
| 节点发现 | ❌ 只看到直连 peer | ✅ 发现全网 4 节点 |
| Proxy exit | ❌ 未验证 | ✅ 激活 |
| Dashboard | ✅ | ✅ |
| mesh TCP | ❌ 不通 | ❌ 仍不通（同根因） |

gossip join 成功是重大进步——MeshTransport demux 修复 + WaitForHandshake 修复生效了。但节点间 mesh TCP 仍然不通，因为 gossip 发现的 peer 无 endpoint。
