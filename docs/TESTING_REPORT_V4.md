# MeshDesk 实机测试报告 v4 — Reality + Dashboard + x-ui

**Date:** 2026-07-27
**Binary:** commit 56f45c2 (with Reality cert fix)
**Environment:** ARM + AMD1 + AMD2 + 阿里云(共享节点, Reality TLS 443)

---

## ✅ 通过的测试

### Reality TLS Transport
| 测试项 | 结果 | 说明 |
|--------|------|------|
| Reality 服务端启动 | ✅ | 阿里云 443 端口监听 (PID 450770) |
| Reality cert 生成 | ✅ | ECDSA P-256 自签证书 |
| endpoint learning | ✅ | 三台节点 + 阿里云都 announce 了 |
| STUN NAT discovery | ✅ | NAT type=symmetric, endpoint detected |
| NAT traversal | ✅ | STUN + hole-punch + relay fallback active |
| gossip join | ✅ | ARM 成功 join |
| mesh TCP | ✅ | 阿里云收到 ARM stream 连接 |

### Dashboard 配置管理
| 测试项 | 结果 | 说明 |
|--------|------|------|
| Dashboard 可访问 | ✅ | AMD1:18080, 登录正常 |
| GET /api/config | ✅ | 10 个配置区块全部可见 |
| PUT /api/config (热重载) | ✅ | monitoring.interval 15→30, ok=True, pending_restart=False |
| Topology API | ✅ | 返回 3 节点 JSON |

### 前端文件
| 测试项 | 结果 | 说明 |
|--------|------|------|
| anime.min.js | ✅ | 加载正常 |
| anim.js (wrapper) | ✅ | MeshAnim wrapper 加载正常 |
| xui.js | ✅ | x-ui 面板 JS 加载正常 |

## ❌ 失败的测试

### 1. x-ui 面板页面 panic (P0)

**现象：** GET /xui 返回 "Internal Server Error"
**日志：** `PANIC: /xui runtime error: invalid memory address or nil pointer dereference`
**可能原因：** `handleXuiPage` → `s.renderPage(w, "xui.html", data)` 中 renderPage 或模板 nil

### 2. WireGuard 握手未通过 Reality TLS (P1)

**现象：** ARM 配置了 `obfuscation: "reality"`，但 WireGuard 持续报 `no known endpoint for peer`。gossip join 成功（通过 mesh TCP），但 WireGuard 包可能没走 Reality TLS 通道。

**可能原因：** obfuscatingBind 的 Send 路径没有正确路由到 realityBind

### 3. UDP ping 失败 (P2, 已知)

**现象：** TCP 连接成功但 UDP ping 超时，节点标记 Suspect

---

## 已修复的 bug（本次测试）

| Commit | 修复 | 类型 |
|--------|------|------|
| `12cbf3b` | Reality Listen() 缺 Certificates 字段 | 小修复 |
| `56f45c2` | 用 ECDSA P-256 替代 X25519 (crypto.Signer) | 小修复 |

## 需要团队修复的 bug

1. **P0: x-ui 页面 nil pointer panic** — renderPage 或模板 nil
2. **P1: WireGuard 包未路由到 Reality TLS 通道** — obfuscatingBind Send 路径问题
