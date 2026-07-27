# MeshDesk 实机测试报告 v3 — 架构重构后

**Date:** 2026-07-27
**Binary:** commit 4414e5f (v1.0.1)
**Environment:** ARM + AMD1 + AMD2 + 阿里云(共享节点)

---

## ✅ 通过的测试

| 测试项 | 结果 | 对比上次 |
|--------|------|---------|
| 四节点启动 | 全部启动成功 | 同 |
| endpoint learning | ✅ 三台节点都 announce 了 local endpoint | **新功能！之前从未工作** |
| gossip join | ✅ ARM + AMD1 成功 join | 同 |
| gossip 节点发现 | ✅ 发现全网 4 节点 | 同 |
| mesh TCP 连接 | ✅ ARM 能 TCP 连到阿里云和 AMD2 | **重大突破！之前完全不通** |
| Dashboard | ✅ AMD1:18080 可访问 | 同 |
| Topology API | 返回 4 节点 | 同 |
| Proxy exit node | ✅ 激活 | 同 |

## ⚠️ 已知问题

### 1. UDP ping 失败，节点标记 Suspect

**现象：** ARM 能 TCP 连接到其他节点（`Was able to connect over TCP`），但 UDP ping 超时（`Failed UDP ping: timeout reached`）。memberlist 不断标记节点为 Suspect。

**影响：** 节点状态在 topology 里显示 offline（因为 Suspect 状态）。但 mesh TCP 连接本身是通的。

**可能原因：**
- WireGuard UDP 隧道不稳定，memberlist 的 UDP ping 走 mesh IP 但 WireGuard 丢包
- 或者 memberlist 的 UDP ping 和 mesh TCP 走不同的网络路径

### 2. Topology 显示节点 offline

**现象：** 4 节点中只有 AMD1 online，其余 offline。edges 为 0。

**原因：** 节点 Suspect 状态导致。监控数据无法通过 mesh 上报。

### 3. 阿里云 "Text file busy"

**现象：** SCP 传输二进制时如果进程还在写文件，启动时报 "Text file busy"。

**修复：** cp 到新文件名再执行。

---

## 对比历次测试

| 项目 | v1 (初次) | v2 (架构重构后) | v3 (endpoint学习后) |
|------|----------|---------------|-------------------|
| gossip join | ❌ 超时 | ✅ 成功 | ✅ 成功 |
| 节点发现 | ❌ 只看直连 | ✅ 全网 | ✅ 全网 |
| endpoint learning | ❌ 不存在 | ❌ SetLocalEndpoints未调用 | ✅ 三节点都 announce |
| mesh TCP | ❌ 不通 | ❌ 不通 | ✅ **ARM→阿里云/AMD2 TCP 连通** |
| UDP ping | N/A | N/A | ⚠️ 失败但 TCP 通 |
| Dashboard | ✅ | ✅ | ✅ |

## 结论

**核心突破：mesh TCP 从完全不通变成了可以 TCP 连接。** endpoint learning 机制工作了——三台节点都成功 announce 了自己的 local endpoint。

UDP ping 失败是一个需要进一步调试的问题，但不影响 mesh TCP 连接的建立。这可能需要调整 memberlist 的探测策略（优先 TCP 或降低 UDP ping 权重）。
