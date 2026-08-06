# MeshDesk 中继回退部署指南

**版本:** 1.0
**状态:** 生产就绪（零代码变更）
**最后更新:** 2026-08-07
**关联:** motion-fb0fdd61c936, docs/DESIGN_DECISION_NO_GLOBAL_ROUTING.md
**代码基线:** 63ca29a (HEAD = origin/main)

---

## 1. 概述

本指南将 developer 在 Agora 讨论中两次被截断的发言内容整理为具体可执行的
部署步骤。讨论结论是：**四节点拓扑不需要实现全局路由表，现有 per-pair 反应式
中继回退已满足停止条件**（最大有效路径 = 1 跳中继 A→relay→B）。

本文档的目的是使部署步骤**具体可执行**——每一步都有真实代码路径、配置字段、
验证命令，而不是抽象描述。

### 1.1 四节点拓扑

| 节点 | 角色 | 公网地址 | IP 栈 | SSH |
|------|------|---------|-------|-----|
| 阿里云 | 共享节点 (relay+exit) | 203.0.113.10:52888 | IPv4 only | `ssh -i ~/.ssh/deploy_key root@203.0.113.10` |
| N1 | 共享节点 (relay) | fn.example.com:22000 (IPv6 SLAAC) | IPv6 only (CGNAT) | `ssh -p 22000 yzy806806@fn.example.com` |
| txcloud | 普通节点 | IPv6 2001:db8:... | IPv6 (对称NAT, 无入站) | 本机直接操作 |
| Oracle ARM | 普通节点 | 203.0.113.20 + IPv6 | 双栈 (aarch64) | `ssh oracle-arm` |

### 1.2 连通性矩阵与中继需求

| 节点对 | 直连? | 中继节点 | 原因 |
|--------|-------|---------|------|
| 阿里云 ↔ Oracle ARM | ✅ IPv4 | — | 双方都有公网 IPv4 |
| N1 ↔ txcloud | ✅ IPv6 | — | 双方都有公网 IPv6 |
| N1 ↔ Oracle ARM | ✅ IPv6 | — | 双方都有公网 IPv6 |
| 阿里云 ↔ txcloud | ❌ | Oracle ARM 或 N1 | 阿里云无 IPv6，txcloud 对称NAT无入站 |
| 阿里云 ↔ N1 | ❌ | txcloud 或 Oracle ARM | 阿里云无 IPv6，N1 无公网 IPv4 |
| txcloud ↔ Oracle ARM | ❌ | 阿里云或 N1 | txcloud IPv6 与 Oracle IPv6 不通 |

**关键洞察（developer 发言核心）：** 中继对是交叉的——普通节点 (txcloud/Oracle)
为中继共享节点对 (阿里云↔N1) 提供中继，共享节点 (阿里云/N1) 为普通节点对
(txcloud↔Oracle) 提供中继。因此 **所有四个节点都必须启用 relay**，仅在共享
节点上启用会静默破坏 阿里云↔N1 这一对的中继路径。

---

## 2. 部署前提条件

### 2.1 前提条件 1：所有节点启用 CapRelay

**这是唯一的硬性前提。** 代码默认 `proxy.relay.enabled: false`
（config.go:949）。必须显式设为 `true`。

启用方式有两种（等价）：

**方式 A：配置文件**

在 `/etc/meshdesk/config.yaml` 中添加：

```yaml
proxy:
  relay:
    enabled: true
    max_circuits: 1024        # 默认值，可按需调整
    jitter_min_ms: 5          # 默认值
    jitter_max_ms: 50         # 默认值
    max_queue_depth: 256      # 默认值
```

**方式 B：命令行标志**

```bash
meshdesk --relay [其他参数]
```

`--relay` 标志（main.go:95）与 `proxy.relay.enabled: true` 效果相同——两者
都会触发以下两个初始化路径：

1. **P2P 层** `EnableRelayMode(maxCircuits)` （main.go:408-418）
   - 创建 `RelaySessionManager`（处理 circuit_setup/teardown/ping 消息）
   - 通过 `SetLocalCapabilities(true, ...)` 将 `CapRelay=true` 写入 `NodeMeta`
     （gossip.go:1233）
   - 将 `MaxCircuits` 写入 gossip 元数据（gossip.go:1236-1238）
   - 这些元数据通过 gossip 传播给所有节点

2. **Mesh 层** `RegisterRelayHandler()` （main.go:243-249）
   - 在虚拟端口 `0x524C` 注册 `RelayHandler`（relay_dialer.go:164）
   - 启动 accept 循环处理入站中继请求（relay_dialer.go:191）
   - 日志输出：`Smux relay: listening on virtual port 0x524C (maxTunnels=64)`

**为什么所有四个节点都要启用：**

`tryRelayFallback`（relay_dialer.go:316）在收集中继候选时执行以下过滤：

```
relay_dialer.go:359  if !rp.CapRelay { continue }        // 必须有 CapRelay
relay_dialer.go:363  if rp.MaxCircuits > 0 && rp.LoadCircuits >= rp.MaxCircuits { continue }  // 排除满载
relay_dialer.go:367  if rp.NatType == "symmetric" { continue }  // 排除对称NAT
relay_dialer.go:371  if !sessionOK(rp.PeerKey) { continue }     // 必须有活跃 smux session
```

如果只有共享节点启用 relay：
- 阿里云↔N1 这一对需要中继，但候选只有 txcloud 和 Oracle ARM
- txcloud 和 Oracle ARM 的 `CapRelay=false` → 被过滤掉
- 结果：`no relay candidates` → 该节点对无法建立连接

### 2.2 前提条件 2：smux session 就绪

中继流量通过 smux session 传输，不是原始 IP。`DialViaRelay` 的第一步就是
查找到中继节点的 smux session（relay_dialer.go:89-94）：

```go
sess, ok := d.node.clientSessions[relayKey]
if !ok {
    sess, ok = d.node.sessions[relayKey]
}
```

**部署前验证：** 每个节点必须至少与一个共享节点建立 smux session。普通节点
(txcloud/Oracle) 通过出站连接共享节点建立 `clientSessions`；共享节点
(阿里云/N1) 被动接受连接形成 `sessions`。

中继 handler 在转发时也需要到目标节点的 session（relay_handler.go:179）：

```go
targetSession := h.node.GetSession(req.TargetKey)
// GetSession (node.go:661) 先查 clientSessions 再查 sessions
```

**如果 session 不存在：** relay handler 返回 `RelayRejectNoSessionToTarget`
（relay_handler.go:187），中继请求被拒绝。

**确保 session 就绪的方法：**
- 先部署共享节点（阿里云 + N1），等待 gossip 收敛
- 再部署普通节点（txcloud + Oracle），它们会主动连接共享节点
- 使用 `SIGUSR1` 状态转储验证 session 列表（见 §4.2）

### 2.3 前提条件 3：gossip 集群收敛

`CapRelay` 标志通过 gossip `NodeMeta` 传播（delegate.go:35, msgpack 字段 `cr`）。
所有节点必须看到所有其他节点的 `CapRelay=true` 才能正确选择中继候选。

`GetRelayCandidates()`（events.go:542）从 gossip 池中筛选 `CapRelay=true`
的节点。如果 gossip 尚未收敛，新加入的节点不会被识别为中继候选。

**收敛时间：** 默认 `gossip_interval: 30` 秒（PushPull 全状态同步），
`gossip_probe_interval: 1` 秒（健康探测）。建议等待 2-3 个 gossip 周期
（约 90 秒）再进行中继测试。

---

## 3. 部署步骤（按顺序执行）

### 步骤 1：构建二进制

在 txcloud（本机）上构建所有架构的二进制：

```bash
cd /root/meshdesk
git fetch origin
git checkout 63ca29a  # 或最新 origin/main

# amd64 (txcloud, 阿里云)
GOOS=linux GOARCH=amd64 go build -o /tmp/meshdesk-amd64 ./cmd/meshdesk/

# arm64 (N1, Oracle ARM)
GOOS=linux GOARCH=arm64 go build -o /tmp/meshdesk-arm64 ./cmd/meshdesk/

# 验证
file /tmp/meshdesk-amd64 /tmp/meshdesk-arm64
```

### 步骤 2：部署共享节点（先部署）

**阿里云 (amd64, IPv4 only)：**

```bash
# 上传二进制
scp -i ~/.ssh/deploy_key /tmp/meshdesk-amd64 root@203.0.113.10:/usr/local/bin/meshdesk

# SSH 登录后编辑配置
ssh -i ~/.ssh/deploy_key root@203.0.113.10
```

确保 `/etc/meshdesk/config.yaml` 包含：

```yaml
hostname: aliyun
mesh:
  port: 52888
  gossip_port: 52888
reality:
  enabled: true
  private_key: "<阿里云的 Reality 私钥>"
proxy:
  relay:
    enabled: true              # ← 关键：启用 CapRelay
p2p:
  enabled: true
  nat_traversal: true
  relay_mode: auto             # 默认值，自动中继回退
  seeds:
    - "10.144.144.1:52888"     # N1 的 mesh IP（如果已知）
```

```bash
# 重启服务
systemctl restart meshdesk
# 验证 relay handler 注册
journalctl -u meshdesk --no-pager | grep "Smux relay"
# 应看到: Smux relay: listening on virtual port 0x524C (maxTunnels=64)
```

**N1 (arm64, IPv6 only)：**

```bash
# 上传二进制
scp -P 22000 /tmp/meshdesk-arm64 yzy806806@fn.example.com:/tmp/meshdesk
ssh -p 22000 yzy806806@fn.example.com 'sudo mv /tmp/meshdesk /usr/local/bin/meshdesk'
```

确保 N1 的 `/etc/meshdesk/config.yaml` 包含：

```yaml
hostname: N1
mesh:
  port: 52888
  gossip_port: 52888
reality:
  enabled: true
  private_key: "<N1 的 Reality 私钥>"
proxy:
  relay:
    enabled: true              # ← 关键：启用 CapRelay
p2p:
  enabled: true
  nat_traversal: true
  relay_mode: auto
  seeds:
    - "10.144.144.10:52888"    # 阿里云的 mesh IP
```

```bash
sudo systemctl restart meshdesk
sudo journalctl -u meshdesk --no-pager | grep "Smux relay"
# 应看到: Smux relay: listening on virtual port 0x524C (maxTunnels=64)
```

### 步骤 3：等待共享节点 gossip 收敛

```bash
# 在阿里云上检查 gossip 成员
curl -s http://localhost:52888/api/topology | python3 -m json.tool
# 应看到 aliyun 和 N1 两个节点，且都是 online

# 等待至少 90 秒（3 个 gossip 周期）确保元数据传播
sleep 90
```

### 步骤 4：部署普通节点

**txcloud (amd64, 本机, IPv6)：**

确保 `/etc/meshdesk/config.yaml` 包含：

```yaml
hostname: txcloud
mesh:
  port: 52888
  gossip_port: 52888
reality:
  enabled: false               # 普通节点
proxy:
  relay:
    enabled: true              # ← 关键：普通节点也要启用 CapRelay
p2p:
  enabled: true
  nat_traversal: true
  relay_mode: auto
  seeds:
    - "10.144.144.1:52888"     # 阿里云
    - "10.144.144.10:52888"    # N1
```

```bash
systemctl restart meshdesk
journalctl -u meshdesk --no-pager | grep "Smux relay"
```

**Oracle ARM (arm64, 双栈)：**

```bash
scp /tmp/meshdesk-arm64 oracle-arm:/tmp/meshdesk
ssh oracle-arm 'sudo mv /tmp/meshdesk /usr/local/bin/meshdesk'
```

```yaml
hostname: oracle-arm
mesh:
  port: 52888
  gossip_port: 52888
reality:
  enabled: false               # 普通节点
proxy:
  relay:
    enabled: true              # ← 关键
p2p:
  enabled: true
  nat_traversal: true
  relay_mode: auto
  seeds:
    - "10.144.144.1:52888"     # 阿里云
    - "10.144.144.10:52888"    # N1
```

```bash
sudo systemctl restart meshdesk
sudo journalctl -u meshdesk --no-pager | grep "Smux relay"
```

### 步骤 5：等待全网 gossip 收敛

```bash
# 在任意节点上检查四节点都在线
curl -s http://localhost:52888/api/topology | python3 -m json.tool
# 应看到 4 个节点: aliyun, N1, txcloud, oracle-arm

# 等待 90 秒确保 CapRelay 元数据传播完成
sleep 90
```

---

## 4. 部署验证

### 4.1 验证 CapRelay 配置传播

在每个节点上发送 `SIGUSR1` 信号获取状态转储：

```bash
# 获取 meshdesk PID
PID=$(pgrep meshdesk)

# 触发状态转储
kill -USR1 $PID

# 查看日志中的状态转储
journalctl -u meshdesk --no-pager -n 100 | grep -A5 "Routing Table"
```

状态转储（`DumpState`, node.go:687）会输出：

```
=== Routing Table (3 peers) ===
  peer <key>  endpoint=...  allowedIPs=[...]
  ...

=== Sessions (server=N, client=M) ===
  [client] peer <key>  streams=3  rx=12345  tx=67890  established=...
  [server] peer <key>  streams=2  rx=...  tx=...  established=...
  ...

=== TUN VirtualIP Routes (3) ===
  10.144.144.1 -> <aliyun-key>
  10.144.144.10 -> <N1-key>
  ...
```

**验证检查清单：**

- [ ] 每个节点有 3 个 routing table peer（其他三个节点）
- [ ] 每个节点至少有 1 个活跃 smux session（连接到至少一个共享节点）
- [ ] TUN 虚拟 IP 路由包含所有四个节点的 mesh IP
- [ ] 日志中出现 `Smux relay: listening on virtual port 0x524C`（所有四个节点）

### 4.2 验证 CapRelay 元数据

通过 topology API 检查 gossip 传播的 `CapRelay` 标志：

```bash
curl -s http://localhost:52888/api/topology | python3 -c "
import json, sys
data = json.load(sys.stdin)
for node in data.get('nodes', []):
    print(f\"  {node['hostname']:15s}  status={node['status']}  relay={'relay' in node.get('role','')}  endpoints={len(node.get('endpoints',[]))}\")
"
```

所有四个节点都应显示 relay 能力。如果没有，检查该节点的
`proxy.relay.enabled: true` 配置和 `Smux relay` 日志。

### 4.3 验证中继路径（TUN ping 测试）

按连通性矩阵测试所有 6 个节点对：

**直连对（应 0% 丢包）：**

```bash
# 阿里云 → Oracle ARM (IPv4 直连)
ssh -i ~/.ssh/deploy_key root@203.0.113.10 \
  'ping -c 10 10.144.144.<oracle-mesh-ip>'

# N1 → txcloud (IPv6 直连)
ssh -p 22000 yzy806806@fn.example.com \
  'ping -c 10 10.144.144.<txcloud-mesh-ip>'

# N1 → Oracle ARM (IPv6 直连)
ssh -p 22000 yzy806806@fn.example.com \
  'ping -c 10 10.144.144.<oracle-mesh-ip>'
```

**中继对（应通过中继可达）：**

```bash
# 阿里云 → N1 (需中继：阿里云无IPv6, N1无公网IPv4)
ssh -i ~/.ssh/deploy_key root@203.0.113.10 \
  'ping -c 10 10.144.144.<N1-mesh-ip>'

# 阿里云 → txcloud (需中继：txcloud对称NAT无入站)
ssh -i ~/.ssh/deploy_key root@203.0.113.10 \
  'ping -c 10 10.144.144.<txcloud-mesh-ip>'

# txcloud → Oracle ARM (需中继：IPv6不通)
ping -c 10 10.144.144.<oracle-mesh-ip>
```

**中继路径验证：** 中继成功时日志会显示：

```
[mesh-relay] dialer: requesting relay tunnel=<id> relay=<key> target=<key>
[mesh-relay] dialer: tunnel=<id> accepted
```

在中继节点上会显示：

```
[mesh-relay] relay request: tunnel=<id> target=<key>
```

如果中继失败，日志会显示：

```
[mesh] tryRelayFallback: no relay candidates (no eligible relay-capable peers)
```

这通常意味着：
1. 某些节点未启用 `proxy.relay.enabled: true` → 检查 §2.1
2. gossip 尚未收敛 → 等待更长时间 → 检查 §2.3
3. 到中继节点的 smux session 不存在 → 检查 §2.2
4. 中继节点 NatType 被标记为 "symmetric" → 检查 NAT 探测结果

### 4.4 验证停止条件对照

| 停止条件 | 验证方法 | 通过标准 |
|---------|---------|---------|
| 1. 四节点部署，任意两节点 TUN ping 成功 | §4.3 全部 6 对 | 6/6 可达 |
| 2. 能直连的节点对自动走直连，0% 丢包 | §4.3 直连对 | 3 对 0% 丢包 |
| 3. 不能直连的节点对自动走中继 | §4.3 中继对 | 3 对通过中继可达 |
| 4. go build/vet/test 通过，推送 GitHub | `go build ./... && go vet ./... && go test ./...` | 全绿 |

---

## 5. 中继回退工作原理（代码路径）

本节将讨论中 developer 被截断的技术细节补充完整。

### 5.1 连接生命周期

当 gossip 发现新节点 (NotifyJoin) 时，NAT 遍历状态机自动启动：

```
NotifyJoin (gossip event)
  → NatTraversal.InitiateConnection
    → runStateMachine (per-peer goroutine, nat.go:442)
      → STUN_DISCOVERY (handleStunDiscovery, nat.go:486)
        → if both sides symmetric NAT → transitionToRelay (nat.go:603)
        → else → DIRECT_PROBE (handleDirectProbe, nat.go:537)
          → if hole-punch succeeds → DIRECT → ACTIVE (nat.go:463)
          → if hole-punch fails → RELAY_FALLBACK
            → transitionToRelay → SelectBestRelay → circuit_setup via gossip
```

### 5.2 数据平面中继回退

当数据需要传输但无直连 session 时 (DialVirtualPort, node.go:1225)：

```
DialVirtualPort(targetKey)
  → if direct session exists → use it directly
  → else → tryRelayFallback (relay_dialer.go:316)
    → relayMetaProvider() collects CapRelay peers from gossip
    → filter: exclude self, target, at-capacity, symmetric-NAT, dead-session
    → sort by RTT ascending (lowest first)
    → DialViaRelay (relay_dialer.go:258) iterates each candidate:
        1. Look up smux session to relay (relay_dialer.go:89-94)
        2. Open stream on port 0x524C (relay_dialer.go:108)
        3. Send MeshRelayRequest{target=targetKey} (relay_dialer.go:115)
        4. Wait for MeshRelayResponse (10s timeout, relay_dialer.go:132)
        5. On accept → return stream as net.Conn
        6. On reject → try next candidate
```

### 5.3 中继 handler 转发逻辑

中继节点上的 `RelayHandler`（relay_handler.go:43）处理入站中继请求：

```
HandleStream (relay_handler.go)
  → read MeshRelayRequest
  → look up target session: GetSession(req.TargetKey) (relay_handler.go:179)
    → checks clientSessions first, then sessions (node.go:661-668)
  → open stream to target on port 0x524C (relay_handler.go:194)
  → send MeshRelayDial to target (relay_handler.go:214)
  → wait for target response (relay_handler.go:236)
  → on accept: bridge two streams via io.Copy (RelayStream, relay_dialer.go:214)
  → tunnel stays active until either side closes or idle timeout (5min)
```

### 5.4 健康监控与故障转移

两个独立的健康监控系统：

**P2P 层（NAT 中继路径）：**
- `RelaySessionManager`（relay_session.go:71）跟踪 circuit 生命周期
- PING/PONG 每 30 秒（DefaultRelayHeartbeatInterval, relay_handler.go:20）
- 空闲超时 5 分钟（DefaultRelayIdleTimeout, relay_handler.go:17）
- circuit_setup → circuit_accept → 转发 → circuit_teardown

**Proxy 层（匿名代理路径）：**
- `RelayHealthTracker`（relay_health.go:43）跟踪中继健康状态
- 三态：Healthy → Degraded (1-2次失败) → Unhealthy (3+次失败)
- 恢复冷却期 30 秒（DefaultHealthRecoveryDelay, relay_health.go:65）
- `RelaySelector`（relay_selector.go:28）按 RTT 评分选择 top-K 中继

### 5.5 交叉 IP 族中继

中继流量通过 smux session 传输，不是原始 IP。这意味着：

- 阿里云 (IPv4 only) 可以通过 Oracle ARM (双栈) 中继到 N1 (IPv6 only)
- 中继路径：阿里云 → smux session → Oracle ARM → smux session → N1
- 阿里云只需要到 Oracle ARM 的 smux session（IPv4 直连）
- Oracle ARM 只需要到 N1 的 smux session（IPv6 直连）
- 中继 handler 在 `GetSession` 时检查两个 session map（relay_handler.go:179,
  node.go:661），不区分 IPv4/IPv6 session

这就是为什么中继能解决跨 IP 族连通性问题——它复用已有的 smux session，
不需要中继节点同时连接两个 IP 族。

---

## 6. 故障排查

### 6.1 "no relay candidates" 错误

**日志：**
```
[mesh] tryRelayFallback: no relay candidates (no eligible relay-capable peers)
```

**排查步骤：**

1. 检查所有节点是否启用了 relay：
   ```bash
   # 在每个节点上
   grep -A2 "relay:" /etc/meshdesk/config.yaml
   # 或检查日志
   journalctl -u meshdesk | grep "Smux relay"
   ```

2. 检查 gossip 是否传播了 CapRelay：
   ```bash
   curl -s http://localhost:52888/api/topology | python3 -m json.tool
   # 检查每个节点的 role 是否包含 "relay"
   ```

3. 检查到中继节点是否有活跃 smux session：
   ```bash
   kill -USR1 $(pgrep meshdesk)
   journalctl -u meshdesk --no-pager -n 100 | grep "Sessions"
   ```

### 6.2 "no session to relay" 错误

**日志：**
```
mesh relay: no session to relay <key>
```

**原因：** 发起节点到中继节点没有 smux session。

**解决：** 确保普通节点已连接到共享节点。检查 gossip seeds 配置是否正确，
共享节点的 Reality TLS 是否正常工作。

### 6.3 "RelayRejectNoSessionToTarget" 错误

**日志：**
```
[mesh-relay] relay request: tunnel=<id> target=<key>
mesh relay: relay rejected: no session to target
```

**原因：** 中继节点到目标节点没有 smux session。这发生在中继节点尚未与目标
建立连接时。

**解决：** 等待 gossip 收敛和 smux session 自动建立。如果长时间不建立，
检查目标节点的网络可达性和 Reality TLS 配置。

### 6.4 中继工作但 TUN ping 不通

**原因：** 中继 session 建立但 TUN 路由未正确配置。

**排查：**
```bash
kill -USR1 $(pgrep meshdesk)
journalctl -u meshdesk --no-pager -n 100 | grep "TUN"
# 检查 TUN VirtualIP Routes 是否包含目标节点的 mesh IP
```

---

## 7. 配置参考

### 7.1 共享节点完整配置模板

```yaml
hostname: <hostname>
mesh:
  port: 52888
  gossip_port: 52888
reality:
  enabled: true
  private_key: "<X25519 私钥>"
  public_key: "<X25519 公钥>"      # 可选，可从私钥推导
proxy:
  relay:
    enabled: true
    max_circuits: 1024
    jitter_min_ms: 5
    jitter_max_ms: 50
    max_queue_depth: 256
p2p:
  enabled: true
  nat_traversal: true
  relay_mode: auto
  max_relay_hops: 2
  gossip_interval: 30
  gossip_probe_interval: 1
  direct_reprobe_interval: 120
  stun_servers:
    - "stun.l.google.com:19302"
    - "stun.cloudflare.com:3478"
  seeds:
    - "<对端共享节点 mesh IP>:52888"
```

### 7.2 普通节点完整配置模板

```yaml
hostname: <hostname>
mesh:
  port: 52888
  gossip_port: 52888
reality:
  enabled: false
proxy:
  relay:
    enabled: true                  # 普通节点也必须启用
p2p:
  enabled: true
  nat_traversal: true
  relay_mode: auto
  max_relay_hops: 2
  seeds:
    - "<阿里云 mesh IP>:52888"
    - "<N1 mesh IP>:52888"
```

### 7.3 关键配置字段说明

| 字段 | 位置 | 默认值 | 说明 |
|------|------|--------|------|
| `proxy.relay.enabled` | config.go:379 | `false` | **必须显式设为 true**。控制 CapRelay 和 RelayHandler 注册 |
| `p2p.relay_mode` | config.go:678 | `"auto"` | `auto`=自动选择中继, `manual`=仅手动配置, `disabled`=仅直连 |
| `p2p.max_relay_hops` | config.go:681 | `2` | NAT 遍历探测深度（不是中继转发跳数） |
| `proxy.relay.max_circuits` | config.go:395 | `1024` | 最大并发中继 circuit 数 |
| `p2p.gossip_interval` | config.go:693 | `30` | PushPull 全状态同步间隔（秒） |
| `p2p.direct_reprobe_interval` | config.go:699 | `120` | 中继模式下直连重探间隔（秒） |

---

## 8. 代码引用索引

| 组件 | 文件 | 行号 | 说明 |
|------|------|------|------|
| `tryRelayFallback` | `internal/mesh/relay_dialer.go` | 316 | 中继候选收集与过滤 |
| `DialViaRelay` | `internal/mesh/relay_dialer.go` | 258 | 遍历候选发起中继连接 |
| `DialViaRelay` (单候选) | `internal/mesh/relay_dialer.go` | 83 | 单个中继节点的连接流程 |
| `RegisterRelayHandler` | `internal/mesh/relay_dialer.go` | 164 | 注册 0x524C 端口监听 |
| `RelayHandler` | `internal/mesh/relay_handler.go` | 58 | 中继 handler 结构体 |
| `HandleStream` | `internal/mesh/relay_handler.go` | 101 | 处理入站中继请求 |
| `GetSession` | `internal/mesh/node.go` | 661 | 查找 smux session |
| `MeshRelayVirtualPort` | `internal/mesh/relay_protocol.go` | 14 | 0x524C 常量 |
| `RelayPeerInfo` | `internal/mesh/relay_dialer.go` | 18 | 中继元数据结构 |
| `SetRelayMetaProvider` | `internal/mesh/relay_dialer.go` | 46 | 注入 gossip 元数据回调 |
| `transitionToRelay` | `internal/p2p/nat.go` | 603 | NAT 状态机中继回退 |
| `SelectBestRelay` | `internal/p2p/relay_selector.go` | 87 | 选择最佳中继候选 |
| `GetRelayCandidates` | `internal/p2p/events.go` | 542 | 从 gossip 池获取 CapRelay 节点 |
| `EnableRelayMode` | `internal/p2p/gossip.go` | 1200 | 初始化 RelaySessionManager |
| `NodeMeta` | `internal/p2p/delegate.go` | 19 | gossip 节点元数据结构 |
| `CapRelay` | `internal/p2p/delegate.go` | 35 | relay 能力标志字段 |
| `RelaySessionManager` | `internal/p2p/relay_session.go` | 80 | circuit 生命周期管理 |
| `RelayHealthTracker` | `internal/proxy/relay_health.go` | 43 | 代理层中继健康跟踪 |
| `RelaySelector` | `internal/p2p/relay_selector.go` | 28 | RTT 评分选择器 |
| `RelayNodeConfig` | `internal/config/config.go` | 368 | relay 配置结构体 |
| `P2pConfig` | `internal/config/config.go` | 660 | P2P 配置结构体 |
| `Default()` | `internal/config/config.go` | 897 | 默认配置（relay.enabled=false） |
| relay 初始化 | `cmd/meshdesk/main.go` | 408 | P2P 层 EnableRelayMode 调用 |
| relay handler 注册 | `cmd/meshdesk/main.go` | 243 | Mesh 层 RegisterRelayHandler 调用 |
| `--relay` 标志 | `cmd/meshdesk/main.go` | 95 | 命令行启用 relay 模式 |
| `DumpState` | `internal/mesh/node.go` | 687 | SIGUSR1 状态转储 |

---

## 9. 参考

- **设计决策:** docs/DESIGN_DECISION_NO_GLOBAL_ROUTING.md
- **Motion:** motion-fb0fdd61c936 (adopted, unanimous)
- **AGENTS.md:** 四节点拓扑、连通性矩阵、停止条件 §1-4
- **讨论参与者:** architect, researcher, developer, tester, reviewer, writer, leader
