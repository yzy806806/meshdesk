# MeshDesk 四节点 Relay 标准部署与验证

**版本:** 1.3  
**状态:** 生产就绪  
**最后更新:** 2026-08-07

## 概述

MeshDesk 的跨节点互联依赖中继（relay）机制：当两个节点因网络隔离（IPv4↔IPv6、CGNAT、对称 NAT）无法直连时，通过第三方节点中转 smux 流量。Relay 运行在虚拟端口 `0x524C` 上，由两个子系统协同工作：

| 子系统 | 代码位置 | 作用 |
|--------|---------|------|
| Mesh 层 relay handler | `internal/mesh/relay_dialer.go:164` `RegisterRelayHandler()` | 监听 `0x524C`，桥接两个 peer 的 smux stream |
| P2P 层 relay mode | `internal/p2p/gossip.go:1223` `EnableRelayMode()` | 在 gossip NodeMeta 中设置 `CapRelay=true`，让其他节点知道本节点可中转 |

**关键前提：两个子系统由同一开关控制。** `proxy.relay.enabled: true` 同时启用 mesh 层 relay handler 和 p2p 层 CapRelay 广播。缺少任一层都会导致 relay 静默失败。

## 为什么所有四节点都必须 relay 全开

四节点拓扑的 relay 需求是**交叉**的——不存在一个"只负责中转"的专用节点：

```
共享节点（公网可达）：
  阿里云 (IPv4-only) ──── 需要中继 ──── N1 (IPv6-only)
  普通节点（出站连接）：
  txcloud (dual-stack) ─── 需要中继 ─── Oracle ARM (dual-stack)
```

- **阿里云 ↔ N1**：阿里云无 IPv6，N1 无公网 IPv4，无法直连。需要 txcloud 或 Oracle ARM 作为中继——它们是**普通节点**。
- **txcloud ↔ Oracle ARM**：IPv6 不通（txcloud IPv6 出站无法到达 Oracle ARM IPv6），需要阿里云或 N1 作为中继——它们是**共享节点**。

如果只给共享节点开 relay、普通节点不开：
- 阿里云和 N1 都在共享节点对中，`tryRelayFallback` 排除目标 peer → 零候选 → 直连失败且无中继可用。
- txcloud ↔ Oracle ARM 同理。

**因此**：`proxy.relay.enabled: true` 必须在**全部四个节点**上设置。

## 配置

每个节点的 `/etc/meshdesk/config.yaml` 必须包含：

```yaml
proxy:
  relay:
    enabled: true       # 必须 — 同时激活 mesh 层 relay handler 和 p2p 层 CapRelay
    max_circuits: 1024  # 可选 — 默认 1024，限制并发中转电路数
```

启动时如果 relay 已启用，日志中会出现两条确认：

```
Smux relay: listening on virtual port 0x524C (maxTunnels=64)
P2P:       relay mode active (maxCircuits=1024)
```

也可以用 `--relay` 命令行 flag（等价于 `proxy.relay.enabled: true`），但推荐写在 config 中以保证重启一致性。

**重要：配置改动后必须重启 meshdesk 才生效。** `CapRelay` 标志仅在节点启动加入 gossip 集群的首轮 meta 广播中宣告（`EnableRelayMode` 在 `gossip.go:1200` 初始化阶段调用）。运行时修改 `proxy.relay.enabled` 不会动态更新已广播的 gossip metadata——新值只有在下次重启时随首轮 gossip meta 一起发出。

### 完整配置要点

除 relay 外，四节点部署还需要：

- **identity_file 持久化**：所有节点使用 `/etc/meshdesk/identity.pem`，防止重启后公钥变化导致 collector/peer 引用失效。
- **gossip_probe_interval ≥ 5s**：默认 1s 在跨网络场景（IPv4↔IPv6）会导致 UDP 探测超时 → suspect → leave → rejoin 循环。
- **共享节点设置 advertise_endpoints**：阿里云写公网 IPv4，N1 写公网 IPv6 + DNS 名。
- **普通节点 seeds 指向共享节点公网地址**：不写 mesh IP / EasyTier IP。
- **单端口复用**：`mesh.port`、`mesh.gossip_port`、`reality.listen_port` 统一为 52888。

## 验证流程

### 第一步：启动顺序

关键约束：**先启动共享节点、再启动普通节点。** 普通节点的 seeds 写的是共享节点的公网地址，如果共享节点未就绪则 join 失败。

推荐顺序：阿里云 → N1 → txcloud → Oracle ARM。

### 第二步：config 审计门（部署前）

在每台机器上执行，确认 relay 已启用：

```bash
grep -A3 'relay:' /etc/meshdesk/config.yaml
```

预期输出包含 `enabled: true`。

### 第三步：SIGUSR1 dump — mesh 层验证

每台机器上执行：

```bash
# 获取 PID
pid=$(pgrep -f 'meshdesk.*--web' || pgrep meshdesk | head -1)

# 发送 SIGUSR1 触发状态 dump
kill -USR1 $pid

# 查看 dump 输出
journalctl -u meshdesk --since "10 seconds ago" | grep -A1 "=== Relay"
```

预期输出（relay handler 已注册）：

```
=== Relay: active (tunnels=0) ===
```

`tunnels=` 后的数字是当前活跃的中转隧道数——部署初期通常为 0，随着节点互联会增加。

如果输出 `=== Relay: disabled ===`，说明 mesh 层 relay handler 未注册——检查 `proxy.relay.enabled` 和启动日志中是否有错误。

### 第四步：gossip CapRelay — p2p 层验证

SIGUSR1 dump 只显示 mesh 层状态。gossip 层的 `CapRelay` 标志通过 gossip NodeMeta 传播，需要从日志或代码层面确认。

**方法一 — 启动日志检查。** 如果 `proxy.relay.enabled: true` 被正确读取，启动日志中会有：

```
[p2p] relay mode enabled (maxCircuits=1024)
```

**方法二 — 检查 gossip 候选过滤。** 当两个节点尝试通过 relay 连接时，日志中会出现 relay 候选数——如果候选数为 0，说明某个节点的 `CapRelay` 没有被传播：

```
[mesh] tryRelayFallback: N relay-capable candidate(s) for target <peer>...
```

如果 N=0，检查是否有节点缺少 `proxy.relay.enabled: true`。

### 第五步：6 对 TUN ping 矩阵

部署完成后，在每台机器上 ping 其他三台机器的 TUN VirtualIP。

**测试顺序：先验证直连对，再验证中继对。** 直连对（同 IP 族、网络可达）验证通过后，中继对的测试结果才具有诊断意义——如果直连对也失败，问题可能出在基础连通性而非 relay 机制。

直连对（预期 0% 丢包，较低延迟）：

| 源 → 目标 | 延迟参考 |
|-----------|---------|
| N1 → txcloud | 108ms |
| txcloud → N1 | 108ms |
| N1 → Oracle ARM | 294ms |
| Oracle ARM → N1 | 294ms |
| 阿里云 → txcloud | IPv4 通 |
| txcloud → 阿里云 | IPv4 通 |
| 阿里云 → Oracle ARM | 273ms |
| Oracle ARM → 阿里云 | 273ms |

中继对（预期经 relay 中转，延迟高于直连）：

| 源 → 目标 | 原因 |
|-----------|------|
| 阿里云 → N1 | IPv4↔IPv6 不可直连 |
| N1 → 阿里云 | IPv4↔IPv6 不可直连 |
| txcloud → Oracle ARM | IPv6 不通 |
| Oracle ARM → txcloud | IPv6 不通 |

```
节点          VirtualIP（示例，实际依公钥哈希计算）
阿里云       10.100.0.X
N1           10.100.0.Y
txcloud      10.100.0.Z
Oracle ARM   10.100.0.W
```

TUN ping 命令（在每台机器上替换 VirtualIP）：

```bash
ping -c 3 10.100.0.X
```

**直连 vs 中继判定**：如果两个节点在同一 IP 族（IPv4↔IPv4 或 IPv6↔IPv6）且网络可达，预期走直连（0% 丢包，延迟较低）。跨 IP 族对预期走中继——可接受的延迟比直连高（一跳到两跳 relay 的额外开销）。如果实际路径与预期偏离（如预期直连却走了中继），检查 NAT 穿透日志和 relay 候选选择。

### 第六步：failover 注入

验证 relay 失败时自动切换候选路径：

1. **确定活跃路径。** 选一个走 relay 的节点对（如 阿里云 ↔ N1），记录当前中继节点。
2. **注入故障。** 在中继节点上 kill meshdesk：

   ```bash
   kill -9 $(pgrep meshdesk)
   ```

3. **观察 failover。** 在通信双方（阿里云、N1）的日志中观察：

   ```
   [mesh] tryRelayFallback: N relay-capable candidate(s) for target <peer>...
   ```

   候选数应从 `N` 变为 `N-1`（排除已死的 relay），且连接切换到次优候选（按 RTT 排序）。

4. **确认恢复。** TUN ping 应该在 10-30 秒内恢复（取决于 gossip 收敛时间和 smux 重连间隔）。

5. **恢复中继节点后**，重启被 kill 的节点，确认 gossip 重新加入且 CapRelay 恢复。

## 已知限制

### 零候选静默失败

`tryRelayFallback`（`internal/mesh/relay_dialer.go:396`）在找不到任何 relay 候选时只输出一行日志：

```
no relay candidates (no eligible relay-capable peers)
```

**无指标暴露、无告警。** 运维人员需要主动监控日志才能发现。候选为 0 的典型原因：

- 某个节点未设置 `proxy.relay.enabled: true` → CapRelay 未广播
- 目标 peer 和所有 relay 候选之间没有活跃 smux session
- relay 候选的 NAT 类型为 symmetric（被过滤）

**后期待办**：为 relay 候选健康度增加 metrics 出口（Prometheus/日志结构化），并在候选持续为 0 时输出 WARNING 级别日志。

### 多跳中继未实现

当前 relay 路径仅支持 **单跳**（A → relay → B）。多跳中继（A → r1 → r2 → B）和全局路由表（Peer Center 风格的拓扑广播 + 最优路径选择）不在当前版本范围。

**影响**：在四节点拓扑中影响不大——单跳 relay 已足够覆盖所有跨 IP 族对。在更大规模部署中，如果不存在任何单个节点同时与 A 和 B 有 session，连接会失败。

**后期待办**：实现全局 peer 拓扑表 + 多跳 relay 路径选择，参考 EasyTier 的 Peer Center 设计。

### NAT 穿透超时后 relay fallback 不触发

`tryRelayFallback` 的触发依赖 NAT 穿透状态机（`STUN → DirectProbe → RelayFallback`）。如果 `DirectReprobeInterval`（默认 120s）过长，直连失败后需要等待 120 秒才会进入 relay fallback。对于明确不可直连的节点对（如跨 IP 族），这 120 秒是空等的。

**缓解**：可将 `p2p.direct_reprobe_interval` 调小（如 30s），或在首次连接时通过 gossip metadata 预先判断 IP 族兼容性，跳过不必要的直连探测。

## 故障排除

| 症状 | 可能原因 | 检查方法 |
|------|---------|---------|
| `=== Relay: disabled ===` | config 中 `proxy.relay.enabled` 未设置或为 false | `grep -A3 'relay:' /etc/meshdesk/config.yaml` |
| `no relay candidates` | 某个节点 relay 未开 → CapRelay 未广播 | 逐个节点检查 SIGUSR1 dump + `[p2p] relay mode enabled` 日志 |
| 跨 IP 族对 TUN ping 不通 | 没有 relay 候选或 relay handler 未注册 | 检查日志中 `tryRelayFallback` 的候选数 |
| gossip 节点反复 suspect/leave/rejoin | `gossip_probe_interval` 太小（默认 1s） | 设为 5s 及以上 |
| relay 候选加载满了 | `max_circuits` 太小 | `grep max_circuits /etc/meshdesk/config.yaml`，默认 1024 通常够用 |

## 参考

- [多路径优化说明](MULTI_PATH_OPTIMIZATION_v1.1.md) — relay 候选过滤、RTT 排序、健康检查 FSM 的详细文档
- [SOCKS5 代理指南](SOCKS5_PROXY_GUIDE.md) — relay 在 SOCKS5 代理路径中的角色
- [systemd 部署指南](SYSTEMD_DEPLOY_GUIDE_v1.1.md) — 服务安装、日志管理、升级流程
- 代码参考：`internal/mesh/relay_dialer.go`（中继连接发起）、`internal/mesh/relay_handler.go`（中继流桥接）、`internal/p2p/gossip.go:1200`（EnableRelayMode）
