# MeshDesk 多路径优化说明

**版本:** 1.1
**状态:** 生产就绪
**最后更新:** 2026-08-04

## 概述

MeshDesk v1.1 引入了 relay 多路径优化功能，包含三个核心能力：

1. **RTT 延迟探测：** 自动测量到各个 relay 节点的往返时延，优先选择低延迟路径
2. **自动 failover：** 当活跃路径上的 relay 节点故障时，自动切换到次优候选路径
3. **健康检查：** 持续监控 relay 节点状态，动态剔除不健康节点

这些优化让 SOCKS5 代理的路径选择从纯手动配置升级为全自动、延迟感知、自愈的智能路由。

## 架构

```
                        ┌─────────────────────────────────────┐
                        │          Gossip 层                   │
                        │  ┌─────────┐    ┌─────────────────┐ │
                        │  │ RTT 广播 │    │ NodeMeta 传播    │ │
                        │  │ (每 5s)  │    │ (CapRelay 等)    │ │
                        │  └────┬────┘    └────────┬────────┘ │
                        └───────┼──────────────────┼──────────┘
                                │                  │
          ┌─────────────────────┼──────────────────┼──────────┐
          │                Mesh 层                   │         │
          │  ┌──────────────────▼──────────────────┐ │         │
          │  │      RelayMetaProvider               │ │         │
          │  │  (从 gossip 提供 RelayPeerInfo 列表)   │ │         │
          │  └──────────────────┬──────────────────┘ │         │
          │                     │                     │         │
          │  ┌──────────────────▼──────────────────┐ │         │
          │  │      tryRelayFallback                │ │         │
          │  │  • 过滤 CapRelay                     │ │         │
          │  │  • 排除 at-capacity relays           │ │         │
          │  │  • 排除 symmetric NAT relays         │ │         │
          │  │  • RTT 升序排序                       │ │         │
          │  └──────────────────┬──────────────────┘ │         │
          └─────────────────────┼────────────────────┘         │
                                │                              │
          ┌─────────────────────┼──────────────────────────────┘
          │                Proxy 层
          │  ┌──────────────────▼───────────────────────┐
          │  │          PathSelector                     │
          │  │  • SelectPaths: 选择两条最优不相交路径      │
          │  │  • SelectReplacementPath: 自动 failover    │
          │  │  • 质量评分: RTT + hop数 + 容量 + 健康罚分  │
          │  └──────────────────┬───────────────────────┘
          │                     │
          │  ┌──────────────────▼───────────────────────┐
          │  │        RelayHealthTracker                 │
          │  │  • 三态 FSM: Healthy → Degraded → Unhealthy│
          │  │  • 恢复冷却: 30s（防止 flapping）          │
          │  │  • 健康罚分: 健康=1.0, 降级=1.5, 不健康=∞│
          │  └──────────────────────────────────────────┘
          └──────────────────────────────────────────────┘
```

## 功能 1：RTT 延迟探测

### 工作原理

```
1. Gossip 健康轮询循环 (每 5s)
   │
   ├── 测量到所有已知 peer 的平均 RTT
   │    (通过 smux session Ping 或 TCP 拨号)
   │
   ├── 将本地 RTT 写入 NodeMeta.RTTUs 字段
   │
   └── gossip 协议自动传播到全网

2. Relay 候选收集 (tryRelayFallback)
   │
   ├── 通过 RelayMetaProvider 回调获取 relay 候选列表
   │
   ├── 过滤：仅保留 CapRelay=true 的节点
   ├── 过滤：排除已满载（LoadCircuits >= MaxCircuits）的 relay
   ├── 过滤：排除 symmetric NAT relay（不可靠中转）
   │
   ├── RTT 升序排序（最低延迟优先）
   │    • 有 RTT 数据的 relay：按测量值排序
   │    • RTT=0（未知）的 relay：排在末尾，但仍可候选
   │
   └── 按顺序尝试 relay，直到连接成功

3. 路径质量评分 (PathSelector)
   │
   └── Score = RTT_ms + hopCount × 50 + capacity_penalty
        • RTT_ms: 总路径延迟（毫秒）
        • hopCount × 50: 每跳 50ms 固定罚分
        • capacity_penalty: 低容量 relay 额外罚分
```

### 路径选择算法（SelectPaths）

```
候选 relay 列表 (N 个)
      │
      ▼
健康过滤 ──→ 排除 Unhealthy 的 relay（除非满足 retry 冷却）
      │
      ▼
RTT 预过滤 ──→ 按 advertised RTT 排序，取前 K 个（默认 K=10）
      │
      ▼
并行探测 ──→ 对 K 个候选发送探测包，记录实际 RTT
      │           并发数: 8，超时: 3s
      ▼             缓存 TTL: 30s（避免重复探测）
      │
      ▼
健康更新 ──→ 成功 → RecordSuccess → Healthy
      │      失败 → RecordFailure → Degraded/Unhealthy
      ▼
      │
不相交选择 ──→ 从探测结果中选择两条节点不相交的最优路径
      │          硬性要求：两条路径不能共享任何 relay 节点
      ▼              （防止 relay 通过时序分析关联 entry↔exit）
      │
路径 1 + 路径 2
```

## 功能 2：Relay 健康检查

### 三态有限状态机

```
      ┌─────────────────────────────────────────────┐
      │                                             │
      ▼                                             │
  ┌──────────┐    1 次失败    ┌───────────┐    3 次失败   ┌────────────┐
  │ Healthy  │──────────────→│ Degraded  │─────────────→│ Unhealthy  │
  │          │               │           │              │            │
  │ 可选入路径│               │ 可选入路径  │              │ 排除出路径  │
  │ 罚分=1.0 │               │ 罚分=1.5   │              │ 罚分=∞     │
  └──────────┘               └─────┬─────┘              └─────┬──────┘
       ▲                           │                          │
       │      下次成功探针           │  等待恢复冷却 (30s) 后    │
       │      → 重置失败计数         │  成功探针 → 恢复        │
       └───────────────────────────┴──────────────────────────┘
```

### 状态说明

| 状态 | 条件 | 路径选择行为 | 质量罚分 |
|------|------|-------------|----------|
| **Healthy** | 0 次连续失败 | 正常候选 | 1.0（无罚分） |
| **Degraded** | 1-2 次连续失败 | 仍可候选，质量降级 | 1.5（50% 罚分） |
| **Unhealthy** | 3+ 次连续失败 | 排除出路径选择 | ∞（等同于排除） |

### 恢复冷却机制

Unhealthy relay 不会永久排除。30 秒冷却后，允许重新探测：

- 如果重新探测成功 → 立即恢复到 Healthy（`RecordSuccess` 重置失败计数）
- 如果仍然失败 → 继续留在 Unhealthy（失败计数递增）
- 冷却机制防止 relay 在 Healthy/Unhealthy 之间快速抖动（flapping）

## 功能 3：自动 Failover

### 故障切换流程

```
活跃路径的 relay 节点不可用
          │
          ▼
路径健康探针检测到连续失败
          │
          ▼
RelayHealthTracker 标记为 Unhealthy (3 次失败后)
          │
          ▼
MarkRelayUnhealthy() 触发
          │
          ▼
SelectReplacementPath() 被调用
    ├── 排除已标记为不健康的 relay
    ├── 从剩余的 Healthy/Degraded 候选中选择最佳
    ├── 并行探测（并发 8，超时 3s）
    └── 返回最佳替换路径
          │
          ▼
新路径建立，数据流恢复
```

### SelectReplacementPath 实现

```go
func (ps *PathSelector) SelectReplacementPath(
    ctx context.Context,
    candidates []CandidateRelay,
    exitAddr string,
    failedRelayIDs map[string]bool,  // 失败的 relay 黑名单
) (*Path, error)
```

- 排除 `failedRelayIDs` 中列出的所有 relay
- 再次过滤不健康的 relay（除非满足 retry 冷却）
- 从剩余候选中探测并选择得分最低的路径

## 技术实现细节

### NodeMeta 扩展

```go
// internal/p2p/delegate.go — NodeMeta 新增字段
type NodeMeta struct {
    // ...原有字段...
    RTTUs    uint32   `msgpack:"ru"`  // 本地到各 peer 的 RTT（微秒）
    ACLRules []string `msgpack:"ar"`  // ACL 规则（管道分隔编码）
}
```

### tryRelayFallback 升级

新版本 `tryRelayFallback`（`internal/mesh/relay_dialer.go:316`）：
- **智能模式（有 meta provider）：** 按 gossip NodeMeta 信息过滤和排序 relay 候选
- **Legacy 模式（无 meta provider）：** 回退到尝试所有有活跃 session 的 peer

过滤条件：
1. 排除自身和目标节点
2. 必须标记 `CapRelay=true`
3. 排除已满载（`LoadCircuits >= MaxCircuits`）
4. 排除 symmetric NAT（不可靠中转）
5. 必须有活跃 session

### 路径不相交检测

```
路径 1: entry → relay-A → relay-B → exit
路径 2: entry → relay-C → relay-D → exit

要求: {A, B} ∩ {C, D} = ∅

原因: 如果两个路径共享一个 relay 节点，
      该 relay 可以通过时序关联 entry↔exit，
      即使数据已加密（仅限密文访问）
```

## 与 v1.0 的区别

| 特性 | v1.0 | v1.1 |
|------|------|------|
| 路径选择 | 手动配置 `proxy.paths` | RTT 探测 + 自动选择 |
| relay 排序 | 随机 / 配置顺序 | RTT 升序（低延迟优先） |
| 故障感知 | 无 | 三态 FSM 健康追踪 |
| 自动 failover | 无 | `SelectReplacementPath()` |
| 负载感知 | 无 | 排除满载 relay |
| NAT 感知 | 无 | 排除 symmetric NAT relay |
| RTT 传播 | 无 | gossip NodeMeta 传播 |
| 探测缓存 | 无 | 30s TTL 避免重复探测 |

## 配置方式

多路径优化在 `proxy.path_selection` 配置段：

```yaml
proxy:
  path_selection:
    mode: "auto"              # "manual"（v1.0 行为）或 "auto"（v1.1）
    strategy: "latency"       # "latency" / "random" / "round-robin"
    max_relays_per_path: 2    # 每条路径最大 relay 跳数
    probe_timeout_sec: 3      # 探测超时（秒）
    probe_concurrency: 8      # 并行探测数
    max_candidates: 10        # 最大候选探测数（O(K) 扩展）
    probe_cache_ttl_sec: 30   # 探测结果缓存时间（秒）
```

设置为 `mode: "auto"` 即启用 v1.1 的多路径优化。默认回退为 `mode: "manual"`（v1.0 行为，使用 `proxy.paths` 中手动配置的路径）。
