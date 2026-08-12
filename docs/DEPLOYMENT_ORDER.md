# MeshDesk 部署顺序与验证报告


> ⚠️ **历史验证报告（2026-08-07）**：四节点部署顺序为当时阶段结论。
> 当前部署请参考 README 快速开始 + [ZONE_AWARE_TRANSPORT.md](ZONE_AWARE_TRANSPORT.md)。

**日期:** 2026-08-07
**关联:** motion-fb0fdd61c936, action item 5/5
**代码基线:** 4229ee7 (HEAD = origin/main)

## 1. 验证方法论：先验证，仅在证伪时补代码

本阶段的代码策略是 **零代码变更**：所有三个实现项（endpoint 广播、NotifyJoin 自动连接、中继回退）在 v1.2.1 及之前的开发中已完成，本阶段不添加新功能代码，仅通过配置启用中继能力。

验证流程：
1. 运行 `go build ./...` — 确认编译通过
2. 运行 `go vet ./...` — 确认静态分析通过
3. 运行 `go test -count=1 ./...` — 确认全部测试通过
4. **如果全部通过**：不添加代码，直接推送并文档化
5. **如果失败**：仅修复导致失败的代码，不添加新功能

## 2. 代码验证结果

| 检查项 | 结果 | 详情 |
|--------|------|------|
| `go build ./...` | ✅ PASS | 所有包编译成功 |
| `go vet ./...` | ✅ PASS | 无静态分析告警 |
| `go test -count=1 ./...` | ✅ PASS | 22 个包全部通过，0 FAIL |
| Git HEAD = origin/main | ✅ MATCH | HEAD 4229ee7 == origin/main |
| 停止条件 4 | ✅ SATISFIED | go build/vet/test 通过，HEAD 已推送 |

### 测试详情（22 packages）

```
ok  cmd/meshdesk                 0.109s
ok  internal/auth                0.135s
ok  internal/config              0.027s
ok  internal/crypto              0.018s
ok  internal/dns                 0.017s
ok  internal/handshake           0.634s
ok  internal/identity            0.006s
ok  internal/ipam                0.006s
ok  internal/join                0.221s
ok  internal/logging             0.010s
ok  internal/mesh                20.592s
ok  internal/monitor             50.506s
ok  internal/p2p                 39.597s
ok  internal/proxy               2.227s
ok  internal/service             0.008s
ok  internal/session             0.196s
ok  internal/smux                0.660s
ok  internal/systemd             2.006s
ok  internal/topology            0.002s
ok  internal/transfer            0.318s
ok  internal/tun                 0.044s
ok  internal/web                 29.270s
ok  internal/webssh              3.552s
```

全部 22 个测试包通过，0 失败。最长测试为 `internal/monitor`（50.5s）和 `internal/p2p`（39.6s）。

## 3. 部署顺序

四节点 relay 部署必须按以下顺序执行，不可打乱：

### 步骤 1：构建二进制（txcloud 本机）

```bash
cd /root/meshdesk && git checkout 4229ee7
GOOS=linux GOARCH=amd64 go build -o /tmp/meshdesk-amd64 ./cmd/meshdesk/
GOOS=linux GOARCH=arm64 go build -o /tmp/meshdesk-arm64 ./cmd/meshdesk/
```

### 步骤 2：先部署共享节点（阿里云 + N1）

两条共享节点链路必须先就绪，因为普通节点依赖它们建立 smux session。

**阿里云 (amd64):**
- 上传 meshdesk-amd64 → /usr/local/bin/meshdesk
- 配置 `proxy.relay.enabled: true`
- `systemctl restart meshdesk`

**N1 (arm64):**
- 上传 meshdesk-arm64 → /usr/local/bin/meshdesk
- 配置 `proxy.relay.enabled: true`
- `sudo systemctl restart meshdesk`

### 步骤 3：等待 gossip 收敛（90 秒）

共享节点间需要 2-3 个 gossip 周期完成元数据同步（CapRelay、endpoints、NAT 类型）。

### 步骤 4：后部署普通节点（txcloud + Oracle ARM）

普通节点会主动出站连接共享节点建立 smux session。

**txcloud (amd64):**
- 配置 `proxy.relay.enabled: true` + seeds 指向阿里云和 N1
- `systemctl restart meshdesk`

**Oracle ARM (arm64):**
- 配置 `proxy.relay.enabled: true` + seeds 指向阿里云和 N1
- `sudo systemctl restart meshdesk`

### 步骤 5：等待全网 gossip 收敛（90 秒）

确认四节点全部在线，CapRelay 元数据传播完成。

### 为什么这个顺序不可逆？

先共享后普通的原因是：普通节点启动后立即尝试连接 seeds 列表中的共享节点。如果共享节点未就绪，普通节点没有可建立 smux session 的对端。没有 smux session 就没有中继路径。

所有节点必须启用 `proxy.relay.enabled: true` 的原因是：中继对是交叉的——普通节点 (txcloud/Oracle) 为中继共享节点对 (aliyun↔N1) 提供中继，共享节点 (aliyun/N1) 为普通节点对 (txcloud↔Oracle) 提供中继。部分启用会导致某些节点对的 relay candidates 集合为空。

## 4. 验证顺序（部署后）

| 顺序 | 验证项 | 方法 | 通过标准 |
|------|--------|------|---------|
| 1 | CapRelay 配置传播 | `curl /api/topology` 或 SIGUSR1 状态转储 | 四节点均显示 relay 能力 |
| 2 | smux session 就绪 | SIGUSR1 状态转储 | 每节点至少 1 个活跃 session |
| 3 | 直连对 TUN ping | 阿里云→Oracle, N1→txcloud, N1→Oracle | 0% 丢包 |
| 4 | 中继对 TUN ping | 阿里云→N1, 阿里云→txcloud, txcloud→Oracle | 通过中继可达 |

验证顺序说明：先确认配置（1）和连接（2）正确，再进行 ping 测试（3→4）。如果 ping 失败但配置和连接都正确，再检查 relay 日志排查。

## 5. 相关文档

- [RELAY_DEPLOYMENT_GUIDE.md](./RELAY_DEPLOYMENT_GUIDE.md) — 完整部署指南（729 行，含前提条件、代码路径、故障排查）
- [DESIGN_DECISION_NO_GLOBAL_ROUTING.md](./DESIGN_DECISION_NO_GLOBAL_ROUTING.md) — 设计决策：不实现全局路由表
- [CONFIG_INVENTORY.md](CONFIG_INVENTORY.md) — 配置字段总览
