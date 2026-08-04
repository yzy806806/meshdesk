# MeshDesk ACL 访问控制配置指南

**版本:** 1.1
**状态:** 生产就绪
**最后更新:** 2026-08-04

## 概述

MeshDesk v1.1 引入了 TUN 虚拟网络流量的访问控制列表（ACL）功能。ACL 允许你在每个节点上定义精细的允许/拒绝规则，控制哪些 mesh 流量可以进出 TUN 接口。规则通过 gossip 协议自动传播到所有 peer，确保全网一致的安全策略。

## 核心概念

### 规则求值模型

```
入站/出站数据包
      │
      ▼
  ┌─────────────┐
  │ 规则 1 匹配？ │────是───→ 执行规则动作（allow / deny）
  └─────┬───────┘
        │ 否
        ▼
  ┌─────────────┐
  │ 规则 2 匹配？ │────是───→ 执行规则动作
  └─────┬───────┘
        │ 否
        ▼
       ...
        │
        ▼
  ┌──────────────┐
  │ 默认策略      │────→ 执行默认动作（allow 或 deny）
  └──────────────┘
```

- **从上到下求值：** 规则按 config.yaml 中的顺序逐一匹配
- **首次匹配即生效：** 第一个匹配的规则决定数据包的命运，后续规则不再检查
- **默认策略：** 没有规则匹配时应用的兜底动作

### 默认策略

| 策略 | 行为 | 适用场景 |
|------|------|----------|
| `allow`（默认） | 无匹配规则时放行流量 | 白名单模式：先允许所有，再拒绝特定流量 |
| `deny` | 无匹配规则时拒绝流量 | 黑名单模式：先拒绝所有，再允许特定流量 |

## 配置结构

### config.yaml 中 ACL 部分

```yaml
acl:
  # 是否启用 ACL 检查。false（默认）时所有流量放行（向后兼容）。
  enabled: true

  # 没有规则匹配时的默认策略。allow（默认）或 deny。
  default_policy: deny

  # 规则列表，从上到下求值，首次匹配即生效。
  rules:
    - action: allow
      description: "允许所有节点的 ICMP ping"
      src_cidr: "*"
      dst_cidr: "*"
      protocol: icmp

    - action: deny
      description: "禁止 N1 访问 txcloud 的 SSH"
      src_cidr: "10.144.144.2/32"
      dst_cidr: "10.144.144.5/32"
      protocol: tcp
      dst_port: 22

    - action: allow
      description: "允许所有节点访问 80/443"
      protocol: tcp
      dst_port: 80

    - action: allow
      description: "允许所有节点访问 80/443"
      protocol: tcp
      dst_port: 443
```

### 规则字段详解

| 字段 | 类型 | 必需 | 默认值 | 说明 |
|------|------|------|--------|------|
| `action` | string | 是 | — | `allow` 或 `deny` |
| `src_cidr` | string | 否 | `*`（匹配任意） | 源虚拟 IP，支持 CIDR（如 `10.144.144.0/24`）或精确 IP |
| `dst_cidr` | string | 否 | `*`（匹配任意） | 目标 IP，支持 CIDR 或精确 IP |
| `protocol` | string | 否 | `*`（匹配任意） | `tcp`、`udp`、`icmp` 或 `*` |
| `src_port` | int | 否 | `0`（匹配任意） | 源端口（仅 TCP/UDP 生效） |
| `dst_port` | int | 否 | `0`（匹配任意） | 目标端口（仅 TCP/UDP 生效） |
| `peer_id` | string | 否 | `*`（匹配任意） | 发送方 Ed25519 公钥（hex），限制特定节点 |
| `description` | string | 否 | — | 人类可读注释 |

### 匹配语义

- **CIDR 字段：** 支持标准 CIDR 表示法。`10.144.144.5/32` 仅匹配该精确 IP。`10.144.144.0/24` 匹配该子网内所有 IP。`*` 匹配任意。
- **协议字段：** `tcp`、`udp`、`icmp` 或 `*`。大小写不敏感。
- **端口字段：** `0` 表示不检查端口。设置具体值则仅匹配该端口。
- **peer_id 字段：** 节点的 Ed25519 公钥 hex 字符串（64 字符）。`*` 或空值匹配任意节点。

### CIDR 示例

```yaml
# 匹配整个 mesh 子网
src_cidr: "10.144.144.0/24"

# 仅匹配一个节点
dst_cidr: "10.144.144.5/32"

# 匹配任意（默认行为）
src_cidr: "*"
```

## Dashboard ACL 管理

### 查看 ACL 引擎状态

导航到 Dashboard → **ACL** 页面。Engine Status 卡片显示：
- **Enabled:** 当前 ACL 是否启用
- **Default Policy:** 当前默认策略
- **Total Allow / Deny:** 累计放行和拒绝的数据包数

### 查看命中统计

Rule Hit Statistics 表格显示每条规则的命中次数，帮助评估规则有效性：
- 从未命中的规则可能需要清理
- 命中异常增长的规则可能需要检查

### 管理规则

在 Current Rules 表格中可以：
- **添加规则：** 填写表单（Action、Source CIDR、Dest CIDR、Protocol、Ports、Peer ID、Description），点击「Add Rule」
- **编辑规则：** 点击规则行上的编辑按钮，修改后保存
- **删除规则：** 点击删除按钮
- **注意：** 规则从上到下求值，第一条匹配即生效。请合理安排规则顺序。

### 引擎控制

- **ACL Enabled：** 开关 ACL 包过滤
- **Default Policy：** 切换默认策略（Allow / Deny）
- 修改后点击「Apply Engine Settings」即时生效（热重载，无需重启服务）

## Gossip 传播机制

ACL 规则通过 gossip 协议（memberlist）在 mesh 网络内自动传播：

1. 每个节点在 `NodeMeta.ACLRules` 字段中广播自己的 ACL 规则（msgpack tag `ar`）
2. Peer 节点接收并存储来自其他节点的 ACL 规则
3. 规则通过挑战-应答加入协议分发给新加入节点

这意味着：
- 在一个节点上配置的 ACL 策略可以被全网节点知晓
- 开发者可以通过 peer ID 字段针对特定节点配置精细策略

## 实用场景

### 场景 1：隔离敏感节点（白名单模式）

```yaml
acl:
  enabled: true
  default_policy: deny
  rules:
    - action: allow
      description: "允许 ICMP ping（全网可达）"
      protocol: icmp

    - action: allow
      description: "仅 N1 可以 SSH 访问 txcloud"
      src_cidr: "10.144.144.2/32"
      dst_cidr: "10.144.144.5/32"
      protocol: tcp
      dst_port: 22

    - action: allow
      description: "允许访问 txcloud 的 HTTP 服务"
      protocol: tcp
      dst_port: 80

    - action: allow
      description: "允许访问 txcloud 的 HTTPS 服务"
      protocol: tcp
      dst_port: 443
```

### 场景 2：阻止特定节点访问（黑名单模式）

```yaml
acl:
  enabled: true
  default_policy: allow
  rules:
    - action: deny
      description: "禁止外部节点 SSH 访问内部网络"
      src_cidr: "10.144.144.200/32"
      protocol: tcp
      dst_port: 22

    - action: deny
      description: "禁止 P2P 文件共享端口的流量"
      dst_port: 6881
```

### 场景 3：按节点身份授权

```yaml
acl:
  enabled: true
  default_policy: deny
  rules:
    - action: allow
      description: "仅信任的出口节点可路由至外部"
      src_cidr: "10.144.144.3/32"
      protocol: tcp
      dst_port: 443
      peer_id: "abc123def456789..."  # 出口节点的 Ed25519 公钥
```

## 故障排除

### "规则不生效"

- 检查 `acl.enabled` 是否为 `true`
- 规则从上到下求值——更宽泛的规则可能先匹配并处理了数据包
- 验证 CIDR 格式正确（使用 CIDR 表示法，不要省略掩码）

### "Dashboard 看不到 ACL 页面"

ACL 页面需要 Dashboard Web UI 模式。确保：
- 启动了带 `--web` 参数的服务
- 浏览器访问 `http://<node-ip>:8080`

### "请求控制台热重载失败"

- 确保 `acl.enabled: true`
- `default_policy` 必须是 `allow` 或 `deny`（非空值自动回退为 `allow`）
- 每条规则的 `action` 必须是 `allow` 或 `deny`

## 实现细节（面向开发者）

ACL 引擎实现于 `internal/mesh/acl.go`：

- **并发安全：** `sync.RWMutex` 保护规则集，`atomic.Uint64` 跟踪命中统计（无需锁）
- **热重载：** `UpdateRules()` 原子替换整个规则集，零停机时间
- **包解析：** `parsePacketInfo()` 从原始 IP 包中提取 srcIP、dstIP、协议、端口——支持 IPv4 和 IPv6
- **规则编译：** `compileRule()` 在加载时预解析 CIDR，避免每个包都重复解析
- **统计导出：** `Stats()` 返回快照，包含各规则的命中计数和聚合 allow/deny 计数
- **gossip 编码：** `EncodeACLRulesForGossip()` 将规则编码为紧凑的管道分隔字符串用于传播
