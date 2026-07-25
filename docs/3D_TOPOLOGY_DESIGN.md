# MeshDesk 3D Topology Visualization Design

**Version:** 1.0
**Status:** Proposed
**Created:** 2026-07-25
**Source:** User design discussion

---

## Overview

3D 实时拓扑可视化——在 Web UI 中用 Three.js 渲染 mesh 网络的 3D 拓扑图，展示节点连接、延迟、流量、circuit 路径。点击节点高亮其通信状态，用粒子动画展示多路径分散传输。

实用价值：运维诊断（一眼看延迟/断连）、代理 circuit 可视化（直观理解多路径分散）、mesh 健康监控。

## 技术选型

| 方案 | 大小 | 兼容单二进制 |
|------|------|-------------|
| **Three.js (minified)** | ~600KB | ✅ go:embed |
| D3.js force-directed | ~270KB | ✅ 但只有 2D |
| **Three.js + 力导向布局** | ~650KB | ✅ 3D 力导向 + 渲染 |

选择 Three.js minified，embed 进二进制。与现有 xterm.js（~500KB）同等量级。

```
web/static/js/
  ├── htmx.min.js          (14KB)
  ├── xterm.js + addons    (~500KB)
  ├── three.min.js         (600KB)  ← 新增
  └── topology.js          (自定义，~80KB)
```

## 资源约束

- Three.js minified ~600KB，embed 进二进制，不影响单二进制约束
- 渲染在客户端浏览器执行，不占用服务器 CPU
- 数据通过现有 SSE 推送，无新增传输层

## 节点渲染

每个节点是 3D 球体：

| 视觉属性 | 数据映射 |
|---------|---------|
| 颜色 | 角色：🔵入口 🟢relay 🟠exit ⚪普通 🔴异常 |
| 大小 | 资源量（CPU 核数 + 内存） |
| 亮度/发光 | 活跃 circuit 经过的节点发光 |
| 脉冲动画 | 异常节点红色脉冲 |

## 边渲染

节点间连接为 3D 线段：

| 视觉属性 | 数据映射 |
|---------|---------|
| 颜色 | 延迟梯度：🟢<50ms → 🟡<150ms → 🔴>150ms |
| 粗细 | 当前流量带宽 |
| 粒子流动 | 沿线粒子，速度 = 传输速率，方向 = 数据流向 |

## 交互设计

### 悬停节点
- 显示 tooltip：hostname, mesh IP, role, CPU/mem 概览
- 相连边高亮

### 点击节点
1. 相机平滑过渡（tween）到该节点
2. 所有连接边高亮，其他变暗
3. 弹出详情面板（SSE 实时数据）：
   ```
   节点: ARM (10.144.144.3)
   角色: relay
   CPU: 2核 (23%)
   内存: 11GB (10%)
   延迟矩阵: →AMD1=2ms →AMD2=2ms →阿里云=45ms
   活跃 circuit: 3 条
   流量: 入 12MB/s 出 8MB/s
   ```

### Circuit 可视化（杀手锏功能）

点击一条活跃 circuit：
- 入口 → relay → exit 的完整路径用发光线段展示
- 多路径用不同颜色区分（路径1绿色，路径2蓝色）
- **粒子分散动画**：数据在入口"打散"成多个粒子 → 沿不同路径飞行 → 在 exit 处"重组"合并
- 动画展示乱序到达 + 重组过程

### 全局视图
- 鼠标拖拽旋转 3D 场景
- 滚轮缩放
- 双击节点重置视角
- 节点上线/下线：球体淡入/淡出动画

## 后端 API

### GET /api/topology

返回完整拓扑快照：

```json
{
  "nodes": [
    {
      "id": "arm",
      "hostname": "ARM",
      "mesh_ip": "10.144.144.3",
      "role": "relay",
      "cpu_cores": 2,
      "memory_gb": 11,
      "cpu_pct": 23,
      "mem_pct": 10,
      "status": "online"
    }
  ],
  "edges": [
    {
      "from": "arm",
      "to": "amd1",
      "latency_ms": 2,
      "bandwidth_bps": 12000000,
      "status": "active"
    }
  ],
  "circuits": [
    {
      "id": "c-abc",
      "entry": "入口A",
      "exit": "exit-东京",
      "paths": [
        {"hops": ["入口A", "relay-B", "exit-东京"], "latency_ms": 45},
        {"hops": ["入口A", "relay-C", "relay-D", "exit-东京"], "latency_ms": 62}
      ]
    }
  ]
}
```

数据来源：
- nodes → mesh routing table + monitor store（已有）
- edges → mesh routing table peer connections + RTT（已有）
- circuits → circuit 管理模块（代理功能新增）

### SSE /api/topology/events

实时推送增量更新：
- `node_join` / `node_leave` → 球体出现/消失
- `latency_update` → 边颜色渐变
- `traffic_update` → 粒子流速 + 边粗细变化
- `circuit_create` / `circuit_close` → 路径发光动画

## 前端实现

### 文件结构

```
web/
├── static/
│   ├── js/
│   │   ├── three.min.js           ← 新增 embed
│   │   └── topology.js            ← 新增自定义
│   └── css/
│       └── topology.css           ← 新增
└── templates/
    └── topology.html              ← 新增页面
```

### topology.js 模块结构

```javascript
// 1. Scene setup (Three.js Scene, Camera, Renderer)
// 2. Force-directed 3D layout (节点位置计算)
// 3. Node rendering (球体 + 材质 + 发光效果)
// 4. Edge rendering (线段 + 粒子系统)
// 5. Interaction (Raycaster 点击检测, OrbitControls 旋转缩放)
// 6. Data layer (fetch topology, SSE 订阅, 增量更新)
// 7. Circuit animation (粒子分散 + 重组动画)
// 8. UI overlay (详情面板, 图例, 状态栏)
```

### 性能优化

- **LOD (Level of Detail)**：远距离节点简化渲染
- **InstancedMesh**：同类节点用实例化渲染
- **粒子池**：复用粒子对象，避免 GC 压力
- **帧率自适应**：降帧到 30fps 如果设备性能不足

## 导航集成

Dashboard 导航栏新增 "Topology" 标签：
```
[Dashboard] [Peers] [Terminal] [Files] [Services] [Topology] ← 新增
```

Topology 页面全屏渲染 3D 场景，右侧可折叠详情面板。

## 实现任务分解

| # | Task | Assignee | 依赖 |
|---|------|-----------|------|
| 1 | embed three.min.js + 基础 3D 场景搭建 | developer | - |
| 2 | 拓扑数据 API (/api/topology) | developer | - |
| 3 | 3D 力导向布局 + 节点球体渲染 | developer | 1 |
| 4 | 边渲染 + 延迟颜色编码 | developer | 3 |
| 5 | 交互（OrbitControls + 点击 + 悬停） | developer | 3 |
| 6 | SSE 实时更新（节点上下线/延迟/流量） | developer | 2,4 |
| 7 | Circuit 路径动画（粒子分散 + 重组） | developer | 5,6 |
| 8 | 详情面板 + 图例 + UI 打磨 | writer | 5 |
| 9 | 性能优化（LOD/实例化/粒子池） | developer | 7 |
| 10 | 拓扑页测试（mock 数据 + 真实数据） | tester | 7 |

## Mock 数据支持

开发和测试阶段使用 mock 拓扑数据，不需要真实 mesh 部署：

```javascript
// 开发模式：?mock=1 加载假数据
const MOCK_TOPOLOGY = {
  nodes: [
    {id: "entry-a", hostname: "入口A", role: "entry", ...},
    {id: "relay-b", hostname: "Relay-B", role: "relay", ...},
    ...
  ],
  edges: [...],
  circuits: [...]
};
```

Tester 可以用 mock 数据验证 3D 渲染、交互、动画，不依赖 mesh 运行。
