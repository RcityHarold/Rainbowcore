# Connected Node 准入流程文档

## 概述

本文档描述 DSN（Distributed Storage Network）中 Connected Node（连接节点）的准入控制机制，包括注册流程、硬性要求、信任评分系统和访问控制策略。

## 目录

- [核心概念](#核心概念)
- [硬性要求（Hard Requirements）](#硬性要求hard-requirements)
- [节点类型](#节点类型)
- [注册流程](#注册流程)
- [信任评分系统](#信任评分系统)
- [节点连通性分类](#节点连通性分类)
- [准入检查](#准入检查)
- [健康监控](#健康监控)
- [节点生命周期管理](#节点生命周期管理)
- [API 使用示例](#api-使用示例)

---

## 核心概念

Connected Node 准入控制系统管理以下关键功能：

1. **节点注册** - 验证节点凭证和资格
2. **信任评分** - 基于行为的动态信任度量
3. **准入控制** - 仅允许受信任节点参与网络
4. **健康监控** - 持续监测节点健康状态
5. **驱逐机制** - 移除不当行为的节点

### 实现位置

- **核心代码**: `p2-core/src/node_admission.rs`
- **主要结构**: `NodeAdmissionController`, `ConnectedNode`, `R0SkeletonStatus`, `P1ConnectionStatus`

---

## 硬性要求（Hard Requirements）

根据 DSN 文档第二章，Connected Node **必须**满足以下两个硬性要求：

### 1. P1 连接（L0 Receipt Chain）

节点必须与 P1（L0 共识层）建立有效连接，能够同步和验证 receipt。

**验证条件**:
- `p1_status.connected == true`
- `p1_status.healthy == true`
- 定期成功同步 receipt

**相关结构**:
```rust
pub struct P1ConnectionStatus {
    pub connected: bool,
    pub endpoint: Option<String>,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_receipt_id: Option<String>,
    pub healthy: bool,
    pub error: Option<String>,
}
```

### 2. R0 Skeleton Package

节点必须拥有有效的 R0 骨架包（R0 skeleton package），包含生命复活所需的最小状态。

**验证条件**:
- `r0_status.has_r0 == true`
- `r0_status.verified == true`
- R0 digest 已记录并可验证
- 关联有效的 `SnapshotMapCommit` 或 `payload_map_commit`

**相关结构**:
```rust
pub struct R0SkeletonStatus {
    pub has_r0: bool,
    pub r0_digest: Option<Digest>,
    pub created_at: Option<DateTime<Utc>>,
    pub last_verified_at: Option<DateTime<Utc>>,
    pub verified: bool,
    pub verification_error: Option<String>,
    pub snapshot_map_commit_ref: Option<String>,
}
```

### ⚠️ 未满足硬性要求的后果

不满足 P1 或 R0 要求的节点被归类为 **"local-only"（仅本地）**节点，**无法**：

- ❌ 参与跨节点对账（cross-node reconciliation）
- ❌ 被其他 connected nodes 识别
- ❌ 分享或接收 payload mappings
- ❌ 执行需要网络协作的操作

---

## 节点类型

DSN 支持以下节点类型，每种类型有不同的最低信任评分要求和能力：

| 节点类型 | 描述 | 最低信任分 | 能力 |
|---------|------|-----------|------|
| **Storage** | 存储加密 payload | 0.7 | 可读、可写、存储数据 |
| **Validator** | 验证操作 | 0.9 | 可读、可写、验证、存储 |
| **Relay** | 路由流量 | 0.6 | 仅中继，不存储 |
| **Gateway** | 外部 API 网关 | 0.8 | 可读、可写、中继 |
| **Light** | 轻量级客户端 | 0.3 | 仅读 |

### 节点能力配置

每种节点类型有默认的能力配置：

```rust
pub struct NodeCapabilities {
    pub storage_capacity: Option<u64>,      // 存储容量（字节）
    pub bandwidth: Option<u64>,             // 带宽（字节/秒）
    pub encryption_formats: Vec<String>,    // 支持的加密格式
    pub can_read: bool,                     // 可读取
    pub can_write: bool,                    // 可写入
    pub can_relay: bool,                    // 可中继
    pub max_connections: usize,             // 最大并发连接数
}
```

**示例**: Storage 节点默认配置
- 存储容量: 100 GB
- 带宽: 100 MB/s
- 加密格式: AES-256-GCM, ChaCha20-Poly1305
- 可读写: true
- 最大连接数: 1000

---

## 注册流程

### 1. 提交注册请求

节点通过 `RegistrationRequest` 提交注册申请：

```rust
pub struct RegistrationRequest {
    pub node_type: NodeType,               // 请求的节点类型
    pub public_key: Vec<u8>,               // 节点公钥
    pub address: NodeAddress,              // 网络地址
    pub capabilities: NodeCapabilities,    // 节点能力
    pub ownership_proof: Vec<u8>,          // 所有权证明（签名挑战）
    pub referrer_node_id: Option<String>,  // 推荐节点（可选，用于信任担保）
    pub metadata: HashMap<String, String>, // 元数据
}
```

### 2. 注册验证

系统执行以下验证：

1. **重复检查** - 确保公钥未被注册
2. **封禁检查** - 验证节点未被封禁
3. **容量检查** - 确认该类型节点未达到上限
4. **区域检查** - 验证节点所在区域是否允许
5. **推荐人检查** - 如果需要推荐人，验证推荐人有效性

### 3. 审批方式

根据 `AdmissionPolicy.auto_approve` 设置：

- **自动审批** (`auto_approve = true`): 立即激活节点
- **人工审批** (`auto_approve = false`): 进入待审批队列

### 4. 初始状态

新注册的节点：
- 状态: `Pending` 或 `Active`（取决于审批模式）
- 信任评分: 0.5（中立起点）
- R0 状态: 未验证（需要后续设置）
- P1 状态: 未连接（需要后续建立）
- 有效期: 1 年

---

## 信任评分系统

### 信任评分结构

```rust
pub struct TrustScore {
    pub value: f64,                    // 当前信任值 (0.0 - 1.0)
    pub history: Vec<TrustEvent>,      // 评分历史
    pub updated_at: DateTime<Utc>,     // 最后更新时间
    pub decay_rate: f64,               // 衰减率（每天）
}
```

### 信任事件类型及影响

| 事件类型 | 默认影响值 | 描述 |
|---------|----------|------|
| `SuccessfulOperation` | +0.001 | 成功操作 |
| `FailedOperation` | -0.01 | 失败操作 |
| `HealthCheckPassed` | +0.005 | 健康检查通过 |
| `HealthCheckFailed` | -0.02 | 健康检查失败 |
| `DataCorruption` | -0.2 | 数据损坏 |
| `AvailabilityIssue` | -0.05 | 可用性问题 |
| `LatencyIssue` | -0.01 | 延迟问题 |
| `SecurityViolation` | -0.5 | 安全违规 |
| `PositiveAudit` | +0.05 | 正面审计结果 |
| `NegativeAudit` | -0.1 | 负面审计结果 |
| `Vouched` | +0.02 | 被信任节点推荐 |
| `ManualAdjustment` | 可变 | 人工调整 |

### 信任评分衰减

信任评分会随时间向中性值（0.5）衰减：

- 默认衰减率: 1% per day
- 高于 0.5: 逐渐降低
- 低于 0.5: 逐渐提高
- 目的: 鼓励持续良好行为，而非一次性信任积累

### 自动封禁

当信任评分低于 `ban_threshold`（默认 0.1）时，节点自动被封禁。

---

## 节点连通性分类

系统根据 P1 和 R0 状态将节点分为三类：

### 1. FullyConnected（完全连接）

- ✅ R0 skeleton package 有效且已验证
- ✅ P1 connection 健康
- **可以**: 参与所有网络操作，包括跨节点对账和 payload 共享

### 2. LocalOnly（仅本地）

- ❌ 缺少 R0 或 P1（或两者都缺少）
- **限制**:
  - 无法参与跨节点对账
  - 不被其他 connected nodes 识别
  - 无法共享或接收 payload mappings

### 3. Degraded（降级）

- ⚠️ 有 R0 或 P1，但状态不健康
- **限制**: 类似 LocalOnly，直到状态恢复健康

### 检查方法

```rust
impl ConnectedNode {
    /// 获取节点连通性分类
    pub fn connectivity(&self) -> NodeConnectivity {
        let has_r0 = self.r0_status.is_valid();
        let has_p1 = self.p1_status.is_valid();

        if has_r0 && has_p1 {
            NodeConnectivity::FullyConnected
        } else if self.r0_status.has_r0 || self.p1_status.connected {
            NodeConnectivity::Degraded
        } else {
            NodeConnectivity::LocalOnly
        }
    }

    /// 检查是否为完全连接节点
    pub fn is_fully_connected(&self) -> bool {
        self.connectivity() == NodeConnectivity::FullyConnected
    }

    /// 检查是否为仅本地节点
    pub fn is_local_only(&self) -> bool {
        !self.r0_status.is_valid() || !self.p1_status.is_valid()
    }
}
```

---

## 准入检查

### 1. 基本准入检查

用于验证节点是否可以执行一般操作：

```rust
pub async fn check_admission(&self, node_id: &str) -> AdmissionResult<&'static str>
```

**检查项**:
- ✓ 节点已注册
- ✓ 状态为 `Active`
- ✓ 注册未过期
- ✓ 信任评分 ≥ 策略最低要求
- ✓ 信任评分 ≥ 节点类型要求

### 2. 跨节点操作准入检查

用于验证节点是否可以参与跨节点操作（**硬性要求**）：

```rust
pub async fn check_cross_node_admission(&self, node_id: &str) -> AdmissionResult<NodeConnectivity>
```

**检查项**:
- ✓ 通过基本准入检查
- ✓ **R0 skeleton package 存在且已验证**（硬性要求）
- ✓ **P1 connection 已建立且健康**（硬性要求）

**错误类型**:
- `AdmissionError::MissingR0Skeleton` - 缺少 R0 skeleton
- `AdmissionError::R0VerificationFailed` - R0 验证失败
- `AdmissionError::MissingP1Connection` - P1 连接未建立
- `AdmissionError::LocalOnlyNode` - 节点为仅本地节点

### 3. 检查节点是否可参与

```rust
impl ConnectedNode {
    /// 检查节点是否可以参与一般操作
    pub fn can_participate(&self) -> bool {
        self.is_active() &&
        self.trust_score.value >= self.node_type.min_trust_score()
    }

    /// 检查节点是否可以参与跨节点操作
    pub fn can_participate_cross_node(&self) -> bool {
        self.can_participate() && self.is_fully_connected()
    }

    /// 获取无法参与跨节点操作的详细原因
    pub fn cross_node_participation_blocked_reason(&self) -> Option<String>
}
```

---

## 健康监控

### 健康检查接口

系统通过 `NodeHealthChecker` trait 执行健康检查：

```rust
#[async_trait]
pub trait NodeHealthChecker: Send + Sync {
    async fn check_health(&self, node: &ConnectedNode) -> HealthCheckResult;
}
```

### 健康检查结果

```rust
pub struct HealthCheckResult {
    pub healthy: bool,                  // 是否健康
    pub latency_ms: Option<u64>,        // 响应延迟（毫秒）
    pub error: Option<String>,          // 错误信息
    pub checked_at: DateTime<Utc>,      // 检查时间
    pub metrics: HashMap<String, f64>,  // 其他指标
}
```

### 健康检查流程

1. 系统定期调用 `run_health_check(node_id)`
2. 执行自定义健康检查逻辑
3. 根据结果记录信任事件：
   - 成功: `TrustEventType::HealthCheckPassed` (+0.005)
   - 失败: `TrustEventType::HealthCheckFailed` (-0.02)
4. 更新节点 `last_active_at` 时间戳

### 健康检查配置

通过 `AdmissionPolicy` 配置：

```rust
pub struct AdmissionPolicy {
    pub health_check_interval_secs: u64,  // 健康检查间隔（秒）
    pub inactivity_timeout_hours: u64,     // 不活跃超时（小时）
    // ...
}
```

默认值:
- 健康检查间隔: 60 秒
- 不活跃超时: 24 小时

---

## 节点生命周期管理

### 节点状态

```rust
pub enum RegistrationStatus {
    Pending,    // 待审批
    Active,     // 活跃
    Suspended,  // 暂停
    Banned,     // 封禁
    Expired,    // 已过期
    Departed,   // 已离开
}
```

### 状态转换

```
Pending ──approve──> Active
   │                   │
   └─────reject───────>│
                       │
                       ├──inactivity──> Suspended
                       ├──low_trust───> Banned
                       ├──expire──────> Expired
                       └──depart──────> Departed
```

### 管理操作

#### 1. 设置 R0 状态

```rust
pub async fn set_r0_status(
    &self,
    node_id: &str,
    status: R0SkeletonStatus
) -> AdmissionResult<()>
```

**用途**: 当节点创建或验证 R0 skeleton package 后更新状态

**示例**:
```rust
let r0_status = R0SkeletonStatus::verified_with_digest(
    digest,
    "snapshot:abc123".to_string()
);
controller.set_r0_status("node:xyz", r0_status).await?;
```

#### 2. 设置 P1 连接状态

```rust
pub async fn set_p1_status(
    &self,
    node_id: &str,
    status: P1ConnectionStatus
) -> AdmissionResult<()>
```

**用途**: 当节点建立或失去 P1 连接时更新状态

**示例**:
```rust
let p1_status = P1ConnectionStatus::connected_to("https://l0-api.example.com");
controller.set_p1_status("node:xyz", p1_status).await?;
```

#### 3. 记录信任事件

```rust
pub async fn record_trust_event(
    &self,
    node_id: &str,
    event: TrustEvent
) -> AdmissionResult<()>
```

**示例**:
```rust
let event = TrustEvent {
    event_type: TrustEventType::SuccessfulOperation,
    impact: 0.001,
    timestamp: Utc::now(),
    details: Some("Payload successfully stored".to_string()),
};
controller.record_trust_event("node:xyz", event).await?;
```

#### 4. 封禁节点

```rust
pub async fn ban_node(
    &self,
    node_id: &str,
    reason: &str,
    duration: Option<Duration>
) -> AdmissionResult<()>
```

**参数**:
- `duration = None`: 永久封禁
- `duration = Some(Duration::days(7))`: 临时封禁 7 天

#### 5. 节点离开

```rust
pub async fn depart_node(&self, node_id: &str) -> AdmissionResult<()>
```

**用途**: 优雅地移除节点（非惩罚性）

#### 6. 清理不活跃节点

```rust
pub async fn cleanup_inactive(&self) -> usize
```

**功能**:
- 标记过期注册为 `Expired`
- 标记长时间不活跃的节点为 `Suspended`
- 返回清理的节点数量

**建议**: 定期调用（如每小时）

---

## API 使用示例

### 完整的节点准入流程示例

```rust
use p2_core::node_admission::*;
use chrono::Utc;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

// 1. 创建健康检查器
struct MyHealthChecker;

#[async_trait::async_trait]
impl NodeHealthChecker for MyHealthChecker {
    async fn check_health(&self, node: &ConnectedNode) -> HealthCheckResult {
        // 实现自定义健康检查逻辑
        // 例如：ping 节点，检查 HTTP 端点等
        HealthCheckResult {
            healthy: true,
            latency_ms: Some(50),
            error: None,
            checked_at: Utc::now(),
            metrics: HashMap::new(),
        }
    }
}

// 2. 创建准入控制器
let policy = AdmissionPolicy::default();
let health_checker = Arc::new(MyHealthChecker);
let controller = NodeAdmissionController::new(health_checker, policy);

// 3. 提交注册请求
let request = RegistrationRequest {
    node_type: NodeType::Storage,
    public_key: vec![1, 2, 3, 4],
    address: NodeAddress {
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        port: 9000,
        protocol: NetworkProtocol::Tcp,
        region: Some("us-west".to_string()),
        dns_name: Some("storage-node-1.example.com".to_string()),
    },
    capabilities: NodeCapabilities::default_for(NodeType::Storage),
    ownership_proof: vec![/* 签名数据 */],
    referrer_node_id: None,
    metadata: HashMap::new(),
};

let node_id = controller.submit_registration(request).await?;
println!("Node registered: {}", node_id);

// 4. 设置 P1 连接状态
let p1_status = P1ConnectionStatus::connected_to("https://l0-api.example.com");
controller.set_p1_status(&node_id, p1_status).await?;

// 5. 设置 R0 skeleton 状态
let r0_digest = Digest::blake3(b"r0_skeleton_data");
let r0_status = R0SkeletonStatus::verified_with_digest(
    r0_digest,
    "snapshot:abc123".to_string()
);
controller.set_r0_status(&node_id, r0_status).await?;

// 6. 检查节点是否可以参与跨节点操作
match controller.check_cross_node_admission(&node_id).await {
    Ok(NodeConnectivity::FullyConnected) => {
        println!("✓ Node is fully connected and can participate in cross-node operations");
    }
    Err(AdmissionError::MissingR0Skeleton { .. }) => {
        println!("✗ Node is missing R0 skeleton package");
    }
    Err(AdmissionError::MissingP1Connection { .. }) => {
        println!("✗ Node is missing P1 connection");
    }
    Err(e) => {
        println!("✗ Admission check failed: {}", e);
    }
}

// 7. 运行健康检查
let health_result = controller.run_health_check(&node_id).await?;
println!("Health check: {:?}", health_result);

// 8. 记录信任事件
let event = TrustEvent {
    event_type: TrustEventType::SuccessfulOperation,
    impact: 0.001,
    timestamp: Utc::now(),
    details: Some("Stored payload successfully".to_string()),
};
controller.record_trust_event(&node_id, event).await?;

// 9. 获取完全连接的节点列表
let fully_connected_nodes = controller.get_fully_connected_nodes().await;
println!("Fully connected nodes: {}", fully_connected_nodes.len());

// 10. 获取仅本地节点列表
let local_only_nodes = controller.get_local_only_nodes().await;
println!("Local-only nodes: {}", local_only_nodes.len());

// 11. 获取统计信息
let stats = controller.get_stats().await;
println!("Total active nodes: {}", stats.total_active);
println!("Average trust score: {:.2}", stats.average_trust_score);

// 12. 定期清理
let cleaned = controller.cleanup_inactive().await;
println!("Cleaned up {} inactive nodes", cleaned);
```

---

## 配置参数

### AdmissionPolicy 完整配置

```rust
pub struct AdmissionPolicy {
    /// 每种类型的最大节点数
    pub max_nodes: HashMap<NodeType, usize>,

    /// 准入的最低信任评分
    pub min_trust_score: f64,

    /// 允许的区域列表（None = 允许所有）
    pub allowed_regions: Option<Vec<String>>,

    /// 禁止的区域列表
    pub blocked_regions: Vec<String>,

    /// 注册是否需要推荐人
    pub require_referrer: bool,

    /// 自动审批注册
    pub auto_approve: bool,

    /// 健康检查间隔（秒）
    pub health_check_interval_secs: u64,

    /// 不活跃超时（小时）
    pub inactivity_timeout_hours: u64,

    /// 封禁阈值（信任评分低于此值自动封禁）
    pub ban_threshold: f64,
}
```

### 默认值

```rust
AdmissionPolicy {
    max_nodes: {
        Storage: 1000,
        Relay: 100,
        Validator: 50,
        Gateway: 20,
        Light: 10000,
    },
    min_trust_score: 0.3,
    allowed_regions: None,
    blocked_regions: vec![],
    require_referrer: false,
    auto_approve: true,
    health_check_interval_secs: 60,
    inactivity_timeout_hours: 24,
    ban_threshold: 0.1,
}
```

---

## 错误处理

### 准入错误类型

| 错误 | 描述 | 处理建议 |
|------|------|---------|
| `NodeNotRegistered` | 节点未注册 | 先注册节点 |
| `InvalidCredentials` | 凭证无效 | 检查公钥和所有权证明 |
| `InsufficientTrust` | 信任评分不足 | 提高信任评分或等待 |
| `NodeBanned` | 节点已封禁 | 联系管理员申诉 |
| `CapacityExceeded` | 容量已满 | 等待空位或选择其他类型 |
| `NodeTypeNotAllowed` | 节点类型不允许 | 更改节点类型 |
| `RegionNotAllowed` | 区域不允许 | 更改节点位置 |
| `HealthCheckFailed` | 健康检查失败 | 修复节点健康问题 |
| `RegistrationExpired` | 注册已过期 | 续期注册 |
| `DuplicateRegistration` | 重复注册 | 使用唯一公钥 |
| `RateLimitExceeded` | 速率限制超出 | 降低请求频率 |
| **`MissingR0Skeleton`** | **缺少 R0 skeleton**（硬性要求） | **创建并验证 R0 skeleton package** |
| **`R0VerificationFailed`** | **R0 验证失败** | **修复 R0 验证问题** |
| **`MissingP1Connection`** | **P1 连接未建立**（硬性要求） | **建立 P1 (L0) 连接** |
| **`LocalOnlyNode`** | **节点为仅本地节点** | **满足 P1 + R0 硬性要求** |

---

## 最佳实践

### 1. 注册新节点

- ✓ 提供准确的节点能力信息
- ✓ 如有推荐人，提供可信推荐人 ID
- ✓ 使用强所有权证明（签名挑战）
- ✓ 设置合理的元数据

### 2. 满足硬性要求

- ✓ **优先建立 P1 连接** - 这是 Connected Node 的基础
- ✓ **创建 R0 skeleton package** - 确保包含必要的复活状态
- ✓ **验证 R0** - 通过 SnapshotMapCommit 验证
- ✓ **监控连接状态** - 定期检查 P1 健康状态

### 3. 维护信任评分

- ✓ 确保节点稳定运行
- ✓ 及时响应健康检查
- ✓ 避免数据损坏和安全违规
- ✓ 积极参与网络操作

### 4. 健康监控

- ✓ 实现自定义健康检查逻辑
- ✓ 监控响应延迟
- ✓ 记录关键指标
- ✓ 及时修复健康问题

### 5. 生命周期管理

- ✓ 定期续期注册
- ✓ 保持节点活跃
- ✓ 优雅离开网络（使用 `depart_node`）
- ✓ 定期运行 `cleanup_inactive`

---

## 安全考虑

### 1. 所有权证明

- 使用节点私钥签名挑战数据
- 验证签名与公钥匹配
- 防止公钥劫持

### 2. 信任评分保护

- 防止信任评分操纵
- 记录所有信任事件以便审计
- 实施速率限制防止刷分

### 3. P1 连接安全

- 使用 HTTPS/TLS 连接 P1
- 验证 P1 endpoint 证书
- 定期验证 receipt 签名

### 4. R0 验证

- 验证 R0 digest 与 SnapshotMapCommit 匹配
- 确保 R0 包含必要的复活状态
- 防止伪造 R0 skeleton

### 5. 区域和容量限制

- 实施区域白名单/黑名单
- 限制每种节点类型的数量
- 防止 Sybil 攻击

---

## 监控和告警

### 推荐监控指标

1. **节点数量**
   - 总注册节点数
   - 活跃节点数
   - 各类型节点分布
   - 完全连接 vs 仅本地节点比例

2. **信任评分**
   - 平均信任评分
   - 低于阈值的节点数
   - 信任评分趋势

3. **健康状态**
   - 健康检查成功率
   - 平均响应延迟
   - 失败节点数

4. **P1 和 R0 状态**
   - 缺少 P1 连接的节点数
   - 缺少 R0 的节点数
   - R0 验证失败率

### 推荐告警规则

- ⚠️ 完全连接节点比例 < 80%
- ⚠️ 平均信任评分 < 0.5
- ⚠️ 健康检查失败率 > 10%
- ⚠️ 仅本地节点数量异常增加
- 🚨 信任评分低于封禁阈值的节点数 > 5
- 🚨 P1 连接失败节点数 > 10

---

## 总结

Connected Node 准入控制系统提供了完整的节点生命周期管理，重点是**硬性要求**（P1 + R0）的验证。

### 关键要点

1. ✅ **P1 连接 + R0 skeleton** 是 Connected Node 的**硬性要求**
2. ✅ 不满足要求的节点为 **local-only**，无法参与跨节点操作
3. ✅ 信任评分系统确保节点持续良好行为
4. ✅ 健康监控和自动清理保证网络质量
5. ✅ 灵活的配置策略适应不同部署场景

### 下一步

- 实现自定义 `NodeHealthChecker`
- 配置 `AdmissionPolicy` 以匹配您的网络需求
- 建立监控和告警系统
- 集成 P1 连接和 R0 验证逻辑

---

## 参考资料

- **代码实现**: `p2-core/src/node_admission.rs`
- **DSN 文档**: 07-DSN层/02-DSN第2篇-Connected-Node硬门槛.md
- **P2 架构**: `docs/ARCHITECTURE.md`
- **P2 API**: `docs/P2_API.md`
