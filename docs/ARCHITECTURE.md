# L0 公共现实账本 - 架构文档

## 概述

RainbowCore 实现了 L0（零层）公共现实账本，作为基础设施层提供：

- **不可变记录锚定** - 跨链状态存证
- **门限签名** - 基于 BLS12-381（5/9 方案）
- **分布式密钥生成（DKG）** - 使用 Shamir 秘密共享
- **P2P 网络** - 签名者协调通信
- **多租户身份管理** - Actor 生命周期管理

## 工作区结构

```
Rainbowcore/
├── l0-core/        # 核心类型、特征和加密原语
├── l0-db/          # 数据库层（SurrealDB）和业务服务
├── l0-network/     # P2P 传输、消息路由、节点发现
├── l0-signer/      # 门限签名、BLS、DKG 操作
├── l0-api/         # REST/gRPC API 服务器
├── l0-cli/         # 命令行界面
└── tests/          # 集成测试
```

## Crate 依赖关系

```
l0-cli ─┬─> l0-api ───> l0-db ───> l0-core
        │                │
        └─> l0-signer ───┴─> l0-network
```

---

## l0-core

**职责**：核心领域类型、特征定义和加密原语。

### 模块

| 模块 | 描述 |
|------|------|
| `types/` | 领域实体（Actor、Commitment、Receipt、Batch、Epoch） |
| `ledger/` | 账本操作的特征定义 |
| `crypto/` | BLAKE3 摘要、Merkle 树实现 |
| `canon/` | 规范化处理（确定性哈希） |
| `error.rs` | 错误类型定义 |

### 核心类型

```rust
// 身份
Actor { id, alias, pubkey, status, created_at }
ActorKeyRotation { actor_id, old_key, new_key, timestamp }

// 承诺
Commitment { digest, actor_id, scope, parent, metadata }
Receipt { commitment_digest, batch_id, timestamp, signature }

// 批处理
Batch { epoch, seq, merkle_root, commitments, signature }
Epoch { id, start_time, end_time, batch_count }

// 加密
Digest - BLAKE3 32字节哈希
MerkleTree - 二叉 Merkle 树（含包含证明）
```

---

## l0-db

**职责**：数据库持久化和业务逻辑服务。

### 分层架构

```
┌─────────────────────────────────────┐
│           服务层 (Services)          │  业务逻辑
├─────────────────────────────────────┤
│          仓库层 (Repository)         │  数据访问模式
├─────────────────────────────────────┤
│           实体层 (Entities)          │  数据库模型
├─────────────────────────────────────┤
│      SurrealDB（通过 soulbase）       │  存储引擎
└─────────────────────────────────────┘
```

### 服务列表

| 服务 | 职责 |
|------|------|
| `IdentityService` | Actor 注册、密钥轮换、Merkle 根计算 |
| `AnchorService` | 承诺锚定、批次创建 |
| `ReceiptService` | 收据生成与检索 |
| `CausalityService` | 纪元/批次排序、链验证 |
| `ConsentService` | 同意契约、紧急覆盖 |
| `DisputeService` | 争议提交与解决 |
| `KnowledgeService` | AKN 索引、Merkle 验证 |
| `TipWitnessService` | L1/L2 链的 Tip 见证 |
| `BackfillService` | 缺口检测与回填操作 |

### 数据库模式（18 张表）

```
l0_actors, l0_key_rotation, l0_commitments, l0_receipts,
l0_batches, l0_epochs, l0_merkle_nodes, l0_consent_covenants,
l0_consent_overrides, l0_disputes, l0_appeals, l0_fees,
l0_tip_witnesses, l0_backfill_tasks, l0_backfill_items,
l0_akn_index, l0_config, l0_metrics
```

---

## l0-network

**职责**：签名者协调的 P2P 网络通信。

### 组件

| 组件 | 描述 |
|------|------|
| `TcpTransport` | 基于 TCP 的对等连接 |
| `MemoryTransport` | 内存传输（用于测试） |
| `NodeManager` | 对等节点跟踪和状态管理 |
| `NodeDiscovery` | 基于 DHT 的节点发现 |
| `MessageRouter` | 消息路由和转发 |

### 消息类型

```rust
enum MessagePayload {
    Ping(PingPayload),           // 心跳检测
    Pong(PongPayload),           // 心跳响应
    DkgPhase1(DkgPhase1Payload), // DKG 第一阶段
    DkgPhase2(DkgPhase2Payload), // DKG 第二阶段
    DkgComplete(DkgCompletePayload), // DKG 完成
    SignRequest(SignRequestPayload),   // 签名请求
    SignResponse(SignResponsePayload), // 签名响应
    BatchProposal(BatchProposalPayload), // 批次提案
    BatchVote(BatchVotePayload),   // 批次投票
}
```

### 节点角色

```rust
enum NodeRole {
    CertifiedSigner,   // 认证签名者（5/9 集合成员）
    ObserverSigner,    // 观察者（无投票权）
    ReadVerify,        // 只读验证
    WriteAudit,        // 审计日志
}
```

---

## l0-signer

**职责**：门限密码学和分布式密钥生成。

### 签名方案

| 方案 | 用途 | 性能 |
|------|------|------|
| BLS12-381 | 门限签名（5/9） | 签名: ~287µs, 验证: ~669µs |
| Ed25519 | 单独签名 | 签名: ~12.6µs |

### 门限签名流程

```
1. 消息到达协调者
2. 协调者向 9 个签名者广播 SignRequest
3. 每个签名者创建 ThresholdSignatureShare
4. 协调者收集 5+ 份额（达到门限）
5. 份额聚合为 AggregatedBlsSignature
6. 验证签名并附加到批次
```

### DKG 协议

```
第一阶段：承诺
  - 每方生成多项式
  - 广播系数承诺

第二阶段：份额分发
  - 每方为其他参与者计算份额
  - 加密份额分发

第三阶段：重建
  - 各方重建共享秘密
  - 需要 t+1 方参与
```

### 核心类型

```rust
BlsSecretKey, BlsPublicKey, BlsSignature
ThresholdSignatureShare { signer_index, signature }
AggregatedBlsSignature { signature, bitmap, threshold }
BlsThresholdSigner { secret, index, threshold }
DkgSession { state, participants, shares }
```

---

## l0-api

**职责**：REST 和 gRPC API 服务器。

### REST 端点（60+）

| 前缀 | 描述 |
|------|------|
| `/health`, `/ready` | 健康检查 |
| `/api/v1/actors/*` | Actor 增删改查、密钥轮换 |
| `/api/v1/commitments/*` | 承诺提交 |
| `/api/v1/receipts/*` | 收据检索 |
| `/api/v1/batches/*` | 批次查询 |
| `/api/v1/epochs/*` | 纪元管理 |
| `/api/v1/disputes/*` | 争议提交 |
| `/api/v1/consent/*` | 同意契约 |
| `/api/v1/knowledge/*` | AKN 索引 |
| `/api/v1/tips/*` | Tip 见证 |
| `/api/v1/anchors/*` | 锚定操作 |
| `/api/v1/fees/*` | 费用估算 |

### 服务栈

```
Axum (HTTP) + Tonic (gRPC)
    │
    ├── Tower 中间件（CORS、追踪）
    │
    └── Handlers ──> Services ──> Repositories ──> SurrealDB
```

---

## l0-cli

**职责**：节点操作的命令行界面。

### 命令

```bash
l0-cli init          # 初始化数据库
l0-cli serve         # 启动 API 服务器
l0-cli actor ...     # Actor 管理
l0-cli commit ...    # 提交承诺
l0-cli batch ...     # 批次操作
l0-cli interactive   # 交互式 REPL 模式
```

### 配置

环境变量（`.env`）：
```
DATABASE_URL=ws://localhost:8000
DATABASE_NAME=l0_ledger
API_PORT=3000
SIGNER_INDEX=1
THRESHOLD=5
TOTAL_SIGNERS=9
```

---

## 数据流

### 承诺流程

```
客户端 ──> POST /commitments
              │
              ▼
        AnchorService.anchor()
              │
              ├── 验证 Actor
              ├── 验证父链
              ├── 存储承诺
              └── 加入批处理队列
              │
              ▼
        BatchService.create_batch()
              │
              ├── 收集待处理承诺
              ├── 构建 Merkle 树
              ├── 请求门限签名
              └── 持久化批次
              │
              ▼
        ReceiptService.generate()
              │
              └── 返回收据给客户端
```

### 门限签名流程

```
BatchService ──> SignerCoordinator
                      │
                      ├── 广播 SignRequest
                      │
                      ▼
    ┌─────────────────────────────────────────┐
    │  签名者1   签名者2   ...   签名者9       │
    │     │        │              │           │
    │     ▼        ▼              ▼           │
    │  Sign(msg) Sign(msg)    Sign(msg)       │
    │     │        │              │           │
    │     └────────┴──────────────┘           │
    │                │                        │
    │                ▼                        │
    │        收集 5+ 份额                      │
    │                │                        │
    │                ▼                        │
    │     aggregate_signatures()              │
    │                │                        │
    │                ▼                        │
    │      AggregatedBlsSignature             │
    └─────────────────────────────────────────┘
```

---

## 安全模型

### 威胁缓解

| 威胁 | 缓解措施 |
|------|----------|
| 单签名者被攻破 | 5/9 门限（拜占庭容错） |
| 密钥泄露 | DKG + Shamir 秘密共享 |
| 网络分区 | 消息重试（指数退避） |
| 重放攻击 | 消息中包含 nonce + 时间戳 |
| 数据篡改 | BLAKE3 + Merkle 证明 |

### 信任假设

- 至少 5/9 签名者是诚实的
- 网络最终能送达消息
- 时钟松散同步
- 数据库可信（本地 SurrealDB）

---

## 性能特性

### 加密操作

| 操作 | 延迟 |
|------|------|
| BLS 密钥生成 | ~80µs |
| BLS 签名 | ~287µs |
| BLS 验证 | ~669µs |
| Ed25519 签名 | ~12.6µs |
| 门限签名（5/9） | ~299µs |
| 门限验证（5/9） | ~1.05ms |
| 完整 5/9 工作流 | ~2.78ms |
| DKG 份额分割 | ~2.5µs |
| DKG 重建 | ~159ns |

### 扩展性考虑

- 批处理将签名成本分摊到 N 个承诺
- 签名聚合：O(n)（签名者数量）
- Merkle 证明：O(log n)（批次大小）
- 数据库：SurrealDB 支持水平扩展

---

## 依赖

### 外部 Crate

| Crate | 用途 |
|-------|------|
| `blst` | BLS12-381 签名 |
| `ed25519-dalek` | Ed25519 签名 |
| `blake3` | BLAKE3 哈希 |
| `tokio` | 异步运行时 |
| `axum` | HTTP 服务器 |
| `tonic` | gRPC 服务器 |
| `serde` | 序列化 |
| `chrono` | 时间处理 |

### Soul-Base 基础设施

复用自 `../soul-base/crates/`：
- `soulbase-types` - 通用类型
- `soulbase-errors` - 错误处理
- `soulbase-crypto` - 加密工具
- `soulbase-storage` - SurrealDB 抽象
- `soulbase-net` - 网络工具

---

## 测试

- **单元测试**：工作区内 126+ 测试
- **集成测试**：`tests/integration_tests.rs`
- **API 测试**：`l0-api/tests/integration_tests.rs`
- **基准测试**：`l0-signer/benches/signing_benchmarks.rs`

运行测试：
```bash
cargo test --workspace
cargo bench -p l0-signer
```
