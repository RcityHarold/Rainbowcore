# L0 公共现实账本 - 部署指南

## 前置条件

### 系统要求

| 组件 | 最低配置 | 推荐配置 |
|------|----------|----------|
| CPU | 2 核 | 4+ 核 |
| 内存 | 4 GB | 8+ GB |
| 磁盘 | 20 GB SSD | 100+ GB NVMe |
| 操作系统 | Linux (x86_64) | Ubuntu 22.04 LTS |

### 软件依赖

```bash
# Rust 工具链（1.75+）
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# 构建工具
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev

# SurrealDB（可选，用于远程数据库）
curl -sSf https://install.surrealdb.com | sh
```

---

## 快速开始（开发环境）

```bash
# 克隆仓库
git clone https://github.com/rainbowcity/rainbowcore.git
cd rainbowcore

# 复制环境配置
cp .env.example .env

# 构建
cargo build --release

# 初始化数据库
./target/release/l0-cli init

# 启动 API 服务器
./target/release/l0-cli serve
```

API 将在 `http://localhost:3000` 上可用。

---

## 配置

### 环境变量

在项目根目录创建 `.env` 文件：

```bash
# 数据库配置
L0_DB_URL=rocksdb://./data      # 生产环境：使用 RocksDB
L0_DB_NAMESPACE=l0
L0_DB_DATABASE=ledger

# API 服务器
L0_API_HOST=0.0.0.0
L0_API_PORT=3000
L0_NODE_ID=node_primary

# 日志
RUST_LOG=info

# 签名者配置（分布式签名）
L0_SIGNER_MODE=distributed
L0_SIGNER_THRESHOLD=5
L0_SIGNER_TOTAL=9
```

### 数据库选项

| URL 格式 | 用途 |
|----------|------|
| `mem://` | 开发/测试（重启后数据丢失） |
| `file://./data` | 简单持久化 |
| `rocksdb://./data` | 生产环境（推荐） |
| `ws://host:8000` | 远程 SurrealDB 集群 |

---

## 生产环境部署

### 单节点部署

1. **构建发布版本**：
   ```bash
   cargo build --release --features full-crypto
   ```

2. **创建数据目录**：
   ```bash
   mkdir -p /var/lib/l0-ledger
   chown l0-service:l0-service /var/lib/l0-ledger
   ```

3. **创建 systemd 服务**（`/etc/systemd/system/l0-ledger.service`）：
   ```ini
   [Unit]
   Description=L0 公共现实账本
   After=network.target

   [Service]
   Type=simple
   User=l0-service
   Group=l0-service
   WorkingDirectory=/opt/l0-ledger
   EnvironmentFile=/opt/l0-ledger/.env
   ExecStart=/opt/l0-ledger/l0-cli serve
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```

4. **启动服务**：
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable l0-ledger
   sudo systemctl start l0-ledger
   ```

### 分布式签名集群（5/9 门限）

生产环境门限签名需要部署 9 个签名节点：

```
┌─────────────────────────────────────────────────────────┐
│                      负载均衡器                          │
│                    （API 请求）                          │
└─────────────────────────────────────────────────────────┘
                           │
       ┌───────────────────┼───────────────────┐
       ▼                   ▼                   ▼
  ┌─────────┐         ┌─────────┐         ┌─────────┐
  │ API 节点│         │ API 节点│         │ API 节点│
  └────┬────┘         └────┬────┘         └────┬────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
       ┌───────────────────┼───────────────────┐
       │                   │                   │
       ▼                   ▼                   ▼
  ┌─────────┐         ┌─────────┐         ┌─────────┐
  │ 签名者1 │ ◄─────► │ 签名者2 │ ◄─────► │ 签名者3 │
  └─────────┘         └─────────┘         └─────────┘
       │                   │                   │
       │        ... （共 9 个签名者） ...       │
       │                   │                   │
  ┌─────────┐         ┌─────────┐         ┌─────────┐
  │ 签名者7 │ ◄─────► │ 签名者8 │ ◄─────► │ 签名者9 │
  └─────────┘         └─────────┘         └─────────┘
```

**签名节点配置**（每个节点）：
```bash
# /opt/l0-signer/.env
L0_NODE_ID=signer_1           # 每个节点唯一（1-9）
L0_SIGNER_MODE=distributed
L0_SIGNER_INDEX=1             # 节点索引（1-9）
L0_SIGNER_THRESHOLD=5
L0_SIGNER_TOTAL=9

# P2P 配置
L0_P2P_PORT=9000
L0_P2P_PEERS=signer_2:9000,signer_3:9000,...
```

### DKG 初始化

签名前需要运行 DKG 生成共享密钥：

```bash
# 在协调节点上
./l0-cli dkg init --session-id "epoch_001" --threshold 5 --total 9

# 等待所有签名者加入
./l0-cli dkg status --session-id "epoch_001"

# 所有参与方就绪后完成 DKG
./l0-cli dkg finalize --session-id "epoch_001"
```

---

## Docker 部署

### Dockerfile

```dockerfile
FROM rust:1.75-slim as builder

WORKDIR /app
COPY . .
RUN cargo build --release --features full-crypto

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/l0-cli /usr/local/bin/

EXPOSE 3000
ENTRYPOINT ["l0-cli"]
CMD ["serve"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  l0-ledger:
    build: .
    ports:
      - "3000:3000"
    environment:
      - L0_DB_URL=rocksdb:///data
      - L0_API_HOST=0.0.0.0
      - L0_API_PORT=3000
      - RUST_LOG=info
    volumes:
      - l0-data:/data
    restart: unless-stopped

volumes:
  l0-data:
```

### 使用 Docker Compose 运行

```bash
docker-compose up -d
```

---

## Kubernetes 部署

### Helm 配置（values.yaml）

```yaml
replicaCount: 3

image:
  repository: rainbowcity/l0-ledger
  tag: latest

service:
  type: LoadBalancer
  port: 3000

persistence:
  enabled: true
  size: 50Gi
  storageClass: ssd

env:
  L0_DB_URL: "rocksdb:///data"
  L0_SIGNER_MODE: "distributed"
  L0_SIGNER_THRESHOLD: "5"
  L0_SIGNER_TOTAL: "9"

resources:
  requests:
    memory: "2Gi"
    cpu: "1"
  limits:
    memory: "4Gi"
    cpu: "2"
```

---

## 监控

### 健康检查端点

| 端点 | 描述 |
|------|------|
| `GET /health` | 基本健康检查 |
| `GET /ready` | 就绪探针（数据库已连接、签名者可用） |

### Prometheus 指标

启用指标端点：
```bash
L0_METRICS_ENABLED=true
L0_METRICS_PORT=9090
```

关键指标：
- `l0_commitments_total` - 接收的总承诺数
- `l0_batches_created_total` - 创建的批次数
- `l0_signing_latency_seconds` - 门限签名延迟
- `l0_db_query_latency_seconds` - 数据库查询延迟

### 日志

生产环境配置结构化 JSON 日志：
```bash
RUST_LOG=info
L0_LOG_FORMAT=json
```

---

## 备份与恢复

### 数据库备份

对于 RocksDB 存储：
```bash
# 停止服务
systemctl stop l0-ledger

# 备份数据目录
tar -czf l0-backup-$(date +%Y%m%d).tar.gz /var/lib/l0-ledger

# 重启服务
systemctl start l0-ledger
```

### 密钥备份

**重要**：安全备份签名者密钥：
```bash
# 导出密钥份额（加密）
./l0-cli keys export --encrypted --output /secure/backup/keys.enc

# 存储到安全位置（HSM、保险库等）
```

---

## 安全加固

### 网络

- 在反向代理（nginx、Caddy）后运行 API
- 在代理层启用 TLS 终止
- 将 P2P 端口限制为仅签名者网络
- 使用防火墙规则限制访问

### 密钥管理

```bash
# 使用环境变量或密钥管理器
# 永远不要将密钥提交到 git

# HashiCorp Vault 集成
export VAULT_ADDR="https://vault.example.com"
export L0_DB_PASSWORD=$(vault kv get -field=password secret/l0-ledger/db)
```

### 文件权限

```bash
chmod 600 /opt/l0-ledger/.env
chmod 700 /var/lib/l0-ledger
chown -R l0-service:l0-service /opt/l0-ledger
```

---

## 故障排除

### 常见问题

| 问题 | 解决方案 |
|------|----------|
| "数据库连接失败" | 检查 `L0_DB_URL`，确保 SurrealDB 正在运行 |
| "签名者不足" | 验证 5+ 签名节点已连接 |
| "DKG 超时" | 增加 `L0_DKG_TIMEOUT_SECS`，检查网络 |
| "签名验证失败" | 确保所有签名者的密钥份额一致 |

### 调试模式

```bash
RUST_LOG=debug ./l0-cli serve
```

### 检查签名者连接

```bash
./l0-cli network status
./l0-cli signers list
```

---

## 升级

### 滚动升级

1. 构建新版本
2. 逐节点部署
3. 验证健康后再继续
4. 升级期间保持 5+ 健康签名者

### 数据库迁移

启动时自动运行迁移：
```bash
./l0-cli migrate
```

---

## 支持

- 问题反馈：https://github.com/rainbowcity/rainbowcore/issues
- 文档：https://docs.rainbowcity.io/l0
