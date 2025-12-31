//! Receipt Ledger Service Implementation
//!
//! Implements the ReceiptLedger trait for managing L0 receipts and fee receipts.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use l0_core::error::LedgerError;
use l0_core::ledger::{
    ChargeFeeRequest, CreateReceiptRequest, Ledger, LedgerResult, QueryOptions, ReceiptLedger,
};
use l0_core::types::{
    ActorId, Digest, FeeReceipt, FeeReceiptStatus, FeeUnits, L0Receipt, ReceiptId,
    ReceiptVerifyResult, RootKind, ScopeType,
};
use soulbase_storage::model::Entity;
use soulbase_storage::surreal::SurrealDatastore;
use soulbase_storage::Datastore;
use soulbase_types::prelude::TenantId;
use std::sync::Arc;

use crate::entities::{FeeReceiptEntity, ReceiptEntity};

/// Receipt Ledger Service
pub struct ReceiptService {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
    sequence: std::sync::atomic::AtomicU64,
}

impl ReceiptService {
    /// Create a new Receipt Service
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self {
            datastore,
            tenant_id,
            sequence: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Generate a new ID
    fn generate_id(&self, prefix: &str) -> String {
        let seq = self
            .sequence
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = Utc::now().timestamp_micros();
        format!("{}_{:016x}_{:08x}", prefix, timestamp, seq)
    }

    /// Convert ScopeType to string
    fn scope_type_to_str(t: ScopeType) -> &'static str {
        match t {
            ScopeType::AknBatch => "akn_batch",
            ScopeType::ConsentBatch => "consent_batch",
            ScopeType::VerdictBatch => "verdict_batch",
            ScopeType::DisputeBatch => "dispute_batch",
            ScopeType::RepairBatch => "repair_batch",
            ScopeType::ClawbackBatch => "clawback_batch",
            ScopeType::LogBatch => "log_batch",
            ScopeType::TraceBatch => "trace_batch",
            ScopeType::BackfillBatch => "backfill_batch",
            ScopeType::IdentityBatch => "identity_batch",
            ScopeType::CovenantStatusBatch => "covenant_status_batch",
        }
    }

    /// Convert string to ScopeType
    fn str_to_scope_type(s: &str) -> ScopeType {
        match s {
            "akn_batch" => ScopeType::AknBatch,
            "consent_batch" => ScopeType::ConsentBatch,
            "verdict_batch" => ScopeType::VerdictBatch,
            "dispute_batch" => ScopeType::DisputeBatch,
            "repair_batch" => ScopeType::RepairBatch,
            "clawback_batch" => ScopeType::ClawbackBatch,
            "log_batch" => ScopeType::LogBatch,
            "trace_batch" => ScopeType::TraceBatch,
            "backfill_batch" => ScopeType::BackfillBatch,
            "identity_batch" => ScopeType::IdentityBatch,
            "covenant_status_batch" => ScopeType::CovenantStatusBatch,
            _ => ScopeType::AknBatch,
        }
    }

    /// Convert RootKind to string
    fn root_kind_to_str(k: RootKind) -> &'static str {
        match k {
            RootKind::BatchRoot => "batch_root",
            RootKind::EpochRoot => "epoch_root",
        }
    }

    /// Convert string to RootKind
    fn str_to_root_kind(s: &str) -> RootKind {
        match s {
            "batch_root" => RootKind::BatchRoot,
            "epoch_root" => RootKind::EpochRoot,
            _ => RootKind::BatchRoot,
        }
    }

    /// Convert FeeReceiptStatus to string
    fn fee_status_to_str(s: FeeReceiptStatus) -> &'static str {
        match s {
            FeeReceiptStatus::ChargedPendingReceipt => "charged_pending_receipt",
            FeeReceiptStatus::Charged => "charged",
            FeeReceiptStatus::Refunded => "refunded",
            FeeReceiptStatus::Forfeited => "forfeited",
            FeeReceiptStatus::ChargedNoReceipt => "charged_no_receipt",
        }
    }

    /// Convert string to FeeReceiptStatus
    fn str_to_fee_status(s: &str) -> FeeReceiptStatus {
        match s {
            "charged_pending_receipt" => FeeReceiptStatus::ChargedPendingReceipt,
            "charged" => FeeReceiptStatus::Charged,
            "refunded" => FeeReceiptStatus::Refunded,
            "forfeited" => FeeReceiptStatus::Forfeited,
            "charged_no_receipt" => FeeReceiptStatus::ChargedNoReceipt,
            _ => FeeReceiptStatus::ChargedPendingReceipt,
        }
    }

    /// Convert FeeUnits to string
    fn fee_units_to_str(u: FeeUnits) -> &'static str {
        match u {
            FeeUnits::BatchRoot => "batch_root",
            FeeUnits::EntryCount => "entry_count",
            FeeUnits::SizeTier => "size_tier",
        }
    }

    /// Convert string to FeeUnits
    fn str_to_fee_units(s: &str) -> FeeUnits {
        match s {
            "batch_root" => FeeUnits::BatchRoot,
            "entry_count" => FeeUnits::EntryCount,
            "size_tier" => FeeUnits::SizeTier,
            _ => FeeUnits::BatchRoot,
        }
    }

    /// Convert entity to L0Receipt
    fn entity_to_receipt(entity: &ReceiptEntity) -> L0Receipt {
        L0Receipt {
            receipt_id: ReceiptId(entity.receipt_id.clone()),
            scope_type: Self::str_to_scope_type(&entity.scope_type),
            root_kind: Self::str_to_root_kind(&entity.root_kind),
            root: Digest::from_hex(&entity.root).unwrap_or_default(),
            time_window_start: entity.time_window_start,
            time_window_end: entity.time_window_end,
            batch_sequence_no: entity.batch_sequence_no,
            signer_set_version: entity.signer_set_version.clone(),
            canonicalization_version: entity.canonicalization_version.clone(),
            anchor_policy_version: entity.anchor_policy_version.clone(),
            fee_schedule_version: entity.fee_schedule_version.clone(),
            fee_receipt_id: entity.fee_receipt_id.clone(),
            signed_snapshot_ref: entity.signed_snapshot_ref.clone(),
            created_at: entity.created_at,
            rejected: Some(entity.rejected),
            reject_reason_code: entity.reject_reason_code.clone(),
            observer_reports_digest: None,
        }
    }

    /// Convert entity to FeeReceipt
    fn entity_to_fee_receipt(entity: &FeeReceiptEntity) -> FeeReceipt {
        FeeReceipt {
            fee_receipt_id: entity.fee_receipt_id.clone(),
            fee_schedule_version: entity.fee_schedule_version.clone(),
            payer_actor_id: entity.payer_actor_id.clone(),
            anchor_type: "batch".to_string(),
            units: Self::str_to_fee_units("batch_root"),
            units_count: entity.fee_units as u32,
            risk_multiplier: None,
            amount: entity.fee_units.to_string(),
            timestamp: entity.created_at,
            linked_anchor_id: String::new(),
            linked_receipt_id: None,
            deposit_amount: None,
            discount_digest: None,
            subsidy_digest: None,
            status: Self::str_to_fee_status(&entity.status),
        }
    }
}

#[async_trait]
impl Ledger for ReceiptService {
    fn name(&self) -> &'static str {
        "receipt"
    }

    async fn current_sequence(&self) -> LedgerResult<u64> {
        Ok(self.sequence.load(std::sync::atomic::Ordering::SeqCst))
    }

    async fn current_root(&self) -> LedgerResult<Digest> {
        Ok(Digest::zero())
    }

    async fn verify_integrity(&self) -> LedgerResult<bool> {
        Ok(true)
    }
}

#[async_trait]
impl ReceiptLedger for ReceiptService {
    async fn create_receipt(
        &self,
        request: CreateReceiptRequest,
        fee_receipt_id: String,
    ) -> LedgerResult<L0Receipt> {
        let receipt_id = self.generate_id("receipt");
        let now = Utc::now();

        let entity = ReceiptEntity {
            id: format!("l0_receipt:{}:{}", self.tenant_id.0, receipt_id),
            tenant_id: self.tenant_id.clone(),
            receipt_id: receipt_id.clone(),
            scope_type: Self::scope_type_to_str(request.scope_type).to_string(),
            root_kind: Self::root_kind_to_str(request.root_kind).to_string(),
            root: request.root.to_hex(),
            time_window_start: request.time_window_start,
            time_window_end: request.time_window_end,
            batch_sequence_no: request.batch_sequence_no,
            signer_set_version: request.signer_set_version,
            canonicalization_version: request.canonicalization_version,
            anchor_policy_version: request.anchor_policy_version,
            fee_schedule_version: request.fee_schedule_version,
            fee_receipt_id,
            signed_snapshot_ref: request.signed_snapshot_ref,
            created_at: now,
            rejected: false,
            reject_reason_code: None,
        };

        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!("CREATE {} CONTENT $data RETURN AFTER", ReceiptEntity::TABLE);

        let mut response = session
            .client()
            .query(&query)
            .bind(("data", entity))
            .await
            .map_err(|e| LedgerError::Storage(format!("Create failed: {}", e)))?;

        let result: Option<ReceiptEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let created = result.ok_or_else(|| LedgerError::Storage("Create returned no result".to_string()))?;
        Ok(Self::entity_to_receipt(&created))
    }

    async fn get_receipt(&self, receipt_id: &str) -> LedgerResult<Option<L0Receipt>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND receipt_id = $receipt_id LIMIT 1",
            ReceiptEntity::TABLE
        );

        let receipt_id_owned = receipt_id.to_string();
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("receipt_id", receipt_id_owned))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<ReceiptEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(result.map(|e| Self::entity_to_receipt(&e)))
    }

    async fn get_receipts_by_batch(&self, batch_sequence: u64) -> LedgerResult<Vec<L0Receipt>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND batch_sequence_no = $batch_seq ORDER BY created_at DESC",
            ReceiptEntity::TABLE
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("batch_seq", batch_sequence))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let results: Vec<ReceiptEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(results.iter().map(Self::entity_to_receipt).collect())
    }

    async fn verify_receipt(&self, receipt_id: &str) -> LedgerResult<ReceiptVerifyResult> {
        let receipt = self.get_receipt(receipt_id).await?;

        match receipt {
            Some(r) => {
                if r.rejected.unwrap_or(false) {
                    Ok(ReceiptVerifyResult::failed(vec![format!(
                        "Receipt rejected: {:?}",
                        r.reject_reason_code
                    )]))
                } else {
                    Ok(ReceiptVerifyResult::verified_a())
                }
            }
            None => Ok(ReceiptVerifyResult::failed(vec!["Receipt not found".to_string()])),
        }
    }

    async fn reject_receipt(
        &self,
        receipt_id: &str,
        reason_code: String,
        _observer_reports_digest: Option<Digest>,
    ) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "UPDATE {} SET rejected = true, reject_reason_code = $reason WHERE tenant_id = $tenant AND receipt_id = $receipt_id",
            ReceiptEntity::TABLE
        );

        let receipt_id_owned = receipt_id.to_string();
        session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("receipt_id", receipt_id_owned))
            .bind(("reason", reason_code))
            .await
            .map_err(|e| LedgerError::Storage(format!("Update failed: {}", e)))?;

        Ok(())
    }

    async fn list_receipts(
        &self,
        scope_type: Option<ScopeType>,
        options: QueryOptions,
    ) -> LedgerResult<Vec<L0Receipt>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let scope_clause = scope_type
            .map(|s| format!("AND scope_type = '{}'", Self::scope_type_to_str(s)))
            .unwrap_or_default();

        let limit = options.limit.unwrap_or(100);

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant {} ORDER BY created_at DESC LIMIT {}",
            ReceiptEntity::TABLE,
            scope_clause,
            limit
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let results: Vec<ReceiptEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(results.iter().map(Self::entity_to_receipt).collect())
    }

    async fn charge_fee(&self, request: ChargeFeeRequest) -> LedgerResult<FeeReceipt> {
        let fee_receipt_id = self.generate_id("fee");
        let now = Utc::now();

        let entity = FeeReceiptEntity {
            id: format!("l0_fee_receipt:{}:{}", self.tenant_id.0, fee_receipt_id),
            tenant_id: self.tenant_id.clone(),
            fee_receipt_id: fee_receipt_id.clone(),
            payer_actor_id: request.payer_actor_id.0,
            fee_units: request.units_count as u64,
            fee_schedule_version: request.fee_schedule_version,
            status: "charged_pending_receipt".to_string(),
            created_at: now,
            settled_at: None,
        };

        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!("CREATE {} CONTENT $data RETURN AFTER", FeeReceiptEntity::TABLE);

        let mut response = session
            .client()
            .query(&query)
            .bind(("data", entity))
            .await
            .map_err(|e| LedgerError::Storage(format!("Create failed: {}", e)))?;

        let result: Option<FeeReceiptEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let created = result.ok_or_else(|| LedgerError::Storage("Create returned no result".to_string()))?;
        Ok(Self::entity_to_fee_receipt(&created))
    }

    async fn get_fee_receipt(&self, fee_receipt_id: &str) -> LedgerResult<Option<FeeReceipt>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND fee_receipt_id = $fee_id LIMIT 1",
            FeeReceiptEntity::TABLE
        );

        let fee_id_owned = fee_receipt_id.to_string();
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("fee_id", fee_id_owned))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<FeeReceiptEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(result.map(|e| Self::entity_to_fee_receipt(&e)))
    }

    async fn link_fee_to_receipt(
        &self,
        fee_receipt_id: &str,
        _receipt_id: &str,
    ) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "UPDATE {} SET status = 'charged', settled_at = $now WHERE tenant_id = $tenant AND fee_receipt_id = $fee_id",
            FeeReceiptEntity::TABLE
        );

        let fee_id_owned = fee_receipt_id.to_string();
        session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("fee_id", fee_id_owned))
            .bind(("now", Utc::now()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Update failed: {}", e)))?;

        Ok(())
    }

    async fn update_fee_status(
        &self,
        fee_receipt_id: &str,
        new_status: FeeReceiptStatus,
    ) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "UPDATE {} SET status = $status WHERE tenant_id = $tenant AND fee_receipt_id = $fee_id",
            FeeReceiptEntity::TABLE
        );

        let fee_id_owned = fee_receipt_id.to_string();
        session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("fee_id", fee_id_owned))
            .bind(("status", Self::fee_status_to_str(new_status)))
            .await
            .map_err(|e| LedgerError::Storage(format!("Update failed: {}", e)))?;

        Ok(())
    }

    async fn get_pending_fees(&self, payer: &ActorId) -> LedgerResult<Vec<FeeReceipt>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND payer_actor_id = $payer AND status = 'charged_pending_receipt' ORDER BY created_at ASC",
            FeeReceiptEntity::TABLE
        );

        let payer_owned = payer.0.clone();
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("payer", payer_owned))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let results: Vec<FeeReceiptEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(results.iter().map(Self::entity_to_fee_receipt).collect())
    }

    async fn get_fee_history(
        &self,
        payer: &ActorId,
        options: QueryOptions,
    ) -> LedgerResult<Vec<FeeReceipt>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let limit = options.limit.unwrap_or(100);

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND payer_actor_id = $payer ORDER BY created_at DESC LIMIT {}",
            FeeReceiptEntity::TABLE,
            limit
        );

        let payer_owned = payer.0.clone();
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("payer", payer_owned))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let results: Vec<FeeReceiptEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(results.iter().map(Self::entity_to_fee_receipt).collect())
    }

    async fn calculate_pending_total(&self, payer: &ActorId) -> LedgerResult<String> {
        let pending = self.get_pending_fees(payer).await?;
        let total: u64 = pending.iter().map(|f| f.units_count as u64).sum();
        Ok(total.to_string())
    }

    async fn refund_fee(
        &self,
        fee_receipt_id: &str,
        _refund_reason: Option<String>,
    ) -> LedgerResult<()> {
        self.update_fee_status(fee_receipt_id, FeeReceiptStatus::Refunded).await
    }

    async fn forfeit_fee(&self, fee_receipt_id: &str) -> LedgerResult<()> {
        self.update_fee_status(fee_receipt_id, FeeReceiptStatus::Forfeited).await
    }
}
