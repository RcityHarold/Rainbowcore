//! Policy-Consent Ledger Service Implementation
//!
//! Implements the ConsentLedger trait for managing consent records,
//! access tickets, delegations, and covenants.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use l0_core::crypto::IncrementalMerkleTree;
use l0_core::error::LedgerError;
use l0_core::ledger::{ConsentLedger, ConsentVerifyResult, Ledger, LedgerResult, QueryOptions};
use l0_core::types::{
    AccessTicket, ActorId, ConsentRecord, ConsentScope, ConsentStatus, ConsentType,
    CovenantStatus, DelegationRecord, Digest, EmergencyJustificationType, EmergencyOverrideRecord, ReceiptId, SpaceId,
};
use soulbase_storage::model::Entity;
use soulbase_storage::surreal::SurrealDatastore;
use soulbase_storage::Datastore;
use soulbase_types::prelude::TenantId;
use std::collections::HashSet;
use std::sync::Arc;

use crate::entities::{AccessTicketEntity, ConsentEntity, CovenantEntity, DelegationEntity, EmergencyOverrideEntity};
use crate::validation::validate_not_space;

/// Policy-Consent Ledger Service
pub struct ConsentService {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
    sequence: std::sync::atomic::AtomicU64,
}

impl ConsentService {
    /// Create a new Consent Service
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self {
            datastore,
            tenant_id,
            sequence: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create a new Consent Service with persistent sequence
    pub async fn new_with_persistence(
        datastore: Arc<SurrealDatastore>,
        tenant_id: TenantId,
    ) -> Result<Self, LedgerError> {
        let service = Self::new(datastore.clone(), tenant_id.clone());
        let max_seq = service.load_max_sequence().await?;
        service
            .sequence
            .store(max_seq + 1, std::sync::atomic::Ordering::SeqCst);
        Ok(service)
    }

    /// Load the maximum sequence number from existing records
    async fn load_max_sequence(&self) -> Result<u64, LedgerError> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant ORDER BY created_at DESC LIMIT 1",
            ConsentEntity::TABLE
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<ConsentEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        if let Some(consent) = result {
            if let Some(seq) = crate::sequence::extract_sequence_from_id(&consent.consent_id) {
                return Ok(seq);
            }
        }

        Ok(0)
    }

    /// Generate a new ID
    fn generate_id(&self, prefix: &str) -> String {
        let seq = self
            .sequence
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = Utc::now().timestamp_micros();
        format!("{}_{:016x}_{:08x}", prefix, timestamp, seq)
    }

    /// Convert ConsentType to string
    fn consent_type_to_str(t: ConsentType) -> &'static str {
        match t {
            ConsentType::Explicit => "explicit",
            ConsentType::Implied => "implied",
            ConsentType::Delegated => "delegated",
            ConsentType::Emergency => "emergency",
        }
    }

    /// Convert string to ConsentType with validation
    fn str_to_consent_type(s: &str) -> LedgerResult<ConsentType> {
        match s {
            "explicit" => Ok(ConsentType::Explicit),
            "implied" => Ok(ConsentType::Implied),
            "delegated" => Ok(ConsentType::Delegated),
            "emergency" => Ok(ConsentType::Emergency),
            other => Err(LedgerError::Validation(format!(
                "Invalid consent_type: '{}'. Expected one of: explicit, implied, delegated, emergency",
                other
            ))),
        }
    }

    /// Convert ConsentStatus to string
    fn consent_status_to_str(s: ConsentStatus) -> &'static str {
        match s {
            ConsentStatus::Active => "active",
            ConsentStatus::Expired => "expired",
            ConsentStatus::Revoked => "revoked",
            ConsentStatus::Superseded => "superseded",
        }
    }

    /// Convert string to ConsentStatus with validation
    fn str_to_consent_status(s: &str) -> LedgerResult<ConsentStatus> {
        match s {
            "active" => Ok(ConsentStatus::Active),
            "expired" => Ok(ConsentStatus::Expired),
            "revoked" => Ok(ConsentStatus::Revoked),
            "superseded" => Ok(ConsentStatus::Superseded),
            other => Err(LedgerError::Validation(format!(
                "Invalid consent status: '{}'. Expected one of: active, expired, revoked, superseded",
                other
            ))),
        }
    }

    /// Parse Digest from hex string with proper error handling
    fn parse_digest(hex_str: &str, field_name: &str) -> LedgerResult<Digest> {
        Digest::from_hex(hex_str).map_err(|e| {
            LedgerError::Validation(format!(
                "Invalid {} digest '{}': {}",
                field_name, hex_str, e
            ))
        })
    }

    /// Convert entity to ConsentRecord with validation
    fn entity_to_consent_record(entity: &ConsentEntity) -> LedgerResult<ConsentRecord> {
        let consent_type = Self::str_to_consent_type(&entity.consent_type)?;
        let status = Self::str_to_consent_status(&entity.status)?;
        let terms_digest = Self::parse_digest(&entity.terms_digest, "terms")?;

        let constraints_digest = match &entity.constraints_digest {
            Some(d) => Some(Self::parse_digest(d, "constraints")?),
            None => None,
        };

        let revocation_reason_digest = match &entity.revocation_reason_digest {
            Some(d) => Some(Self::parse_digest(d, "revocation_reason")?),
            None => None,
        };

        Ok(ConsentRecord {
            consent_id: entity.consent_id.clone(),
            consent_type,
            grantor: ActorId(entity.grantor.clone()),
            grantee: ActorId(entity.grantee.clone()),
            scope: ConsentScope {
                resource_type: entity.resource_type.clone(),
                resource_id: entity.resource_id.clone(),
                actions: entity.actions.clone(),
                constraints_digest,
            },
            status,
            terms_digest,
            granted_at: entity.granted_at,
            expires_at: entity.expires_at,
            revoked_at: entity.revoked_at,
            revocation_reason_digest,
            superseded_by: entity.superseded_by.clone(),
            receipt_id: entity.receipt_id.as_ref().map(|r| ReceiptId(r.clone())),
        })
    }

    /// Convert entity to AccessTicket with validation
    fn entity_to_ticket(entity: &AccessTicketEntity) -> LedgerResult<AccessTicket> {
        let ticket_digest = Self::parse_digest(&entity.ticket_digest, "ticket")?;

        Ok(AccessTicket {
            ticket_id: entity.ticket_id.clone(),
            consent_ref: entity.consent_ref.clone(),
            holder: ActorId(entity.holder.clone()),
            target_resource: entity.target_resource.clone(),
            permissions: entity.permissions.clone(),
            issued_at: entity.issued_at,
            valid_from: entity.valid_from,
            valid_until: entity.valid_until,
            one_time: entity.one_time,
            used_at: entity.used_at,
            ticket_digest,
            receipt_id: entity.receipt_id.as_ref().map(|r| ReceiptId(r.clone())),
        })
    }

    /// Convert entity to DelegationRecord
    fn entity_to_delegation(entity: &DelegationEntity) -> DelegationRecord {
        DelegationRecord {
            delegation_id: entity.delegation_id.clone(),
            delegator: ActorId(entity.delegator.clone()),
            delegate: ActorId(entity.delegate.clone()),
            scope: ConsentScope {
                resource_type: entity.resource_type.clone(),
                resource_id: None,
                actions: entity.actions.clone(),
                constraints_digest: None,
            },
            can_redelegate: entity.can_redelegate,
            max_depth: entity.max_depth,
            current_depth: entity.current_depth,
            parent_delegation_ref: entity.parent_delegation_ref.clone(),
            valid_from: entity.valid_from,
            valid_until: entity.valid_until,
            revoked_at: entity.revoked_at,
            receipt_id: entity.receipt_id.as_ref().map(|r| ReceiptId(r.clone())),
        }
    }

    /// Convert EmergencyJustificationType to string
    fn justification_type_to_str(t: EmergencyJustificationType) -> &'static str {
        match t {
            EmergencyJustificationType::SafetyRisk => "safety_risk",
            EmergencyJustificationType::SecurityBreach => "security_breach",
            EmergencyJustificationType::LegalCompliance => "legal_compliance",
            EmergencyJustificationType::SystemIntegrity => "system_integrity",
            EmergencyJustificationType::Other => "other",
        }
    }

    /// Convert string to EmergencyJustificationType with validation
    fn str_to_justification_type(s: &str) -> LedgerResult<EmergencyJustificationType> {
        match s {
            "safety_risk" => Ok(EmergencyJustificationType::SafetyRisk),
            "security_breach" => Ok(EmergencyJustificationType::SecurityBreach),
            "legal_compliance" => Ok(EmergencyJustificationType::LegalCompliance),
            "system_integrity" => Ok(EmergencyJustificationType::SystemIntegrity),
            "other" => Ok(EmergencyJustificationType::Other),
            other => Err(LedgerError::Validation(format!(
                "Invalid justification_type: '{}'. Expected one of: safety_risk, security_breach, legal_compliance, system_integrity, other",
                other
            ))),
        }
    }

    /// Convert entity to EmergencyOverrideRecord with validation
    fn entity_to_override(entity: &EmergencyOverrideEntity) -> LedgerResult<EmergencyOverrideRecord> {
        let justification_type = Self::str_to_justification_type(&entity.justification_type)?;
        let justification_digest = Self::parse_digest(&entity.justification_digest, "justification")?;
        let action_taken_digest = Self::parse_digest(&entity.action_taken_digest, "action_taken")?;

        let review_outcome_digest = match &entity.review_outcome_digest {
            Some(d) => Some(Self::parse_digest(d, "review_outcome")?),
            None => None,
        };

        Ok(EmergencyOverrideRecord {
            override_id: entity.override_id.clone(),
            justification_type,
            justification_digest,
            overridden_consent_ref: entity.overridden_consent_ref.clone(),
            authorized_by: ActorId(entity.authorized_by.clone()),
            executed_by: ActorId(entity.executed_by.clone()),
            affected_actors: entity.affected_actors.iter().map(|s| ActorId(s.clone())).collect(),
            action_taken_digest,
            initiated_at: entity.initiated_at,
            completed_at: entity.completed_at,
            review_deadline: entity.review_deadline,
            reviewed_by: entity.reviewed_by.as_ref().map(|s| ActorId(s.clone())),
            review_outcome_digest,
            receipt_id: entity.receipt_id.as_ref().map(|r| ReceiptId(r.clone())),
        })
    }

    /// Convert entity to CovenantStatus with validation
    fn entity_to_covenant(entity: &CovenantEntity) -> LedgerResult<CovenantStatus> {
        let covenant_digest = Self::parse_digest(&entity.covenant_digest, "covenant")?;
        let status = Self::str_to_consent_status(&entity.status)?;

        let amendments_digest = match &entity.amendments_digest {
            Some(d) => Some(Self::parse_digest(d, "amendments")?),
            None => None,
        };

        Ok(CovenantStatus {
            covenant_id: entity.covenant_id.clone(),
            space_id: SpaceId(entity.space_id.clone()),
            covenant_digest,
            signatories: entity.signatories.iter().map(|s| ActorId(s.clone())).collect(),
            effective_from: entity.effective_from,
            status,
            amendments_digest,
            receipt_id: entity.receipt_id.as_ref().map(|r| ReceiptId(r.clone())),
        })
    }
}

#[async_trait]
impl Ledger for ConsentService {
    fn name(&self) -> &'static str {
        "consent"
    }

    async fn current_sequence(&self) -> LedgerResult<u64> {
        Ok(self.sequence.load(std::sync::atomic::Ordering::SeqCst))
    }

    async fn current_root(&self) -> LedgerResult<Digest> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        // Query all consents
        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant ORDER BY created_at ASC",
            ConsentEntity::TABLE
        );
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;
        let consents: Vec<ConsentEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        // Query all tickets
        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant ORDER BY issued_at ASC",
            AccessTicketEntity::TABLE
        );
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;
        let tickets: Vec<AccessTicketEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        // Query all delegations
        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant ORDER BY valid_from ASC",
            DelegationEntity::TABLE
        );
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;
        let delegations: Vec<DelegationEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        // Query all covenants
        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant ORDER BY effective_from ASC",
            CovenantEntity::TABLE
        );
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;
        let covenants: Vec<CovenantEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        // Query all emergency overrides
        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant ORDER BY initiated_at ASC",
            EmergencyOverrideEntity::TABLE
        );
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;
        let overrides: Vec<EmergencyOverrideEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        if consents.is_empty() && tickets.is_empty() && delegations.is_empty()
            && covenants.is_empty() && overrides.is_empty() {
            return Ok(Digest::zero());
        }

        let mut tree = IncrementalMerkleTree::new();

        // Add consents to tree
        for consent in &consents {
            let data = format!(
                "consent:{}:{}:{}:{}:{}",
                consent.consent_id,
                consent.grantor,
                consent.grantee,
                consent.consent_type,
                consent.terms_digest
            );
            tree.add(Digest::blake3(data.as_bytes()));
        }

        // Add tickets to tree
        for ticket in &tickets {
            let data = format!(
                "ticket:{}:{}:{}:{}",
                ticket.ticket_id,
                ticket.consent_ref,
                ticket.holder,
                ticket.ticket_digest
            );
            tree.add(Digest::blake3(data.as_bytes()));
        }

        // Add delegations to tree
        for delegation in &delegations {
            let data = format!(
                "delegation:{}:{}:{}:{}",
                delegation.delegation_id,
                delegation.delegator,
                delegation.delegate,
                delegation.max_depth
            );
            tree.add(Digest::blake3(data.as_bytes()));
        }

        // Add covenants to tree
        for covenant in &covenants {
            let data = format!(
                "covenant:{}:{}:{}:{}",
                covenant.covenant_id,
                covenant.space_id,
                covenant.covenant_digest,
                covenant.status
            );
            tree.add(Digest::blake3(data.as_bytes()));
        }

        // Add emergency overrides to tree
        for override_record in &overrides {
            let data = format!(
                "override:{}:{}:{}:{}",
                override_record.override_id,
                override_record.authorized_by,
                override_record.justification_type,
                override_record.justification_digest
            );
            tree.add(Digest::blake3(data.as_bytes()));
        }

        Ok(tree.root())
    }

    async fn verify_integrity(&self) -> LedgerResult<bool> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        // Verify consents
        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant",
            ConsentEntity::TABLE
        );
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;
        let consents: Vec<ConsentEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let mut seen_consent_ids = HashSet::new();
        for consent in &consents {
            // Check for duplicate consent_ids
            if !seen_consent_ids.insert(&consent.consent_id) {
                return Ok(false);
            }
            // Check required fields
            if consent.consent_id.is_empty() || consent.grantor.is_empty() || consent.grantee.is_empty() {
                return Ok(false);
            }
            // Validate consent_type
            if Self::str_to_consent_type(&consent.consent_type).is_err() {
                return Ok(false);
            }
            // Validate status
            if Self::str_to_consent_status(&consent.status).is_err() {
                return Ok(false);
            }
        }

        // Verify tickets
        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant",
            AccessTicketEntity::TABLE
        );
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;
        let tickets: Vec<AccessTicketEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let mut seen_ticket_ids = HashSet::new();
        for ticket in &tickets {
            // Check for duplicate ticket_ids
            if !seen_ticket_ids.insert(&ticket.ticket_id) {
                return Ok(false);
            }
            // Check required fields
            if ticket.ticket_id.is_empty() || ticket.consent_ref.is_empty() || ticket.holder.is_empty() {
                return Ok(false);
            }
        }

        // Verify delegations
        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant",
            DelegationEntity::TABLE
        );
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;
        let delegations: Vec<DelegationEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let mut seen_delegation_ids = HashSet::new();
        for delegation in &delegations {
            // Check for duplicate delegation_ids
            if !seen_delegation_ids.insert(&delegation.delegation_id) {
                return Ok(false);
            }
            // Check required fields
            if delegation.delegation_id.is_empty() || delegation.delegator.is_empty() || delegation.delegate.is_empty() {
                return Ok(false);
            }
            // Validate depth constraints
            if delegation.current_depth > delegation.max_depth {
                return Ok(false);
            }
        }

        // Verify covenants
        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant",
            CovenantEntity::TABLE
        );
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;
        let covenants: Vec<CovenantEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let mut seen_covenant_ids = HashSet::new();
        for covenant in &covenants {
            // Check for duplicate covenant_ids
            if !seen_covenant_ids.insert(&covenant.covenant_id) {
                return Ok(false);
            }
            // Check required fields
            if covenant.covenant_id.is_empty() || covenant.space_id.is_empty() {
                return Ok(false);
            }
            // Validate status
            if Self::str_to_consent_status(&covenant.status).is_err() {
                return Ok(false);
            }
        }

        // Verify emergency overrides
        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant",
            EmergencyOverrideEntity::TABLE
        );
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;
        let overrides: Vec<EmergencyOverrideEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let mut seen_override_ids = HashSet::new();
        for override_record in &overrides {
            // Check for duplicate override_ids
            if !seen_override_ids.insert(&override_record.override_id) {
                return Ok(false);
            }
            // Check required fields
            if override_record.override_id.is_empty() || override_record.authorized_by.is_empty() {
                return Ok(false);
            }
            // Validate justification_type
            if Self::str_to_justification_type(&override_record.justification_type).is_err() {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

#[async_trait]
impl ConsentLedger for ConsentService {
    async fn grant_consent(
        &self,
        consent_type: ConsentType,
        grantor: &ActorId,
        grantee: &ActorId,
        scope: ConsentScope,
        terms_digest: Digest,
        expires_at: Option<DateTime<Utc>>,
    ) -> LedgerResult<ConsentRecord> {
        // Validate: Space cannot be grantor or grantee (only allowed as context_ref)
        validate_not_space(&grantor.0, "grantor").map_err(|e| {
            LedgerError::Validation(e.to_string())
        })?;
        validate_not_space(&grantee.0, "grantee").map_err(|e| {
            LedgerError::Validation(e.to_string())
        })?;

        let consent_id = self.generate_id("consent");

        let entity = ConsentEntity {
            id: format!("l0_consent:{}:{}", self.tenant_id.0, consent_id),
            tenant_id: self.tenant_id.clone(),
            consent_id: consent_id.clone(),
            consent_type: Self::consent_type_to_str(consent_type).to_string(),
            grantor: grantor.0.clone(),
            grantee: grantee.0.clone(),
            resource_type: scope.resource_type.clone(),
            resource_id: scope.resource_id.clone(),
            actions: scope.actions.clone(),
            constraints_digest: scope.constraints_digest.map(|d| d.to_hex()),
            status: "active".to_string(),
            terms_digest: terms_digest.to_hex(),
            granted_at: Utc::now(),
            expires_at,
            revoked_at: None,
            revocation_reason_digest: None,
            superseded_by: None,
            receipt_id: None,
        };

        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!("CREATE {} CONTENT $data RETURN AFTER", ConsentEntity::TABLE);

        let mut response = session
            .client()
            .query(&query)
            .bind(("data", entity))
            .await
            .map_err(|e| LedgerError::Storage(format!("Create failed: {}", e)))?;

        let result: Option<ConsentEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let created = result.ok_or_else(|| LedgerError::Storage("Create returned no result".to_string()))?;
        Self::entity_to_consent_record(&created)
    }

    async fn revoke_consent(
        &self,
        consent_id: &str,
        reason_digest: Option<Digest>,
    ) -> LedgerResult<ReceiptId> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "UPDATE {} SET status = 'revoked', revoked_at = $now, revocation_reason_digest = $reason WHERE tenant_id = $tenant AND consent_id = $consent_id",
            ConsentEntity::TABLE
        );

        let consent_id_owned = consent_id.to_string();
        session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("consent_id", consent_id_owned))
            .bind(("now", Utc::now()))
            .bind(("reason", reason_digest.map(|d| d.to_hex())))
            .await
            .map_err(|e| LedgerError::Storage(format!("Update failed: {}", e)))?;

        Ok(ReceiptId(format!("receipt:revoke:{}", consent_id)))
    }

    async fn get_consent(&self, consent_id: &str) -> LedgerResult<Option<ConsentRecord>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND consent_id = $consent_id LIMIT 1",
            ConsentEntity::TABLE
        );

        let consent_id_owned = consent_id.to_string();
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("consent_id", consent_id_owned))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<ConsentEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        match result {
            Some(e) => Ok(Some(Self::entity_to_consent_record(&e)?)),
            None => Ok(None),
        }
    }

    async fn verify_consent(
        &self,
        grantor: &ActorId,
        grantee: &ActorId,
        action: &str,
        resource_type: &str,
    ) -> LedgerResult<ConsentVerifyResult> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND grantor = $grantor AND grantee = $grantee AND resource_type = $resource_type AND status = 'active' AND (expires_at IS NONE OR expires_at > $now) LIMIT 1",
            ConsentEntity::TABLE
        );

        let grantor_owned = grantor.0.clone();
        let grantee_owned = grantee.0.clone();
        let resource_type_owned = resource_type.to_string();
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("grantor", grantor_owned))
            .bind(("grantee", grantee_owned))
            .bind(("resource_type", resource_type_owned))
            .bind(("now", Utc::now()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<ConsentEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        match result {
            Some(entity) => {
                let has_action = entity.actions.contains(&action.to_string());
                if has_action {
                    Ok(ConsentVerifyResult::success(
                        entity.consent_id,
                        l0_core::types::EvidenceLevel::A,
                    ))
                } else {
                    Ok(ConsentVerifyResult {
                        valid: false,
                        consent_ref: Some(entity.consent_id),
                        reason: format!("Action '{}' not in allowed actions", action),
                        scope_matches: false,
                        ..Default::default()
                    })
                }
            }
            None => Ok(ConsentVerifyResult::failure("No active consent found")),
        }
    }

    async fn list_granted_consents(
        &self,
        grantor: &ActorId,
        status: Option<ConsentStatus>,
        options: QueryOptions,
    ) -> LedgerResult<Vec<ConsentRecord>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let status_clause = status
            .map(|s| format!("AND status = '{}'", Self::consent_status_to_str(s)))
            .unwrap_or_default();

        let limit = options.limit.unwrap_or(100);

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND grantor = $grantor {} ORDER BY granted_at DESC LIMIT {}",
            ConsentEntity::TABLE,
            status_clause,
            limit
        );

        let grantor_owned = grantor.0.clone();
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("grantor", grantor_owned))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let results: Vec<ConsentEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        results.iter().map(Self::entity_to_consent_record).collect()
    }

    async fn list_received_consents(
        &self,
        grantee: &ActorId,
        status: Option<ConsentStatus>,
        options: QueryOptions,
    ) -> LedgerResult<Vec<ConsentRecord>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let status_clause = status
            .map(|s| format!("AND status = '{}'", Self::consent_status_to_str(s)))
            .unwrap_or_default();

        let limit = options.limit.unwrap_or(100);

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND grantee = $grantee {} ORDER BY granted_at DESC LIMIT {}",
            ConsentEntity::TABLE,
            status_clause,
            limit
        );

        let grantee_owned = grantee.0.clone();
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("grantee", grantee_owned))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let results: Vec<ConsentEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        results.iter().map(Self::entity_to_consent_record).collect()
    }

    async fn issue_ticket(
        &self,
        consent_ref: &str,
        holder: &ActorId,
        target_resource: String,
        permissions: Vec<String>,
        valid_until: DateTime<Utc>,
        one_time: bool,
    ) -> LedgerResult<AccessTicket> {
        let ticket_id = self.generate_id("ticket");
        let now = Utc::now();

        // Compute ticket digest
        let mut digest_input = Vec::new();
        digest_input.extend_from_slice(ticket_id.as_bytes());
        digest_input.extend_from_slice(holder.0.as_bytes());
        digest_input.extend_from_slice(target_resource.as_bytes());
        let ticket_digest = Digest::blake3(&digest_input);

        let entity = AccessTicketEntity {
            id: format!("l0_access_ticket:{}:{}", self.tenant_id.0, ticket_id),
            tenant_id: self.tenant_id.clone(),
            ticket_id: ticket_id.clone(),
            consent_ref: consent_ref.to_string(),
            holder: holder.0.clone(),
            target_resource,
            permissions,
            issued_at: now,
            valid_from: now,
            valid_until,
            one_time,
            used_at: None,
            ticket_digest: ticket_digest.to_hex(),
            receipt_id: None,
        };

        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!("CREATE {} CONTENT $data RETURN AFTER", AccessTicketEntity::TABLE);

        let mut response = session
            .client()
            .query(&query)
            .bind(("data", entity))
            .await
            .map_err(|e| LedgerError::Storage(format!("Create failed: {}", e)))?;

        let result: Option<AccessTicketEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let created = result.ok_or_else(|| LedgerError::Storage("Create returned no result".to_string()))?;
        Self::entity_to_ticket(&created)
    }

    async fn use_ticket(&self, ticket_id: &str) -> LedgerResult<bool> {
        let ticket = self.get_ticket(ticket_id).await?;

        match ticket {
            None => Ok(false),
            Some(t) => {
                let now = Utc::now();

                // Check validity
                if now < t.valid_from || now > t.valid_until {
                    return Ok(false);
                }

                // Check one-time use
                if t.one_time && t.used_at.is_some() {
                    return Ok(false);
                }

                // Mark as used
                let session = self.datastore.session().await.map_err(|e| {
                    LedgerError::Storage(format!("Failed to get session: {}", e))
                })?;

                let query = format!(
                    "UPDATE {} SET used_at = $now WHERE tenant_id = $tenant AND ticket_id = $ticket_id",
                    AccessTicketEntity::TABLE
                );

                let ticket_id_owned = ticket_id.to_string();
                session
                    .client()
                    .query(&query)
                    .bind(("tenant", self.tenant_id.clone()))
                    .bind(("ticket_id", ticket_id_owned))
                    .bind(("now", now))
                    .await
                    .map_err(|e| LedgerError::Storage(format!("Update failed: {}", e)))?;

                Ok(true)
            }
        }
    }

    async fn get_ticket(&self, ticket_id: &str) -> LedgerResult<Option<AccessTicket>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND ticket_id = $ticket_id LIMIT 1",
            AccessTicketEntity::TABLE
        );

        let ticket_id_owned = ticket_id.to_string();
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("ticket_id", ticket_id_owned))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<AccessTicketEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        match result {
            Some(e) => Ok(Some(Self::entity_to_ticket(&e)?)),
            None => Ok(None),
        }
    }

    async fn create_delegation(
        &self,
        delegator: &ActorId,
        delegate: &ActorId,
        scope: ConsentScope,
        can_redelegate: bool,
        max_depth: u32,
        valid_until: Option<DateTime<Utc>>,
    ) -> LedgerResult<DelegationRecord> {
        let delegation_id = self.generate_id("deleg");
        let now = Utc::now();

        let entity = DelegationEntity {
            id: format!("l0_delegation:{}:{}", self.tenant_id.0, delegation_id),
            tenant_id: self.tenant_id.clone(),
            delegation_id: delegation_id.clone(),
            delegator: delegator.0.clone(),
            delegate: delegate.0.clone(),
            resource_type: scope.resource_type,
            actions: scope.actions,
            can_redelegate,
            max_depth,
            current_depth: 0,
            parent_delegation_ref: None,
            valid_from: now,
            valid_until,
            revoked_at: None,
            receipt_id: None,
        };

        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!("CREATE {} CONTENT $data RETURN AFTER", DelegationEntity::TABLE);

        let mut response = session
            .client()
            .query(&query)
            .bind(("data", entity))
            .await
            .map_err(|e| LedgerError::Storage(format!("Create failed: {}", e)))?;

        let result: Option<DelegationEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        let created = result.ok_or_else(|| LedgerError::Storage("Create returned no result".to_string()))?;
        Ok(Self::entity_to_delegation(&created))
    }

    async fn revoke_delegation(&self, delegation_id: &str) -> LedgerResult<ReceiptId> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "UPDATE {} SET revoked_at = $now WHERE tenant_id = $tenant AND delegation_id = $delegation_id",
            DelegationEntity::TABLE
        );

        let delegation_id_owned = delegation_id.to_string();
        session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("delegation_id", delegation_id_owned))
            .bind(("now", Utc::now()))
            .await
            .map_err(|e| LedgerError::Storage(format!("Update failed: {}", e)))?;

        Ok(ReceiptId(format!("receipt:revoke_delegation:{}", delegation_id)))
    }

    async fn get_delegation_chain(
        &self,
        delegation_id: &str,
    ) -> LedgerResult<Vec<DelegationRecord>> {
        // Walk up the delegation chain
        let mut chain = Vec::new();
        let mut current_id = Some(delegation_id.to_string());

        while let Some(id) = current_id {
            let session = self.datastore.session().await.map_err(|e| {
                LedgerError::Storage(format!("Failed to get session: {}", e))
            })?;

            let query = format!(
                "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND delegation_id = $delegation_id LIMIT 1",
                DelegationEntity::TABLE
            );

            let id_owned = id.clone();
            let mut response = session
                .client()
                .query(&query)
                .bind(("tenant", self.tenant_id.clone()))
                .bind(("delegation_id", id_owned))
                .await
                .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

            let result: Option<DelegationEntity> = response
                .take(0)
                .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

            match result {
                Some(entity) => {
                    current_id = entity.parent_delegation_ref.clone();
                    chain.push(Self::entity_to_delegation(&entity));
                }
                None => break,
            }

            // Prevent infinite loops
            if chain.len() > 100 {
                break;
            }
        }

        Ok(chain)
    }

    async fn record_emergency_override(
        &self,
        override_record: EmergencyOverrideRecord,
    ) -> LedgerResult<ReceiptId> {
        let entity = EmergencyOverrideEntity {
            id: format!("l0_emergency_override:{}:{}", self.tenant_id.0, override_record.override_id),
            tenant_id: self.tenant_id.clone(),
            override_id: override_record.override_id.clone(),
            justification_type: Self::justification_type_to_str(override_record.justification_type).to_string(),
            justification_digest: override_record.justification_digest.to_hex(),
            overridden_consent_ref: override_record.overridden_consent_ref.clone(),
            authorized_by: override_record.authorized_by.0.clone(),
            executed_by: override_record.executed_by.0.clone(),
            affected_actors: override_record.affected_actors.iter().map(|a| a.0.clone()).collect(),
            action_taken_digest: override_record.action_taken_digest.to_hex(),
            initiated_at: override_record.initiated_at,
            completed_at: override_record.completed_at,
            review_deadline: override_record.review_deadline,
            reviewed_by: override_record.reviewed_by.as_ref().map(|a| a.0.clone()),
            review_outcome_digest: override_record.review_outcome_digest.map(|d| d.to_hex()),
            receipt_id: override_record.receipt_id.as_ref().map(|r| r.0.clone()),
        };

        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!("CREATE {} CONTENT $data", EmergencyOverrideEntity::TABLE);

        session
            .client()
            .query(&query)
            .bind(("data", entity))
            .await
            .map_err(|e| LedgerError::Storage(format!("Create failed: {}", e)))?;

        Ok(ReceiptId(format!("receipt:emergency_override:{}", override_record.override_id)))
    }

    async fn get_pending_override_reviews(
        &self,
        options: QueryOptions,
    ) -> LedgerResult<Vec<EmergencyOverrideRecord>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let limit = options.limit.unwrap_or(100);
        let now = Utc::now();

        // Get overrides that haven't been reviewed yet and deadline hasn't passed
        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND reviewed_by IS NONE AND review_deadline > $now ORDER BY review_deadline ASC LIMIT {}",
            EmergencyOverrideEntity::TABLE,
            limit
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("now", now))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let results: Vec<EmergencyOverrideEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        results.iter().map(Self::entity_to_override).collect()
    }

    async fn update_covenant(
        &self,
        space_id: &SpaceId,
        covenant_digest: Digest,
        signatories: Vec<ActorId>,
    ) -> LedgerResult<CovenantStatus> {
        let now = Utc::now();

        // Check if covenant already exists for this space
        let existing = self.get_covenant(space_id).await?;

        let covenant_id = existing
            .as_ref()
            .map(|c| c.covenant_id.clone())
            .unwrap_or_else(|| self.generate_id("covenant"));

        let entity = CovenantEntity {
            id: format!("l0_covenant:{}:{}", self.tenant_id.0, covenant_id),
            tenant_id: self.tenant_id.clone(),
            covenant_id: covenant_id.clone(),
            space_id: space_id.0.clone(),
            covenant_digest: covenant_digest.to_hex(),
            signatories: signatories.iter().map(|a| a.0.clone()).collect(),
            effective_from: now,
            status: "active".to_string(),
            amendments_digest: existing.as_ref().and_then(|c| c.amendments_digest.as_ref()).map(|d| d.to_hex()),
            receipt_id: None,
        };

        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        if existing.is_some() {
            // Update existing covenant
            let query = format!(
                "UPDATE {} SET covenant_digest = $digest, signatories = $signatories, effective_from = $now, status = 'active' WHERE tenant_id = $tenant AND space_id = $space_id",
                CovenantEntity::TABLE
            );

            session
                .client()
                .query(&query)
                .bind(("tenant", self.tenant_id.clone()))
                .bind(("space_id", space_id.0.clone()))
                .bind(("digest", covenant_digest.to_hex()))
                .bind(("signatories", signatories.iter().map(|a| a.0.clone()).collect::<Vec<_>>()))
                .bind(("now", now))
                .await
                .map_err(|e| LedgerError::Storage(format!("Update failed: {}", e)))?;
        } else {
            // Create new covenant
            let query = format!("CREATE {} CONTENT $data", CovenantEntity::TABLE);

            session
                .client()
                .query(&query)
                .bind(("data", entity.clone()))
                .await
                .map_err(|e| LedgerError::Storage(format!("Create failed: {}", e)))?;
        }

        Self::entity_to_covenant(&entity)
    }

    async fn get_covenant(&self, space_id: &SpaceId) -> LedgerResult<Option<CovenantStatus>> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let query = format!(
            "SELECT *, type::string(id) AS id FROM {} WHERE tenant_id = $tenant AND space_id = $space_id LIMIT 1",
            CovenantEntity::TABLE
        );

        let space_id_owned = space_id.0.clone();
        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("space_id", space_id_owned))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?;

        let result: Option<CovenantEntity> = response
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        match result {
            Some(e) => Ok(Some(Self::entity_to_covenant(&e)?)),
            None => Ok(None),
        }
    }
}
