//! Observer Report Service
//!
//! Manages observer reports, corroboration, and network health monitoring.

use async_trait::async_trait;
use chrono::Utc;
use l0_core::error::LedgerError;
use l0_core::ledger::LedgerResult;
use l0_core::types::{
    ActorId, Digest, NetworkHealthSnapshot, ObserverRecord, ObserverReport,
    ObserverReportPolicy, ObserverStatus, ReportCorroboration, ReportResolution,
    ReportSeverity, ReportStatus, ReportType, ResolutionOutcome,
};
use soulbase_storage::surreal::SurrealDatastore;
use soulbase_storage::Datastore;
use soulbase_types::prelude::TenantId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Observer Report Ledger trait
#[async_trait]
pub trait ObserverReportLedger: Send + Sync {
    /// Register a new observer
    async fn register_observer(
        &self,
        observer_id: &ActorId,
        public_key: &str,
    ) -> LedgerResult<ObserverRecord>;

    /// Submit a new report
    async fn submit_report(
        &self,
        observer_id: &ActorId,
        report_type: ReportType,
        severity: ReportSeverity,
        subject_id: Option<&str>,
        title: &str,
        description: &str,
        evidence_digest: Option<Digest>,
        observed_epoch: u64,
    ) -> LedgerResult<ObserverReport>;

    /// Corroborate an existing report
    async fn corroborate_report(
        &self,
        report_id: &str,
        observer_id: &ActorId,
        evidence_digest: Option<Digest>,
        notes: Option<&str>,
        signature: &str,
    ) -> LedgerResult<ObserverReport>;

    /// Resolve a report
    async fn resolve_report(
        &self,
        report_id: &str,
        resolved_by: &ActorId,
        outcome: ResolutionOutcome,
        actions_taken: Vec<String>,
        notes: Option<&str>,
    ) -> LedgerResult<ObserverReport>;

    /// Update observer heartbeat
    async fn update_heartbeat(&self, observer_id: &ActorId) -> LedgerResult<ObserverRecord>;

    /// Get observer by ID
    async fn get_observer(&self, observer_id: &ActorId) -> LedgerResult<Option<ObserverRecord>>;

    /// Get report by ID
    async fn get_report(&self, report_id: &str) -> LedgerResult<Option<ObserverReport>>;

    /// Get pending reports
    async fn get_pending_reports(&self) -> LedgerResult<Vec<ObserverReport>>;

    /// Get reports by type
    async fn get_reports_by_type(&self, report_type: ReportType) -> LedgerResult<Vec<ObserverReport>>;

    /// Get reports for epoch
    async fn get_reports_for_epoch(&self, epoch: u64) -> LedgerResult<Vec<ObserverReport>>;

    /// Get active observers
    async fn get_active_observers(&self) -> LedgerResult<Vec<ObserverRecord>>;

    /// Create network health snapshot
    async fn create_health_snapshot(&self, epoch: u64) -> LedgerResult<NetworkHealthSnapshot>;

    /// Update report policy
    async fn update_policy(&self, policy: ObserverReportPolicy) -> LedgerResult<()>;
}

/// Observer Report Service implementation
pub struct ObserverReportService {
    datastore: Arc<SurrealDatastore>,
    tenant_id: TenantId,
    observers: RwLock<HashMap<String, ObserverRecord>>,
    reports: RwLock<HashMap<String, ObserverReport>>,
    policy: RwLock<ObserverReportPolicy>,
    sequence: std::sync::atomic::AtomicU64,
}

impl ObserverReportService {
    pub fn new(datastore: Arc<SurrealDatastore>, tenant_id: TenantId) -> Self {
        Self {
            datastore,
            tenant_id,
            observers: RwLock::new(HashMap::new()),
            reports: RwLock::new(HashMap::new()),
            policy: RwLock::new(ObserverReportPolicy::default()),
            sequence: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn generate_report_id(&self) -> String {
        let seq = self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = Utc::now().timestamp_micros();
        format!("rpt_{:016x}_{:08x}", timestamp, seq)
    }

    fn generate_snapshot_id(&self) -> String {
        let seq = self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = Utc::now().timestamp_micros();
        format!("snap_{:016x}_{:08x}", timestamp, seq)
    }

    fn get_min_corroborations(&self, severity: ReportSeverity) -> u32 {
        let policy = self.policy.read().unwrap();
        match severity {
            ReportSeverity::Info | ReportSeverity::Low => policy.min_corroborations_low,
            ReportSeverity::Medium => policy.min_corroborations_medium,
            ReportSeverity::High | ReportSeverity::Critical => policy.min_corroborations_high,
        }
    }

    async fn save_observer_to_db(&self, observer: &ObserverRecord) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let observer_id = observer.observer_id.0.clone();
        let public_key = observer.public_key.clone();
        let status = serde_json::to_string(&observer.status).unwrap_or_default();
        let reputation_score = observer.reputation_score;
        let total_reports = observer.total_reports;
        let valid_reports = observer.valid_reports;
        let invalid_reports = observer.invalid_reports;
        let registered_at = observer.registered_at.to_rfc3339();
        let last_report_at = observer.last_report_at.map(|d| d.to_rfc3339());
        let last_heartbeat_at = observer.last_heartbeat_at.to_rfc3339();

        let _: Option<ObserverRecord> = session
            .client()
            .query(
                "UPSERT observer_records SET
                    tenant_id = $tenant,
                    observer_id = $observer_id,
                    public_key = $public_key,
                    status = $status,
                    reputation_score = $reputation_score,
                    total_reports = $total_reports,
                    valid_reports = $valid_reports,
                    invalid_reports = $invalid_reports,
                    registered_at = $registered_at,
                    last_report_at = $last_report_at,
                    last_heartbeat_at = $last_heartbeat_at
                WHERE tenant_id = $tenant AND observer_id = $observer_id",
            )
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("observer_id", observer_id))
            .bind(("public_key", public_key))
            .bind(("status", status))
            .bind(("reputation_score", reputation_score))
            .bind(("total_reports", total_reports))
            .bind(("valid_reports", valid_reports))
            .bind(("invalid_reports", invalid_reports))
            .bind(("registered_at", registered_at))
            .bind(("last_report_at", last_report_at))
            .bind(("last_heartbeat_at", last_heartbeat_at))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(())
    }

    async fn save_report_to_db(&self, report: &ObserverReport) -> LedgerResult<()> {
        let session = self.datastore.session().await.map_err(|e| {
            LedgerError::Storage(format!("Failed to get session: {}", e))
        })?;

        let report_id = report.report_id.clone();
        let observer_id = report.observer_id.0.clone();
        let report_type = serde_json::to_string(&report.report_type).unwrap_or_default();
        let severity = serde_json::to_string(&report.severity).unwrap_or_default();
        let subject_id = report.subject_id.clone();
        let title = report.title.clone();
        let description = report.description.clone();
        let evidence_digest = report.evidence_digest.as_ref().map(|d| d.to_hex());
        let observed_epoch = report.observed_epoch;
        let observed_at = report.observed_at.to_rfc3339();
        let submitted_at = report.submitted_at.to_rfc3339();
        let status = serde_json::to_string(&report.status).unwrap_or_default();
        let corroborations = serde_json::to_string(&report.corroborations).unwrap_or_default();
        let min_corroborations = report.min_corroborations;
        let resolution = serde_json::to_string(&report.resolution).unwrap_or_default();

        let _: Option<ObserverReport> = session
            .client()
            .query(
                "UPSERT observer_reports SET
                    tenant_id = $tenant,
                    report_id = $report_id,
                    observer_id = $observer_id,
                    report_type = $report_type,
                    severity = $severity,
                    subject_id = $subject_id,
                    title = $title,
                    description = $description,
                    evidence_digest = $evidence_digest,
                    observed_epoch = $observed_epoch,
                    observed_at = $observed_at,
                    submitted_at = $submitted_at,
                    status = $status,
                    corroborations = $corroborations,
                    min_corroborations = $min_corroborations,
                    resolution = $resolution
                WHERE tenant_id = $tenant AND report_id = $report_id",
            )
            .bind(("tenant", self.tenant_id.clone()))
            .bind(("report_id", report_id))
            .bind(("observer_id", observer_id))
            .bind(("report_type", report_type))
            .bind(("severity", severity))
            .bind(("subject_id", subject_id))
            .bind(("title", title))
            .bind(("description", description))
            .bind(("evidence_digest", evidence_digest))
            .bind(("observed_epoch", observed_epoch))
            .bind(("observed_at", observed_at))
            .bind(("submitted_at", submitted_at))
            .bind(("status", status))
            .bind(("corroborations", corroborations))
            .bind(("min_corroborations", min_corroborations))
            .bind(("resolution", resolution))
            .await
            .map_err(|e| LedgerError::Storage(format!("Query failed: {}", e)))?
            .take(0)
            .map_err(|e| LedgerError::Storage(format!("Parse failed: {}", e)))?;

        Ok(())
    }
}

#[async_trait]
impl ObserverReportLedger for ObserverReportService {
    async fn register_observer(
        &self,
        observer_id: &ActorId,
        public_key: &str,
    ) -> LedgerResult<ObserverRecord> {
        let now = Utc::now();
        let observer = ObserverRecord {
            observer_id: observer_id.clone(),
            public_key: public_key.to_string(),
            status: ObserverStatus::Active,
            reputation_score: 500, // Starting reputation
            total_reports: 0,
            valid_reports: 0,
            invalid_reports: 0,
            registered_at: now,
            last_report_at: None,
            last_heartbeat_at: now,
        };

        {
            let mut observers = self.observers.write().unwrap();
            observers.insert(observer_id.0.clone(), observer.clone());
        }

        self.save_observer_to_db(&observer).await?;
        Ok(observer)
    }

    async fn submit_report(
        &self,
        observer_id: &ActorId,
        report_type: ReportType,
        severity: ReportSeverity,
        subject_id: Option<&str>,
        title: &str,
        description: &str,
        evidence_digest: Option<Digest>,
        observed_epoch: u64,
    ) -> LedgerResult<ObserverReport> {
        // Validate observer
        {
            let observers = self.observers.read().unwrap();
            let observer = observers
                .get(&observer_id.0)
                .ok_or_else(|| LedgerError::NotFound(format!("Observer {}", observer_id.0)))?;

            if observer.status != ObserverStatus::Active {
                return Err(LedgerError::Validation(
                    "Observer is not active".to_string(),
                ));
            }

            let policy = self.policy.read().unwrap();
            if observer.reputation_score < policy.min_reputation {
                return Err(LedgerError::Validation(
                    "Observer reputation too low".to_string(),
                ));
            }
        }

        let now = Utc::now();
        let report = ObserverReport {
            report_id: self.generate_report_id(),
            observer_id: observer_id.clone(),
            report_type,
            severity,
            subject_id: subject_id.map(|s| s.to_string()),
            title: title.to_string(),
            description: description.to_string(),
            evidence_digest,
            observed_epoch,
            observed_at: now,
            submitted_at: now,
            status: ReportStatus::Pending,
            corroborations: Vec::new(),
            min_corroborations: self.get_min_corroborations(severity),
            resolution: None,
        };

        // Update observer stats
        {
            let mut observers = self.observers.write().unwrap();
            if let Some(obs) = observers.get_mut(&observer_id.0) {
                obs.total_reports += 1;
                obs.last_report_at = Some(now);
            }
        }

        {
            let mut reports = self.reports.write().unwrap();
            reports.insert(report.report_id.clone(), report.clone());
        }

        self.save_report_to_db(&report).await?;
        Ok(report)
    }

    async fn corroborate_report(
        &self,
        report_id: &str,
        observer_id: &ActorId,
        evidence_digest: Option<Digest>,
        notes: Option<&str>,
        signature: &str,
    ) -> LedgerResult<ObserverReport> {
        // Validate observer
        {
            let observers = self.observers.read().unwrap();
            let observer = observers
                .get(&observer_id.0)
                .ok_or_else(|| LedgerError::NotFound(format!("Observer {}", observer_id.0)))?;

            if observer.status != ObserverStatus::Active {
                return Err(LedgerError::Validation(
                    "Observer is not active".to_string(),
                ));
            }
        }

        let report = {
            let mut reports = self.reports.write().unwrap();
            let report = reports
                .get_mut(report_id)
                .ok_or_else(|| LedgerError::NotFound(format!("Report {}", report_id)))?;

            if report.status != ReportStatus::Pending {
                return Err(LedgerError::Validation(
                    "Report is not pending".to_string(),
                ));
            }

            // Check not self-corroborating
            if &report.observer_id == observer_id {
                return Err(LedgerError::Validation(
                    "Cannot corroborate own report".to_string(),
                ));
            }

            // Check not already corroborated by this observer
            if report.corroborations.iter().any(|c| &c.observer_id == observer_id) {
                return Err(LedgerError::Validation(
                    "Already corroborated".to_string(),
                ));
            }

            report.corroborations.push(ReportCorroboration {
                observer_id: observer_id.clone(),
                evidence_digest,
                corroborated_at: Utc::now(),
                notes: notes.map(|s| s.to_string()),
                signature: signature.to_string(),
            });

            // Check if now corroborated
            if report.has_enough_corroborations() {
                report.status = ReportStatus::Corroborated;
            }

            report.clone()
        };

        self.save_report_to_db(&report).await?;
        Ok(report)
    }

    async fn resolve_report(
        &self,
        report_id: &str,
        resolved_by: &ActorId,
        outcome: ResolutionOutcome,
        actions_taken: Vec<String>,
        notes: Option<&str>,
    ) -> LedgerResult<ObserverReport> {
        let (report, observer_id) = {
            let mut reports = self.reports.write().unwrap();
            let report = reports
                .get_mut(report_id)
                .ok_or_else(|| LedgerError::NotFound(format!("Report {}", report_id)))?;

            if report.resolution.is_some() {
                return Err(LedgerError::Validation(
                    "Report already resolved".to_string(),
                ));
            }

            report.resolution = Some(ReportResolution {
                resolved_by: resolved_by.clone(),
                outcome,
                actions_taken,
                resolved_at: Utc::now(),
                notes: notes.map(|s| s.to_string()),
            });

            report.status = match outcome {
                ResolutionOutcome::ActionTaken | ResolutionOutcome::NoActionNeeded => {
                    ReportStatus::Confirmed
                }
                _ => ReportStatus::Dismissed,
            };

            (report.clone(), report.observer_id.clone())
        };

        // Update observer reputation based on outcome
        {
            let mut observers = self.observers.write().unwrap();
            if let Some(obs) = observers.get_mut(&observer_id.0) {
                let policy = self.policy.read().unwrap();
                match outcome {
                    ResolutionOutcome::ActionTaken | ResolutionOutcome::NoActionNeeded => {
                        obs.valid_reports += 1;
                        obs.reputation_score = (obs.reputation_score + policy.valid_report_reward).min(1000);
                    }
                    ResolutionOutcome::FalsePositive | ResolutionOutcome::InsufficientEvidence => {
                        obs.invalid_reports += 1;
                        obs.reputation_score = obs.reputation_score.saturating_sub(policy.invalid_report_penalty);
                    }
                    ResolutionOutcome::Duplicate => {
                        // No penalty for duplicates
                    }
                }
            }
        }

        self.save_report_to_db(&report).await?;
        Ok(report)
    }

    async fn update_heartbeat(&self, observer_id: &ActorId) -> LedgerResult<ObserverRecord> {
        let observer = {
            let mut observers = self.observers.write().unwrap();
            let observer = observers
                .get_mut(&observer_id.0)
                .ok_or_else(|| LedgerError::NotFound(format!("Observer {}", observer_id.0)))?;

            observer.last_heartbeat_at = Utc::now();
            observer.clone()
        };

        self.save_observer_to_db(&observer).await?;
        Ok(observer)
    }

    async fn get_observer(&self, observer_id: &ActorId) -> LedgerResult<Option<ObserverRecord>> {
        let observers = self.observers.read().unwrap();
        Ok(observers.get(&observer_id.0).cloned())
    }

    async fn get_report(&self, report_id: &str) -> LedgerResult<Option<ObserverReport>> {
        let reports = self.reports.read().unwrap();
        Ok(reports.get(report_id).cloned())
    }

    async fn get_pending_reports(&self) -> LedgerResult<Vec<ObserverReport>> {
        let reports = self.reports.read().unwrap();
        Ok(reports
            .values()
            .filter(|r| r.status == ReportStatus::Pending || r.status == ReportStatus::Corroborated)
            .cloned()
            .collect())
    }

    async fn get_reports_by_type(&self, report_type: ReportType) -> LedgerResult<Vec<ObserverReport>> {
        let reports = self.reports.read().unwrap();
        Ok(reports
            .values()
            .filter(|r| r.report_type == report_type)
            .cloned()
            .collect())
    }

    async fn get_reports_for_epoch(&self, epoch: u64) -> LedgerResult<Vec<ObserverReport>> {
        let reports = self.reports.read().unwrap();
        Ok(reports
            .values()
            .filter(|r| r.observed_epoch == epoch)
            .cloned()
            .collect())
    }

    async fn get_active_observers(&self) -> LedgerResult<Vec<ObserverRecord>> {
        let observers = self.observers.read().unwrap();
        Ok(observers
            .values()
            .filter(|o| o.status == ObserverStatus::Active)
            .cloned()
            .collect())
    }

    async fn create_health_snapshot(&self, epoch: u64) -> LedgerResult<NetworkHealthSnapshot> {
        let observers = self.observers.read().unwrap();
        let reports = self.reports.read().unwrap();

        let active_observers: Vec<_> = observers
            .values()
            .filter(|o| o.status == ObserverStatus::Active)
            .cloned()
            .collect();

        let epoch_reports: Vec<_> = reports
            .values()
            .filter(|r| r.observed_epoch == epoch)
            .collect();

        let missed_signatures = epoch_reports
            .iter()
            .filter(|r| r.report_type == ReportType::MissedSignature)
            .count() as u32;

        let double_sign_attempts = epoch_reports
            .iter()
            .filter(|r| r.report_type == ReportType::DoubleSignEvidence)
            .count() as u32;

        let snapshot = NetworkHealthSnapshot {
            snapshot_id: self.generate_snapshot_id(),
            epoch,
            active_signers: 9, // TODO: Get from signer set
            active_observers: active_observers.len() as u32,
            avg_block_time_ms: 100, // TODO: Calculate from actual data
            missed_signatures,
            double_sign_attempts,
            connectivity_score: 95, // TODO: Calculate from actual data
            consensus_score: 98,    // TODO: Calculate from actual data
            snapshot_at: Utc::now(),
            contributing_observers: active_observers.iter().map(|o| o.observer_id.clone()).collect(),
        };

        Ok(snapshot)
    }

    async fn update_policy(&self, policy: ObserverReportPolicy) -> LedgerResult<()> {
        let mut current = self.policy.write().unwrap();
        *current = policy;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_min_corroborations() {
        let policy = ObserverReportPolicy::default();
        assert_eq!(policy.min_corroborations_low, 1);
        assert_eq!(policy.min_corroborations_medium, 2);
        assert_eq!(policy.min_corroborations_high, 3);
    }
}
