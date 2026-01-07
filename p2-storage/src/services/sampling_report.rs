//! Sampling Report Generation
//!
//! Generates detailed reports from sampling verification runs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::integrity_check::{IntegrityCheckResult, IntegrityCheckType, IntegrityStats};
use super::sampler::SelectedSample;

/// Sampling run report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingReport {
    /// Unique report ID
    pub report_id: String,
    /// Report generation timestamp
    pub generated_at: DateTime<Utc>,
    /// Sampling run start time
    pub run_started_at: DateTime<Utc>,
    /// Sampling run end time
    pub run_ended_at: DateTime<Utc>,
    /// Total run duration in seconds
    pub duration_secs: u64,
    /// Summary statistics
    pub summary: SamplingSummary,
    /// Results breakdown by temperature tier
    pub by_temperature: HashMap<String, TierResults>,
    /// Results breakdown by check type
    pub by_check_type: HashMap<String, CheckTypeResults>,
    /// Failed checks (for immediate attention)
    pub failures: Vec<FailureDetail>,
    /// Warnings (non-critical issues)
    pub warnings: Vec<ReportWarning>,
    /// Overall health assessment
    pub health_status: HealthStatus,
    /// Recommendations based on findings
    pub recommendations: Vec<String>,
}

/// Summary statistics for the sampling run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingSummary {
    /// Total population size
    pub population_size: usize,
    /// Number of samples selected
    pub samples_selected: usize,
    /// Sampling rate achieved
    pub sampling_rate: f64,
    /// Number of checks completed
    pub checks_completed: usize,
    /// Number of checks passed
    pub checks_passed: usize,
    /// Number of checks failed
    pub checks_failed: usize,
    /// Pass rate
    pub pass_rate: f64,
    /// Total data verified (bytes)
    pub total_bytes_verified: u64,
    /// Average check duration (ms)
    pub avg_check_duration_ms: u64,
}

/// Results for a temperature tier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierResults {
    /// Tier name
    pub tier: String,
    /// Number of samples from this tier
    pub sample_count: usize,
    /// Number passed
    pub passed: usize,
    /// Number failed
    pub failed: usize,
    /// Pass rate for this tier
    pub pass_rate: f64,
    /// Average check duration for this tier
    pub avg_duration_ms: u64,
}

/// Results for a check type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckTypeResults {
    /// Check type name
    pub check_type: String,
    /// Number of checks
    pub count: usize,
    /// Number passed
    pub passed: usize,
    /// Number failed
    pub failed: usize,
    /// Pass rate
    pub pass_rate: f64,
}

/// Details about a failed check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureDetail {
    /// Payload reference ID
    pub ref_id: String,
    /// Temperature tier
    pub temperature: String,
    /// Check type that failed
    pub check_type: String,
    /// Error message
    pub error: String,
    /// Check timestamp
    pub checked_at: DateTime<Utc>,
    /// Severity level
    pub severity: FailureSeverity,
    /// Suggested action
    pub suggested_action: String,
}

/// Failure severity
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FailureSeverity {
    /// Critical - data loss possible
    Critical,
    /// High - immediate attention needed
    High,
    /// Medium - should be investigated
    Medium,
    /// Low - minor issue
    Low,
}

/// Report warning (non-critical issue)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportWarning {
    /// Warning code
    pub code: String,
    /// Warning message
    pub message: String,
    /// Affected items count
    pub affected_count: usize,
}

/// Overall health status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HealthStatus {
    /// All checks passed
    Healthy,
    /// Minor issues detected
    Degraded,
    /// Significant issues
    Warning,
    /// Critical issues requiring immediate attention
    Critical,
}

/// Report builder
pub struct SamplingReportBuilder {
    report_id: String,
    run_started_at: DateTime<Utc>,
    population_size: usize,
    samples: Vec<SelectedSample>,
    results: Vec<IntegrityCheckResult>,
}

impl SamplingReportBuilder {
    /// Create a new report builder
    pub fn new(report_id: String, population_size: usize) -> Self {
        Self {
            report_id,
            run_started_at: Utc::now(),
            population_size,
            samples: Vec::new(),
            results: Vec::new(),
        }
    }

    /// Set run start time
    pub fn started_at(mut self, time: DateTime<Utc>) -> Self {
        self.run_started_at = time;
        self
    }

    /// Add selected samples
    pub fn with_samples(mut self, samples: Vec<SelectedSample>) -> Self {
        self.samples = samples;
        self
    }

    /// Add check results
    pub fn with_results(mut self, results: Vec<IntegrityCheckResult>) -> Self {
        self.results = results;
        self
    }

    /// Build the report
    pub fn build(self) -> SamplingReport {
        let run_ended_at = Utc::now();
        let duration_secs = (run_ended_at - self.run_started_at).num_seconds() as u64;

        let summary = self.build_summary();
        let by_temperature = self.build_temperature_breakdown();
        let by_check_type = self.build_check_type_breakdown();
        let failures = self.build_failure_details();
        let warnings = self.build_warnings(&summary);
        let health_status = self.determine_health_status(&summary, &failures);
        let recommendations = self.generate_recommendations(&summary, &failures, &warnings);

        SamplingReport {
            report_id: self.report_id,
            generated_at: Utc::now(),
            run_started_at: self.run_started_at,
            run_ended_at,
            duration_secs,
            summary,
            by_temperature,
            by_check_type,
            failures,
            warnings,
            health_status,
            recommendations,
        }
    }

    fn build_summary(&self) -> SamplingSummary {
        let checks_completed = self.results.len();
        let checks_passed = self.results.iter().filter(|r| r.passed).count();
        let checks_failed = checks_completed - checks_passed;

        let total_bytes: u64 = self.results.iter().filter_map(|r| r.size_bytes).sum();
        let total_duration: u64 = self.results.iter().map(|r| r.duration_ms).sum();

        SamplingSummary {
            population_size: self.population_size,
            samples_selected: self.samples.len(),
            sampling_rate: if self.population_size > 0 {
                self.samples.len() as f64 / self.population_size as f64
            } else {
                0.0
            },
            checks_completed,
            checks_passed,
            checks_failed,
            pass_rate: if checks_completed > 0 {
                checks_passed as f64 / checks_completed as f64
            } else {
                1.0
            },
            total_bytes_verified: total_bytes,
            avg_check_duration_ms: if checks_completed > 0 {
                total_duration / checks_completed as u64
            } else {
                0
            },
        }
    }

    fn build_temperature_breakdown(&self) -> HashMap<String, TierResults> {
        let mut by_temp: HashMap<String, Vec<&IntegrityCheckResult>> = HashMap::new();

        // Group results by temperature
        for result in &self.results {
            let temp = self
                .samples
                .iter()
                .find(|s| s.ref_id == result.ref_id)
                .map(|s| s.temperature.clone())
                .unwrap_or_else(|| "Unknown".to_string());

            by_temp.entry(temp).or_default().push(result);
        }

        by_temp
            .into_iter()
            .map(|(tier, results)| {
                let passed = results.iter().filter(|r| r.passed).count();
                let failed = results.len() - passed;
                let total_duration: u64 = results.iter().map(|r| r.duration_ms).sum();

                (
                    tier.clone(),
                    TierResults {
                        tier,
                        sample_count: results.len(),
                        passed,
                        failed,
                        pass_rate: if !results.is_empty() {
                            passed as f64 / results.len() as f64
                        } else {
                            1.0
                        },
                        avg_duration_ms: if !results.is_empty() {
                            total_duration / results.len() as u64
                        } else {
                            0
                        },
                    },
                )
            })
            .collect()
    }

    fn build_check_type_breakdown(&self) -> HashMap<String, CheckTypeResults> {
        let mut by_type: HashMap<IntegrityCheckType, Vec<&IntegrityCheckResult>> = HashMap::new();

        for result in &self.results {
            by_type.entry(result.check_type).or_default().push(result);
        }

        by_type
            .into_iter()
            .map(|(check_type, results)| {
                let passed = results.iter().filter(|r| r.passed).count();
                let failed = results.len() - passed;

                (
                    format!("{:?}", check_type),
                    CheckTypeResults {
                        check_type: format!("{:?}", check_type),
                        count: results.len(),
                        passed,
                        failed,
                        pass_rate: if !results.is_empty() {
                            passed as f64 / results.len() as f64
                        } else {
                            1.0
                        },
                    },
                )
            })
            .collect()
    }

    fn build_failure_details(&self) -> Vec<FailureDetail> {
        self.results
            .iter()
            .filter(|r| !r.passed)
            .map(|result| {
                let temperature = self
                    .samples
                    .iter()
                    .find(|s| s.ref_id == result.ref_id)
                    .map(|s| s.temperature.clone())
                    .unwrap_or_else(|| "Unknown".to_string());

                let severity = determine_severity(result, &temperature);
                let suggested_action = suggest_action(&severity, result);

                FailureDetail {
                    ref_id: result.ref_id.clone(),
                    temperature,
                    check_type: format!("{:?}", result.check_type),
                    error: result.error.clone().unwrap_or_else(|| "Unknown error".to_string()),
                    checked_at: result.checked_at,
                    severity,
                    suggested_action,
                }
            })
            .collect()
    }

    fn build_warnings(&self, summary: &SamplingSummary) -> Vec<ReportWarning> {
        let mut warnings = Vec::new();

        // Low sample rate warning
        if summary.sampling_rate < 0.0005 && self.population_size > 1000 {
            warnings.push(ReportWarning {
                code: "LOW_SAMPLE_RATE".to_string(),
                message: format!(
                    "Sampling rate ({:.4}%) is below recommended minimum (0.05%)",
                    summary.sampling_rate * 100.0
                ),
                affected_count: 0,
            });
        }

        // High latency warning
        if summary.avg_check_duration_ms > 5000 {
            warnings.push(ReportWarning {
                code: "HIGH_LATENCY".to_string(),
                message: format!(
                    "Average check duration ({}ms) exceeds 5 second threshold",
                    summary.avg_check_duration_ms
                ),
                affected_count: self
                    .results
                    .iter()
                    .filter(|r| r.duration_ms > 5000)
                    .count(),
            });
        }

        // Retry warning
        let high_retry_count = self
            .results
            .iter()
            .filter(|r| r.details.retry_count > 1)
            .count();
        if high_retry_count > 0 {
            warnings.push(ReportWarning {
                code: "HIGH_RETRY_COUNT".to_string(),
                message: "Some checks required multiple retries".to_string(),
                affected_count: high_retry_count,
            });
        }

        warnings
    }

    fn determine_health_status(
        &self,
        summary: &SamplingSummary,
        failures: &[FailureDetail],
    ) -> HealthStatus {
        let critical_count = failures
            .iter()
            .filter(|f| f.severity == FailureSeverity::Critical)
            .count();
        let high_count = failures
            .iter()
            .filter(|f| f.severity == FailureSeverity::High)
            .count();

        if critical_count > 0 {
            HealthStatus::Critical
        } else if high_count > 0 || summary.pass_rate < 0.95 {
            HealthStatus::Warning
        } else if summary.pass_rate < 0.99 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }

    fn generate_recommendations(
        &self,
        summary: &SamplingSummary,
        failures: &[FailureDetail],
        warnings: &[ReportWarning],
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Based on failures
        if !failures.is_empty() {
            let hot_failures = failures.iter().filter(|f| f.temperature == "Hot").count();
            if hot_failures > 0 {
                recommendations.push(format!(
                    "Investigate {} hot tier failures immediately - these affect frequently accessed data",
                    hot_failures
                ));
            }

            let checksum_failures = failures
                .iter()
                .filter(|f| f.check_type.contains("Checksum"))
                .count();
            if checksum_failures > 0 {
                recommendations.push(format!(
                    "Found {} checksum mismatches - verify data integrity and consider recovery from backups",
                    checksum_failures
                ));
            }
        }

        // Based on pass rate
        if summary.pass_rate < 0.99 {
            recommendations.push(
                "Pass rate below 99% - increase sampling frequency to catch issues earlier"
                    .to_string(),
            );
        }

        // Based on warnings
        for warning in warnings {
            match warning.code.as_str() {
                "LOW_SAMPLE_RATE" => {
                    recommendations
                        .push("Consider increasing base sampling rate for better coverage".to_string());
                }
                "HIGH_LATENCY" => {
                    recommendations
                        .push("Storage backend showing high latency - investigate performance".to_string());
                }
                "HIGH_RETRY_COUNT" => {
                    recommendations.push(
                        "Multiple retries needed - check network stability and backend health"
                            .to_string(),
                    );
                }
                _ => {}
            }
        }

        if recommendations.is_empty() {
            recommendations.push("No issues found - continue regular sampling schedule".to_string());
        }

        recommendations
    }
}

/// Determine failure severity
fn determine_severity(result: &IntegrityCheckResult, temperature: &str) -> FailureSeverity {
    // Checksum mismatch is always critical
    if result
        .error
        .as_ref()
        .map(|e| e.contains("mismatch"))
        .unwrap_or(false)
    {
        return FailureSeverity::Critical;
    }

    // Hot tier failures are high severity
    if temperature == "Hot" {
        return FailureSeverity::High;
    }

    // Accessibility failures
    if !result.details.readable {
        return if temperature == "Warm" {
            FailureSeverity::High
        } else {
            FailureSeverity::Medium
        };
    }

    FailureSeverity::Low
}

/// Suggest action for failure
fn suggest_action(severity: &FailureSeverity, result: &IntegrityCheckResult) -> String {
    match severity {
        FailureSeverity::Critical => {
            "IMMEDIATE: Verify backup availability and initiate data recovery process".to_string()
        }
        FailureSeverity::High => {
            if !result.details.readable {
                "Verify storage backend connectivity and check for hardware issues".to_string()
            } else {
                "Re-verify with fresh read and compare with known good copy".to_string()
            }
        }
        FailureSeverity::Medium => {
            "Schedule investigation within 24 hours".to_string()
        }
        FailureSeverity::Low => {
            "Monitor for recurrence in next sampling run".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_builder() {
        let samples = vec![SelectedSample {
            ref_id: "test:001".to_string(),
            temperature: "Hot".to_string(),
            selected_at: Utc::now(),
            selection_reason: crate::services::sampler::SampleSelectionReason::Random,
            priority: 50.0,
        }];

        let results = vec![IntegrityCheckResult {
            ref_id: "test:001".to_string(),
            checked_at: Utc::now(),
            passed: true,
            check_type: IntegrityCheckType::ChecksumVerification,
            expected_checksum: Some("abc123".to_string()),
            actual_checksum: Some("abc123".to_string()),
            duration_ms: 100,
            size_bytes: Some(1024),
            error: None,
            details: super::super::integrity_check::CheckDetails::default(),
        }];

        let report = SamplingReportBuilder::new("report:001".to_string(), 100)
            .with_samples(samples)
            .with_results(results)
            .build();

        assert_eq!(report.summary.checks_completed, 1);
        assert_eq!(report.summary.checks_passed, 1);
        assert_eq!(report.health_status, HealthStatus::Healthy);
    }

    #[test]
    fn test_failure_severity() {
        use super::super::integrity_check::CheckDetails;

        let critical_result = IntegrityCheckResult {
            ref_id: "test:001".to_string(),
            checked_at: Utc::now(),
            passed: false,
            check_type: IntegrityCheckType::ChecksumVerification,
            expected_checksum: Some("abc".to_string()),
            actual_checksum: Some("def".to_string()),
            duration_ms: 100,
            size_bytes: Some(1024),
            error: Some("Checksum mismatch".to_string()),
            details: CheckDetails::default(),
        };

        assert_eq!(
            determine_severity(&critical_result, "Cold"),
            FailureSeverity::Critical
        );
    }
}
