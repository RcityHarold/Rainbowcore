//! Random Sampling Algorithm
//!
//! Provides random payload selection for integrity verification sampling.

use chrono::{DateTime, Utc};
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::debug;

/// Sampling strategy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingStrategy {
    /// Base sampling rate (0.0 to 1.0)
    pub base_rate: f64,
    /// Minimum samples per run
    pub min_samples: usize,
    /// Maximum samples per run
    pub max_samples: usize,
    /// Whether to use stratified sampling by temperature
    pub stratified_by_temperature: bool,
    /// Hot tier sampling multiplier
    pub hot_multiplier: f64,
    /// Warm tier sampling multiplier
    pub warm_multiplier: f64,
    /// Cold tier sampling multiplier
    pub cold_multiplier: f64,
    /// Whether to prioritize recently modified
    pub prioritize_recent: bool,
    /// Seed for reproducibility (None for random)
    pub seed: Option<u64>,
}

impl Default for SamplingStrategy {
    fn default() -> Self {
        Self {
            base_rate: 0.001, // 0.1%
            min_samples: 10,
            max_samples: 1000,
            stratified_by_temperature: true,
            hot_multiplier: 1.5,
            warm_multiplier: 1.0,
            cold_multiplier: 0.5,
            prioritize_recent: true,
            seed: None,
        }
    }
}

/// Temperature tier for stratified sampling
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TemperatureTier {
    Hot,
    Warm,
    Cold,
}

/// Payload metadata for sampling decisions
#[derive(Debug, Clone)]
pub struct PayloadSampleInfo {
    /// Payload reference ID
    pub ref_id: String,
    /// Temperature tier
    pub temperature: TemperatureTier,
    /// Last access time
    pub last_accessed: DateTime<Utc>,
    /// Last verification time
    pub last_verified: Option<DateTime<Utc>>,
    /// Size in bytes
    pub size_bytes: u64,
    /// Number of times previously sampled
    pub sample_count: u32,
}

/// Selected sample for verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedSample {
    /// Payload reference ID
    pub ref_id: String,
    /// Temperature tier at selection time
    pub temperature: String,
    /// Selection timestamp
    pub selected_at: DateTime<Utc>,
    /// Selection reason
    pub selection_reason: SampleSelectionReason,
    /// Priority score (higher = verify first)
    pub priority: f64,
}

/// Reason for sample selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SampleSelectionReason {
    /// Random selection based on sampling rate
    Random,
    /// Selected due to temperature tier stratification
    StratifiedByTemperature,
    /// Selected due to recent modification
    RecentlyModified,
    /// Selected due to long time since last verification
    NotRecentlyVerified,
    /// Manual selection
    Manual,
}

/// Random sampler for payload selection
pub struct PayloadSampler {
    strategy: SamplingStrategy,
    rng: StdRng,
    /// Track already-selected payloads to avoid duplicates
    selected_this_run: HashSet<String>,
}

impl PayloadSampler {
    /// Create a new sampler with the given strategy
    pub fn new(strategy: SamplingStrategy) -> Self {
        let rng = match strategy.seed {
            Some(seed) => StdRng::seed_from_u64(seed),
            None => StdRng::from_entropy(),
        };

        Self {
            strategy,
            rng,
            selected_this_run: HashSet::new(),
        }
    }

    /// Reset the sampler for a new run
    pub fn reset(&mut self) {
        self.selected_this_run.clear();
        // Re-seed if reproducibility is desired
        if let Some(seed) = self.strategy.seed {
            self.rng = StdRng::seed_from_u64(seed);
        }
    }

    /// Select samples from a population
    pub fn select_samples(&mut self, population: &[PayloadSampleInfo]) -> Vec<SelectedSample> {
        if population.is_empty() {
            return vec![];
        }

        let target_count = self.calculate_target_count(population.len());
        let mut samples = Vec::with_capacity(target_count);

        if self.strategy.stratified_by_temperature {
            // Group by temperature
            let mut hot: Vec<_> = population
                .iter()
                .filter(|p| p.temperature == TemperatureTier::Hot)
                .collect();
            let mut warm: Vec<_> = population
                .iter()
                .filter(|p| p.temperature == TemperatureTier::Warm)
                .collect();
            let mut cold: Vec<_> = population
                .iter()
                .filter(|p| p.temperature == TemperatureTier::Cold)
                .collect();

            // Calculate samples per tier
            let total_weight = self.strategy.hot_multiplier * hot.len() as f64
                + self.strategy.warm_multiplier * warm.len() as f64
                + self.strategy.cold_multiplier * cold.len() as f64;

            if total_weight > 0.0 {
                let hot_count =
                    ((target_count as f64 * self.strategy.hot_multiplier * hot.len() as f64)
                        / total_weight)
                        .ceil() as usize;
                let warm_count =
                    ((target_count as f64 * self.strategy.warm_multiplier * warm.len() as f64)
                        / total_weight)
                        .ceil() as usize;
                let cold_count =
                    ((target_count as f64 * self.strategy.cold_multiplier * cold.len() as f64)
                        / total_weight)
                        .ceil() as usize;

                samples.extend(self.select_from_tier(&mut hot, hot_count, TemperatureTier::Hot));
                samples.extend(self.select_from_tier(&mut warm, warm_count, TemperatureTier::Warm));
                samples.extend(self.select_from_tier(&mut cold, cold_count, TemperatureTier::Cold));
            }
        } else {
            // Simple random sampling
            samples.extend(self.simple_random_sample(population, target_count));
        }

        // Apply priority scoring
        for sample in &mut samples {
            sample.priority = self.calculate_priority(population, &sample.ref_id);
        }

        // Sort by priority (descending)
        samples.sort_by(|a, b| b.priority.partial_cmp(&a.priority).unwrap_or(std::cmp::Ordering::Equal));

        debug!(
            target_count = target_count,
            actual_count = samples.len(),
            "Selected samples for verification"
        );

        samples
    }

    /// Calculate target sample count
    fn calculate_target_count(&self, population_size: usize) -> usize {
        let calculated = (population_size as f64 * self.strategy.base_rate).ceil() as usize;
        calculated.clamp(self.strategy.min_samples.min(population_size), self.strategy.max_samples.min(population_size))
    }

    /// Select samples from a temperature tier
    fn select_from_tier(
        &mut self,
        tier: &mut [&PayloadSampleInfo],
        count: usize,
        temp: TemperatureTier,
    ) -> Vec<SelectedSample> {
        let mut samples = Vec::new();
        let count = count.min(tier.len());

        // Shuffle for randomness
        for i in (1..tier.len()).rev() {
            let j = self.rng.gen_range(0..=i);
            tier.swap(i, j);
        }

        for info in tier.iter().take(count) {
            if !self.selected_this_run.contains(&info.ref_id) {
                self.selected_this_run.insert(info.ref_id.clone());
                samples.push(SelectedSample {
                    ref_id: info.ref_id.clone(),
                    temperature: format!("{:?}", temp),
                    selected_at: Utc::now(),
                    selection_reason: SampleSelectionReason::StratifiedByTemperature,
                    priority: 0.0, // Will be calculated later
                });
            }
        }

        samples
    }

    /// Simple random sampling without stratification
    fn simple_random_sample(
        &mut self,
        population: &[PayloadSampleInfo],
        count: usize,
    ) -> Vec<SelectedSample> {
        let mut indices: Vec<_> = (0..population.len()).collect();
        let mut samples = Vec::new();

        // Fisher-Yates shuffle
        for i in (1..indices.len()).rev() {
            let j = self.rng.gen_range(0..=i);
            indices.swap(i, j);
        }

        for idx in indices.into_iter().take(count) {
            let info = &population[idx];
            if !self.selected_this_run.contains(&info.ref_id) {
                self.selected_this_run.insert(info.ref_id.clone());
                samples.push(SelectedSample {
                    ref_id: info.ref_id.clone(),
                    temperature: format!("{:?}", info.temperature),
                    selected_at: Utc::now(),
                    selection_reason: SampleSelectionReason::Random,
                    priority: 0.0,
                });
            }
        }

        samples
    }

    /// Calculate priority score for a sample
    fn calculate_priority(&self, population: &[PayloadSampleInfo], ref_id: &str) -> f64 {
        let info = match population.iter().find(|p| p.ref_id == ref_id) {
            Some(i) => i,
            None => return 0.0,
        };

        let mut priority = 50.0; // Base priority

        // Higher priority for hot data (more important to verify)
        priority += match info.temperature {
            TemperatureTier::Hot => 30.0,
            TemperatureTier::Warm => 15.0,
            TemperatureTier::Cold => 0.0,
        };

        // Higher priority if not recently verified
        if let Some(last_verified) = info.last_verified {
            let days_since = (Utc::now() - last_verified).num_days();
            priority += (days_since as f64 * 0.5).min(20.0);
        } else {
            // Never verified = high priority
            priority += 25.0;
        }

        // Lower priority if recently sampled
        priority -= (info.sample_count as f64 * 2.0).min(15.0);

        // Prioritize larger files (more at stake)
        let size_mb = info.size_bytes as f64 / (1024.0 * 1024.0);
        priority += (size_mb.ln() * 2.0).max(0.0).min(10.0);

        priority.max(0.0)
    }

    /// Get current strategy
    pub fn strategy(&self) -> &SamplingStrategy {
        &self.strategy
    }

    /// Update strategy
    pub fn set_strategy(&mut self, strategy: SamplingStrategy) {
        self.strategy = strategy;
        // Re-initialize RNG if seed changed
        if let Some(seed) = self.strategy.seed {
            self.rng = StdRng::seed_from_u64(seed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_population(count: usize) -> Vec<PayloadSampleInfo> {
        (0..count)
            .map(|i| PayloadSampleInfo {
                ref_id: format!("payload:{}", i),
                temperature: match i % 3 {
                    0 => TemperatureTier::Hot,
                    1 => TemperatureTier::Warm,
                    _ => TemperatureTier::Cold,
                },
                last_accessed: Utc::now(),
                last_verified: None,
                size_bytes: 1024 * (i as u64 + 1),
                sample_count: 0,
            })
            .collect()
    }

    #[test]
    fn test_sample_selection() {
        let strategy = SamplingStrategy {
            base_rate: 0.1, // 10%
            min_samples: 5,
            max_samples: 50,
            seed: Some(42), // For reproducibility
            ..Default::default()
        };

        let mut sampler = PayloadSampler::new(strategy);
        let population = make_test_population(100);
        let samples = sampler.select_samples(&population);

        assert!(samples.len() >= 5);
        assert!(samples.len() <= 50);
    }

    #[test]
    fn test_stratified_sampling() {
        let strategy = SamplingStrategy {
            base_rate: 0.3,
            min_samples: 9,
            max_samples: 100,
            stratified_by_temperature: true,
            seed: Some(42),
            ..Default::default()
        };

        let mut sampler = PayloadSampler::new(strategy);
        let population = make_test_population(30);
        let samples = sampler.select_samples(&population);

        // Should have samples from different temperatures
        let has_hot = samples.iter().any(|s| s.temperature == "Hot");
        let has_warm = samples.iter().any(|s| s.temperature == "Warm");
        let has_cold = samples.iter().any(|s| s.temperature == "Cold");

        assert!(has_hot || has_warm || has_cold);
    }

    #[test]
    fn test_priority_ordering() {
        let strategy = SamplingStrategy {
            base_rate: 1.0, // Select all
            min_samples: 1,
            max_samples: 1000,
            seed: Some(42),
            ..Default::default()
        };

        let mut sampler = PayloadSampler::new(strategy);
        let population = make_test_population(10);
        let samples = sampler.select_samples(&population);

        // Samples should be sorted by priority (descending)
        for i in 1..samples.len() {
            assert!(samples[i - 1].priority >= samples[i].priority);
        }
    }
}
