//! Persistent Sequence Manager
//!
//! Provides persistent sequence number generation that survives service restarts.
//! Each ledger service uses this to generate unique, monotonically increasing IDs.

use soulbase_storage::surreal::SurrealDatastore;
use soulbase_storage::Datastore;
use soulbase_types::prelude::TenantId;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::error::L0DbError;

/// Persistent sequence generator for a specific ledger
///
/// This struct manages sequence numbers that persist across service restarts.
/// On initialization, it queries the database to find the maximum sequence number
/// for the given ledger and tenant, ensuring no ID collisions after restart.
pub struct PersistentSequence {
    /// Current sequence value (atomic for thread-safety)
    current: AtomicU64,
    /// Ledger name (for identification)
    ledger_name: String,
    /// Tenant ID
    tenant_id: TenantId,
    /// Database reference for persistence
    datastore: Arc<SurrealDatastore>,
    /// Table name to query for max sequence
    table_name: String,
    /// Column name that contains the sequence
    sequence_column: String,
}

impl PersistentSequence {
    /// Create a new persistent sequence manager
    ///
    /// This will query the database to find the maximum existing sequence
    /// and initialize the counter to continue from there.
    pub async fn new(
        datastore: Arc<SurrealDatastore>,
        tenant_id: TenantId,
        ledger_name: &str,
        table_name: &str,
        sequence_column: &str,
    ) -> Result<Self, L0DbError> {
        let seq = Self {
            current: AtomicU64::new(0),
            ledger_name: ledger_name.to_string(),
            tenant_id,
            datastore,
            table_name: table_name.to_string(),
            sequence_column: sequence_column.to_string(),
        };

        // Load the max sequence from database
        seq.reload_from_db().await?;

        Ok(seq)
    }

    /// Create with a simple in-memory counter (for testing)
    ///
    /// This creates a sequence that only uses in-memory counting and doesn't
    /// persist to any database. Use the full `new()` constructor with a
    /// datastore for production use.
    #[cfg(test)]
    pub fn new_in_memory(ledger_name: &str, initial_value: u64) -> Self {
        // Create a minimal struct - the datastore won't actually be used
        // since table_name is empty
        use std::sync::OnceLock;
        static DUMMY_DS: OnceLock<Arc<SurrealDatastore>> = OnceLock::new();

        let ds = DUMMY_DS.get_or_init(|| {
            // This won't be used since table_name is empty
            // We need an Arc<SurrealDatastore> to satisfy the type, but it won't be called
            panic!("Dummy datastore should not be used - call reload_from_db in tests to check")
        });

        Self {
            current: AtomicU64::new(initial_value),
            ledger_name: ledger_name.to_string(),
            tenant_id: TenantId("memory".to_string()),
            datastore: ds.clone(),
            table_name: String::new(),
            sequence_column: String::new(),
        }
    }

    /// Create an in-memory sequence without database backing
    /// This is useful for testing or when persistence isn't needed
    pub fn in_memory(ledger_name: &str, initial_value: u64, datastore: Arc<SurrealDatastore>) -> Self {
        Self {
            current: AtomicU64::new(initial_value),
            ledger_name: ledger_name.to_string(),
            tenant_id: TenantId("memory".to_string()),
            datastore,
            table_name: String::new(),
            sequence_column: String::new(),
        }
    }

    /// Reload the sequence from the database
    ///
    /// Queries the maximum sequence number from the database and updates
    /// the internal counter. This is called on initialization and can be
    /// called again if needed (e.g., after a database restore).
    pub async fn reload_from_db(&self) -> Result<(), L0DbError> {
        if self.table_name.is_empty() {
            return Ok(()); // In-memory mode, nothing to reload
        }

        let session = self.datastore.session().await.map_err(|e| {
            L0DbError::QueryError(format!("Failed to get session: {}", e))
        })?;

        // Query for maximum sequence in the table for this tenant
        // We extract the sequence from the ID format: prefix_timestamp_sequence
        let query = format!(
            "SELECT math::max({}) AS max_seq FROM {} WHERE tenant_id = $tenant GROUP ALL",
            self.sequence_column,
            self.table_name
        );

        let mut response = session
            .client()
            .query(&query)
            .bind(("tenant", self.tenant_id.clone()))
            .await
            .map_err(|e| L0DbError::QueryError(format!("Query failed: {}", e)))?;

        // Try to parse the result
        #[derive(serde::Deserialize)]
        struct MaxResult {
            max_seq: Option<u64>,
        }

        let result: Option<MaxResult> = response
            .take(0)
            .map_err(|e| L0DbError::QueryError(format!("Parse failed: {}", e)))?;

        if let Some(r) = result {
            if let Some(max_seq) = r.max_seq {
                // Start from max + 1
                self.current.store(max_seq + 1, Ordering::SeqCst);
            }
        }

        Ok(())
    }

    /// Get the next sequence number
    ///
    /// This atomically increments and returns the next sequence number.
    /// Thread-safe and guaranteed to be unique within this service instance.
    pub fn next(&self) -> u64 {
        self.current.fetch_add(1, Ordering::SeqCst)
    }

    /// Get the current sequence number without incrementing
    pub fn current(&self) -> u64 {
        self.current.load(Ordering::SeqCst)
    }

    /// Get the ledger name
    pub fn ledger_name(&self) -> &str {
        &self.ledger_name
    }
}

/// Sequence manager that handles multiple ledgers
pub struct SequenceManager {
    sequences: std::collections::HashMap<String, Arc<PersistentSequence>>,
}

impl SequenceManager {
    /// Create a new sequence manager
    pub fn new() -> Self {
        Self {
            sequences: std::collections::HashMap::new(),
        }
    }

    /// Register a persistent sequence for a ledger
    pub fn register(&mut self, sequence: PersistentSequence) {
        self.sequences.insert(
            sequence.ledger_name.clone(),
            Arc::new(sequence),
        );
    }

    /// Get the sequence for a ledger
    pub fn get(&self, ledger_name: &str) -> Option<Arc<PersistentSequence>> {
        self.sequences.get(ledger_name).cloned()
    }
}

impl Default for SequenceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to extract sequence from an ID string
///
/// ID format: prefix_timestamp_sequence (e.g., "receipt_0000018d1234_00000001")
pub fn extract_sequence_from_id(id: &str) -> Option<u64> {
    let parts: Vec<&str> = id.split('_').collect();
    if parts.len() >= 3 {
        // The sequence is the last part, in hex
        u64::from_str_radix(parts.last()?, 16).ok()
    } else {
        None
    }
}

/// Helper function to get max sequence from a list of IDs
pub fn max_sequence_from_ids(ids: &[String]) -> u64 {
    ids.iter()
        .filter_map(|id| extract_sequence_from_id(id))
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_sequence_from_id() {
        assert_eq!(extract_sequence_from_id("receipt_0000018d1234_00000001"), Some(1));
        assert_eq!(extract_sequence_from_id("anchor_0000018d5678_000000ff"), Some(255));
        assert_eq!(extract_sequence_from_id("invalid"), None);
    }

    #[test]
    fn test_max_sequence_from_ids() {
        let ids = vec![
            "receipt_0000018d1234_00000001".to_string(),
            "receipt_0000018d1235_00000005".to_string(),
            "receipt_0000018d1236_00000003".to_string(),
        ];
        assert_eq!(max_sequence_from_ids(&ids), 5);
    }

    #[test]
    fn test_in_memory_sequence() {
        let seq = PersistentSequence::new_in_memory("test", 100);
        assert_eq!(seq.current(), 100);
        assert_eq!(seq.next(), 100);
        assert_eq!(seq.next(), 101);
        assert_eq!(seq.current(), 102);
    }
}
