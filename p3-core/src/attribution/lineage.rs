//! Lineage Tree Processing
//!
//! Handles ancestor attribution based on knowledge lineage.

use super::ShareInput;
use crate::error::P3Result;
use crate::types::*;
use rust_decimal::Decimal;
use std::collections::HashMap;

/// Lineage processor
pub struct LineageProcessor {
    /// Policy version
    policy: LineagePolicyVersion,
}

impl LineageProcessor {
    /// Create new processor with policy
    pub fn new(policy: LineagePolicyVersion) -> Self {
        Self { policy }
    }

    /// Create processor with default policy
    pub fn default_v1(epoch_id: EpochId) -> Self {
        Self::new(LineagePolicyVersion::default_policy(epoch_id))
    }

    /// Process lineage tree and compute ancestor shares
    pub fn process_tree(&self, tree: &LineageTree) -> P3Result<Vec<ShareInput>> {
        let mut inputs = Vec::new();

        for node in &tree.nodes {
            if node.depth > self.policy.max_depth {
                continue;
            }

            // Apply decay factor
            let decay_factor = self.policy.decay_curve.factor_at_depth(node.depth);
            let adjusted_weight = node.share_weight * decay_factor;

            // Skip if below threshold
            if adjusted_weight < self.policy.min_share_threshold {
                continue;
            }

            inputs.push(ShareInput {
                contributor_id: node.actor_id.clone(),
                contributor_type: self.node_to_contributor_type(&node.contribution_type),
                weight: adjusted_weight,
                basis_ref: if node.parent_refs.is_empty() {
                    P3Digest::zero()
                } else {
                    node.parent_refs[0].clone()
                },
            });
        }

        // Merge shares for same actor
        let merged = self.merge_actor_shares(inputs);

        Ok(merged)
    }

    /// Build lineage tree from parent references
    pub fn build_tree(
        &self,
        root_object_id: &str,
        parent_map: &HashMap<String, Vec<ParentRef>>,
    ) -> P3Result<LineageTree> {
        let mut nodes = Vec::new();
        let mut visited = std::collections::HashSet::new();

        self.traverse_lineage(
            root_object_id,
            parent_map,
            0,
            Decimal::ONE,
            &mut nodes,
            &mut visited,
        );

        let tree = LineageTree {
            root_object_id: root_object_id.to_string(),
            nodes,
            tree_digest: P3Digest::zero(),
            policy_version: self.policy.version_id.clone(),
            computed_at: chrono::Utc::now(),
        };

        Ok(tree)
    }

    /// Recursive lineage traversal
    fn traverse_lineage(
        &self,
        object_id: &str,
        parent_map: &HashMap<String, Vec<ParentRef>>,
        depth: u32,
        weight: Decimal,
        nodes: &mut Vec<LineageNode>,
        visited: &mut std::collections::HashSet<String>,
    ) {
        // Check max depth
        if depth > self.policy.max_depth {
            return;
        }

        // Check if already visited (prevent cycles)
        if visited.contains(object_id) {
            return;
        }
        visited.insert(object_id.to_string());

        // Get parent references
        if let Some(parents) = parent_map.get(object_id) {
            let parent_count = parents.len();
            if parent_count == 0 {
                return;
            }

            let weight_per_parent = weight / Decimal::from(parent_count as i64);

            for parent in parents {
                // Apply decay
                let decayed_weight = weight_per_parent * self.policy.decay_curve.factor_at_depth(depth);

                // Skip if below threshold
                if decayed_weight < self.policy.min_share_threshold {
                    continue;
                }

                let node = LineageNode {
                    node_id: format!("{}:{}", object_id, depth),
                    actor_id: parent.actor_id.clone(),
                    depth,
                    share_weight: decayed_weight,
                    parent_refs: vec![parent.object_digest.clone()],
                    contribution_type: parent.contribution_type.clone(),
                };
                nodes.push(node);

                // Recurse to parent's parents
                self.traverse_lineage(
                    &parent.object_id,
                    parent_map,
                    depth + 1,
                    decayed_weight,
                    nodes,
                    visited,
                );
            }
        }
    }

    /// Convert contribution type to contributor type
    fn node_to_contributor_type(&self, contribution: &ContributionType) -> ContributorType {
        match contribution {
            ContributionType::Direct => ContributorType::HumanActor,
            ContributionType::Derived => ContributorType::AncestorAkn,
            ContributionType::Cited => ContributorType::AncestorAkn,
            ContributionType::Referenced => ContributorType::AncestorAkn,
        }
    }

    /// Merge shares for same actor
    fn merge_actor_shares(&self, inputs: Vec<ShareInput>) -> Vec<ShareInput> {
        let mut actor_weights: HashMap<String, (ShareInput, Decimal)> = HashMap::new();

        for input in inputs {
            let key = input.contributor_id.as_str().to_string();
            actor_weights
                .entry(key)
                .and_modify(|(existing, total)| {
                    *total += input.weight;
                })
                .or_insert((input.clone(), input.weight));
        }

        actor_weights
            .into_values()
            .map(|(mut input, total)| {
                input.weight = total;
                input
            })
            .collect()
    }

    /// Get policy
    pub fn policy(&self) -> &LineagePolicyVersion {
        &self.policy
    }
}

/// Parent reference for lineage building
#[derive(Clone, Debug)]
pub struct ParentRef {
    /// Parent object ID
    pub object_id: String,
    /// Parent actor ID
    pub actor_id: ActorId,
    /// Object digest
    pub object_digest: P3Digest,
    /// Contribution type
    pub contribution_type: ContributionType,
}

impl ParentRef {
    /// Create new parent ref
    pub fn new(
        object_id: impl Into<String>,
        actor_id: ActorId,
        contribution_type: ContributionType,
    ) -> Self {
        Self {
            object_id: object_id.into(),
            actor_id,
            object_digest: P3Digest::zero(),
            contribution_type,
        }
    }

    /// Set object digest
    pub fn with_digest(mut self, digest: P3Digest) -> Self {
        self.object_digest = digest;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_policy() -> LineagePolicyVersion {
        LineagePolicyVersion::default_policy(EpochId::new("epoch:genesis"))
    }

    #[test]
    fn test_lineage_processor_creation() {
        let processor = LineageProcessor::new(create_test_policy());
        assert_eq!(processor.policy.max_depth, 5);
    }

    #[test]
    fn test_process_simple_tree() {
        let processor = LineageProcessor::new(create_test_policy());

        let tree = LineageTree {
            root_object_id: "obj:root".to_string(),
            nodes: vec![
                LineageNode {
                    node_id: "node:1".to_string(),
                    actor_id: ActorId::new("actor:1"),
                    depth: 1,
                    share_weight: Decimal::new(5, 1), // 0.5
                    parent_refs: vec![],
                    contribution_type: ContributionType::Derived,
                },
                LineageNode {
                    node_id: "node:2".to_string(),
                    actor_id: ActorId::new("actor:2"),
                    depth: 1,
                    share_weight: Decimal::new(5, 1), // 0.5
                    parent_refs: vec![],
                    contribution_type: ContributionType::Cited,
                },
            ],
            tree_digest: P3Digest::zero(),
            policy_version: "v1".to_string(),
            computed_at: chrono::Utc::now(),
        };

        let inputs = processor.process_tree(&tree).unwrap();

        assert_eq!(inputs.len(), 2);
    }

    #[test]
    fn test_decay_application() {
        let mut policy = create_test_policy();
        policy.decay_curve = DecayCurve::Exponential {
            base: Decimal::new(5, 1), // 0.5
        };

        let processor = LineageProcessor::new(policy);

        let tree = LineageTree {
            root_object_id: "obj:root".to_string(),
            nodes: vec![
                LineageNode {
                    node_id: "node:1".to_string(),
                    actor_id: ActorId::new("actor:1"),
                    depth: 0,
                    share_weight: Decimal::ONE,
                    parent_refs: vec![],
                    contribution_type: ContributionType::Direct,
                },
                LineageNode {
                    node_id: "node:2".to_string(),
                    actor_id: ActorId::new("actor:2"),
                    depth: 1,
                    share_weight: Decimal::ONE,
                    parent_refs: vec![],
                    contribution_type: ContributionType::Derived,
                },
                LineageNode {
                    node_id: "node:3".to_string(),
                    actor_id: ActorId::new("actor:3"),
                    depth: 2,
                    share_weight: Decimal::ONE,
                    parent_refs: vec![],
                    contribution_type: ContributionType::Derived,
                },
            ],
            tree_digest: P3Digest::zero(),
            policy_version: "v1".to_string(),
            computed_at: chrono::Utc::now(),
        };

        let inputs = processor.process_tree(&tree).unwrap();

        // Verify decay was applied
        let input0 = inputs.iter().find(|i| i.contributor_id.as_str() == "actor:1").unwrap();
        let input1 = inputs.iter().find(|i| i.contributor_id.as_str() == "actor:2").unwrap();
        let input2 = inputs.iter().find(|i| i.contributor_id.as_str() == "actor:3").unwrap();

        assert_eq!(input0.weight, Decimal::ONE); // depth 0: 1.0
        assert_eq!(input1.weight, Decimal::new(5, 1)); // depth 1: 0.5
        assert_eq!(input2.weight, Decimal::new(25, 2)); // depth 2: 0.25
    }

    #[test]
    fn test_build_tree() {
        let processor = LineageProcessor::default_v1(EpochId::new("epoch:1"));

        let mut parent_map = HashMap::new();
        parent_map.insert(
            "obj:child".to_string(),
            vec![ParentRef::new("obj:parent", ActorId::new("actor:parent"), ContributionType::Derived)],
        );

        let tree = processor.build_tree("obj:child", &parent_map).unwrap();

        assert_eq!(tree.root_object_id, "obj:child");
        assert!(!tree.nodes.is_empty());
    }

    #[test]
    fn test_depth_limit() {
        let mut policy = create_test_policy();
        policy.max_depth = 1;

        let processor = LineageProcessor::new(policy);

        let tree = LineageTree {
            root_object_id: "obj:root".to_string(),
            nodes: vec![
                LineageNode {
                    node_id: "node:1".to_string(),
                    actor_id: ActorId::new("actor:1"),
                    depth: 1,
                    share_weight: Decimal::ONE,
                    parent_refs: vec![],
                    contribution_type: ContributionType::Direct,
                },
                LineageNode {
                    node_id: "node:2".to_string(),
                    actor_id: ActorId::new("actor:2"),
                    depth: 2, // Beyond max depth
                    share_weight: Decimal::ONE,
                    parent_refs: vec![],
                    contribution_type: ContributionType::Derived,
                },
            ],
            tree_digest: P3Digest::zero(),
            policy_version: "v1".to_string(),
            computed_at: chrono::Utc::now(),
        };

        let inputs = processor.process_tree(&tree).unwrap();

        // Only depth 1 should be included
        assert_eq!(inputs.len(), 1);
    }
}
