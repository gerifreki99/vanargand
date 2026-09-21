// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The binary Merkle tree over a list.
//!
//! Used for a block's transaction root. The *sparse* Merkle tree that holds
//! state is a different construction and lives in `vanargand-state`; the two
//! must not be confused, which is why they are in different crates and share
//! only their domain strings.
//!
//! # Two properties, and the bugs they exist to prevent
//!
//! **Leaves and internal nodes hash under different domains.** Without that, an
//! internal node can be presented as a leaf and a proof can be forged for data
//! that was never in the tree. This is the standard second-preimage attack on
//! Merkle trees, and the defence costs nothing.
//!
//! **An odd node is promoted, never duplicated.** A level with an odd number of
//! nodes carries its last node up unchanged. The tempting alternative —
//! duplicating it so the level is even — is CVE-2012-2459: with duplication,
//! the lists `[a, b, c]` and `[a, b, c, c]` produce the same root, so two
//! different blocks have the same transaction root.

use vanargand_crypto::hash::{domain, Hash, Hasher};

/// Hashes a leaf into the tree.
#[must_use]
pub fn leaf_hash(leaf: &Hash) -> Hash {
    Hasher::new(domain::SMT_LEAF).update(leaf.as_bytes()).finalize()
}

/// Hashes two children into their parent.
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    Hasher::new(domain::SMT_NODE).update(left.as_bytes()).update(right.as_bytes()).finalize()
}

/// The root of the tree over `leaves`, in the given order.
///
/// An empty list has root [`Hash::ZERO`]. That is a sentinel, not a digest:
/// finding a preimage for it would be a break of BLAKE3, so no non-empty list
/// can collide with the empty one.
#[must_use]
pub fn list_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return Hash::ZERO;
    }
    let mut level: Vec<Hash> = leaves.iter().map(leaf_hash).collect();
    while level.len() > 1 {
        level = fold_level(&level);
    }
    level.first().copied().unwrap_or(Hash::ZERO)
}

fn fold_level(level: &[Hash]) -> Vec<Hash> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    let mut index = 0;
    while index.saturating_add(1) < level.len() {
        let (Some(left), Some(right)) = (level.get(index), level.get(index.saturating_add(1)))
        else {
            break;
        };
        next.push(node_hash(left, right));
        index = index.saturating_add(2);
    }
    if index < level.len() {
        // Promoted, not duplicated. See the module documentation.
        if let Some(last) = level.get(index) {
            next.push(*last);
        }
    }
    next
}

/// One step of an inclusion proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofStep {
    /// The sibling is on the left; the running value goes on the right.
    Left(Hash),
    /// The sibling is on the right; the running value goes on the left.
    Right(Hash),
    /// No sibling: the node was promoted unchanged to the next level.
    ///
    /// A distinct step rather than an absent one. A verifier that silently
    /// skipped a level would accept a proof for a different tree shape.
    Promoted,
}

/// An inclusion proof for one leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// Position of the leaf in the original list.
    pub index: usize,
    /// Steps from the leaf up to the root.
    pub steps: Vec<ProofStep>,
}

/// Builds an inclusion proof for `index`, or `None` if it is out of range.
#[must_use]
pub fn list_proof(leaves: &[Hash], index: usize) -> Option<InclusionProof> {
    if index >= leaves.len() {
        return None;
    }
    let mut level: Vec<Hash> = leaves.iter().map(leaf_hash).collect();
    let mut position = index;
    let mut steps = Vec::new();

    while level.len() > 1 {
        let is_promoted = position == level.len().saturating_sub(1) && level.len() % 2 == 1;
        if is_promoted {
            steps.push(ProofStep::Promoted);
        } else if position % 2 == 0 {
            let sibling = *level.get(position.saturating_add(1))?;
            steps.push(ProofStep::Right(sibling));
        } else {
            let sibling = *level.get(position.saturating_sub(1))?;
            steps.push(ProofStep::Left(sibling));
        }
        position /= 2;
        level = fold_level(&level);
    }

    Some(InclusionProof { index, steps })
}

/// Recomputes the root implied by `leaf` and `proof`.
///
/// Returns the computed root. The caller compares it with the root it trusts;
/// this function deliberately does not do the comparison, so that there is no
/// version of it that takes an expected root and can be called with the wrong
/// one.
#[must_use]
pub fn root_from_proof(leaf: &Hash, proof: &InclusionProof) -> Hash {
    let mut running = leaf_hash(leaf);
    for step in &proof.steps {
        running = match step {
            ProofStep::Left(sibling) => node_hash(sibling, &running),
            ProofStep::Right(sibling) => node_hash(&running, sibling),
            ProofStep::Promoted => running,
        };
    }
    running
}

#[cfg(test)]
mod tests {
    use super::{list_proof, list_root, node_hash, root_from_proof, ProofStep};
    use std::collections::BTreeSet;
    use vanargand_crypto::hash::Hash;

    fn leaves(count: usize) -> Vec<Hash> {
        (0..count).map(|index| Hash::from_bytes([u8::try_from(index).unwrap_or(0); 32])).collect()
    }

    #[test]
    fn an_empty_list_has_the_zero_root() {
        assert_eq!(list_root(&[]), Hash::ZERO);
    }

    #[test]
    fn a_single_leaf_root_is_its_leaf_hash_not_the_leaf() {
        // If the root of a one-element tree were the leaf itself, a 32-byte
        // value could be presented both as a transaction id and as a root.
        let one = leaves(1);
        assert_ne!(list_root(&one), one.first().copied().unwrap_or(Hash::ZERO));
        assert_eq!(list_root(&one), super::leaf_hash(&one[0]));
    }

    #[test]
    fn the_odd_node_is_promoted_and_not_duplicated() {
        // CVE-2012-2459, asserted. Under the duplicating rule, [a, b, c] and
        // [a, b, c, c] have the same root, so two different blocks share a
        // transaction root and one can be swapped for the other.
        let three = leaves(3);
        let mut duplicated = three.clone();
        duplicated.push(three[2]);
        assert_ne!(
            list_root(&three),
            list_root(&duplicated),
            "[a,b,c] and [a,b,c,c] collide; the odd node is being duplicated"
        );
    }

    #[test]
    fn distinct_lists_have_distinct_roots() {
        let mut roots = BTreeSet::new();
        for count in 0..12 {
            assert!(roots.insert(list_root(&leaves(count))), "collision at {count} leaves");
        }
        // Order matters.
        let forwards = leaves(4);
        let mut backwards = forwards.clone();
        backwards.reverse();
        assert_ne!(list_root(&forwards), list_root(&backwards));
    }

    #[test]
    fn a_three_leaf_root_is_what_the_rule_says_it_is() {
        // Computed by hand from the rule, so that the implementation is checked
        // against the specification rather than against itself.
        let items = leaves(3);
        let l0 = super::leaf_hash(&items[0]);
        let l1 = super::leaf_hash(&items[1]);
        let l2 = super::leaf_hash(&items[2]);
        // Level 1: node(l0, l1), then l2 promoted.
        let n01 = node_hash(&l0, &l1);
        // Level 2: node(n01, l2).
        let expected = node_hash(&n01, &l2);
        assert_eq!(list_root(&items), expected);
    }

    #[test]
    fn every_leaf_proves_its_own_inclusion() {
        for count in 1..20 {
            let items = leaves(count);
            let root = list_root(&items);
            for index in 0..count {
                let proof = list_proof(&items, index).expect("index in range");
                assert_eq!(
                    root_from_proof(&items[index], &proof),
                    root,
                    "proof failed for leaf {index} of {count}"
                );
            }
        }
    }

    #[test]
    fn a_proof_does_not_verify_for_another_leaf() {
        let items = leaves(7);
        let root = list_root(&items);
        let proof = list_proof(&items, 3).expect("index in range");
        for index in 0..items.len() {
            let computed = root_from_proof(&items[index], &proof);
            if index == 3 {
                assert_eq!(computed, root);
            } else {
                assert_ne!(computed, root, "leaf {index} verified against leaf 3's proof");
            }
        }
    }

    #[test]
    fn a_tampered_proof_does_not_verify() {
        let items = leaves(5);
        let root = list_root(&items);
        let proof = list_proof(&items, 1).expect("index in range");

        for position in 0..proof.steps.len() {
            let mut tampered = proof.clone();
            if let Some(step) = tampered.steps.get_mut(position) {
                *step = match *step {
                    ProofStep::Left(hash) => ProofStep::Right(hash),
                    ProofStep::Right(hash) => ProofStep::Left(hash),
                    ProofStep::Promoted => ProofStep::Right(Hash::ZERO),
                };
            }
            assert_ne!(
                root_from_proof(&items[1], &tampered),
                root,
                "swapping step {position} still verified"
            );
        }
    }

    #[test]
    fn an_out_of_range_index_has_no_proof() {
        assert!(list_proof(&leaves(3), 3).is_none());
        assert!(list_proof(&[], 0).is_none());
    }

    #[test]
    fn promotion_appears_in_proofs_for_odd_levels() {
        // Three leaves: leaf 2 is promoted at the first level.
        let proof = list_proof(&leaves(3), 2).expect("index in range");
        assert_eq!(proof.steps.first(), Some(&ProofStep::Promoted));
    }
}
