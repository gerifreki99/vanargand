// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The sparse Merkle tree that holds state.
//!
//! A map from 32-byte keys to 32-byte value digests, with a single 32-byte root
//! that commits to the whole map — and, crucially, to everything that is *not*
//! in it.
//!
//! # Why non-inclusion proofs are the point
//!
//! An ordinary Merkle tree proves "this is in the set". A sparse one also
//! proves "this is **not** in the set", and Vanargand needs that far more than
//! it needs the first. A light client shown a balance has no way to know it was
//! not shown a stale one; a light client that can prove a key is absent can
//! check that a name is unregistered, that a device has been revoked, that a
//! channel has been closed. It is also half of what makes A7's state-transition
//! fraud proofs possible: a refutation says "the committee claimed this
//! transition, and here is the branch showing the input it needed was not
//! there".
//!
//! # Two rules that make it work
//!
//! **An empty subtree is `ZERO` at every depth.** Without that, a tree of depth
//! 256 would need 256 hashes to prove anything. With it, the empty parts cost
//! nothing and the proofs are as short as the tree is actually populated.
//!
//! **A subtree holding exactly one key collapses to that key's leaf hash.** The
//! leaf hash binds the key itself, so collapsing loses nothing — and a verifier
//! recomputing upwards has to check that the leaf it was handed really belongs
//! on the path it was handed, which is the subtle part and the part this
//! implementation gets wrong if [`SmtProof`]'s prefix check is ever removed.
//!
//! # Performance, honestly
//!
//! [`SparseMerkleTree::root`] recomputes from scratch, in time linear in the
//! number of entries. That is correct and it is not what a production node
//! should run: it needs an incremental tree with persisted internal nodes, so
//! that a block changing ten accounts costs ten paths rather than a full sweep.
//! The interface here is the one such a tree would expose, and the tests below
//! are the ones it would have to pass.

use std::collections::BTreeMap;

use vanargand_types::codec::{CodecError, Decode, Decoder, Encode, Encoder};
use vanargand_types::Hash;

/// Depth of the tree: one level per bit of the key.
pub const DEPTH: usize = 256;

/// Hashes a leaf: `H[smt leaf](key ‖ value)`.
#[must_use]
pub fn leaf_hash(key: &Hash, value: &Hash) -> Hash {
    vanargand_crypto::hash::Hasher::new(vanargand_crypto::hash::domain::SMT_LEAF)
        .update(key.as_bytes())
        .update(value.as_bytes())
        .finalize()
}

/// Combines two children.
///
/// Two empty children make an empty parent, at every depth. That single rule is
/// what turns a 256-level tree from a thought experiment into something that
/// fits in a proof.
#[must_use]
pub fn combine(left: &Hash, right: &Hash) -> Hash {
    if *left == Hash::ZERO && *right == Hash::ZERO {
        return Hash::ZERO;
    }
    vanargand_crypto::hash::Hasher::new(vanargand_crypto::hash::domain::SMT_NODE)
        .update(left.as_bytes())
        .update(right.as_bytes())
        .finalize()
}

/// A key and the digest of its value, as found at the end of a proof path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmtLeaf {
    /// The key this leaf holds.
    pub key: Hash,
    /// The digest of its value.
    pub value: Hash,
}

impl Encode for SmtLeaf {
    fn encode(&self, out: &mut Encoder) {
        self.key.encode(out);
        self.value.encode(out);
    }
}

impl Decode for SmtLeaf {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self { key: Hash::decode(input)?, value: Hash::decode(input)? })
    }
}

/// A proof about one key: that it holds a value, or that it holds nothing.
///
/// The same object proves both. Which one it proves depends on `terminal`:
///
/// - `terminal` is the key being proved — the key is present with that value;
/// - `terminal` is a *different* key — the key is absent, and this other leaf
///   is the witness, because it occupies the position the key would have gone
///   to;
/// - `terminal` is `None` — the key is absent and the subtree is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtProof {
    /// Sibling digests, from the root downwards.
    pub siblings: Vec<Hash>,
    /// What was found at the end of the path.
    pub terminal: Option<SmtLeaf>,
}

impl SmtProof {
    /// Recomputes the root this proof implies for `key` holding `value`.
    ///
    /// `value` is `None` to ask about absence. Returns `None` when the proof is
    /// structurally invalid — which is a rejection, not an error to be
    /// recovered from.
    #[must_use]
    pub fn compute_root(&self, key: &Hash, value: Option<&Hash>) -> Option<Hash> {
        if self.siblings.len() > DEPTH {
            return None;
        }

        let mut current = match (&self.terminal, value) {
            // Proving presence: the terminal must be this key, with this value.
            (Some(leaf), Some(expected)) => {
                if leaf.key != *key || leaf.value != *expected {
                    return None;
                }
                leaf_hash(&leaf.key, &leaf.value)
            }
            // Proving absence against an occupying leaf: it must be a
            // *different* key, and it must genuinely lie on this key's path.
            //
            // The prefix check is the one that matters. Without it a prover
            // could take any leaf from anywhere in the tree, recompute upwards
            // using the queried key's bits, and produce a valid-looking proof
            // that an occupied key is empty.
            (Some(leaf), None) => {
                if leaf.key == *key {
                    return None;
                }
                if !shares_prefix(&leaf.key, key, self.siblings.len()) {
                    return None;
                }
                leaf_hash(&leaf.key, &leaf.value)
            }
            // Proving absence against an empty subtree.
            (None, None) => Hash::ZERO,
            // An empty terminal cannot prove presence.
            (None, Some(_)) => return None,
        };

        // Walk back up, deepest sibling first.
        for depth in (0..self.siblings.len()).rev() {
            let sibling = *self.siblings.get(depth)?;
            current = if key.bit(depth) {
                combine(&sibling, &current)
            } else {
                combine(&current, &sibling)
            };
        }
        Some(current)
    }

    /// Whether this proof shows `key` holds `value` under `root`.
    #[must_use]
    pub fn verify(&self, root: &Hash, key: &Hash, value: Option<&Hash>) -> bool {
        self.compute_root(key, value).is_some_and(|computed| computed == *root)
    }
}

impl Encode for SmtProof {
    fn encode(&self, out: &mut Encoder) {
        out.write_seq(&self.siblings);
        out.write_option(self.terminal.as_ref());
    }
}

impl Decode for SmtProof {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let siblings = input.read_seq::<Hash>()?;
        if siblings.len() > DEPTH {
            return Err(CodecError::LimitExceeded {
                limit: "sparse Merkle proof depth",
                max: DEPTH,
                got: siblings.len(),
            });
        }
        Ok(Self { siblings, terminal: input.read_option::<SmtLeaf>()? })
    }
}

/// Whether two keys agree on their first `bits` bits.
#[must_use]
fn shares_prefix(a: &Hash, b: &Hash, bits: usize) -> bool {
    (0..bits.min(DEPTH)).all(|index| a.bit(index) == b.bit(index))
}

/// A sparse Merkle tree over 32-byte keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SparseMerkleTree {
    entries: BTreeMap<Hash, Hash>,
}

impl SparseMerkleTree {
    /// An empty tree. Its root is [`Hash::ZERO`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets `key` to `value`.
    pub fn insert(&mut self, key: Hash, value: Hash) {
        self.entries.insert(key, value);
    }

    /// Removes `key`, returning what it held.
    ///
    /// Removal is not a nicety. `docs/01-concept.pdf` requires every settled
    /// obligation to leave state the moment it closes — "le registre n'a pas de
    /// mémoire des dettes payées, seulement des obligations en cours" — and
    /// that is what keeps the state small enough to run a node on a fifty-euro
    /// computer in ten years' time.
    pub fn remove(&mut self, key: &Hash) -> Option<Hash> {
        self.entries.remove(key)
    }

    /// What `key` holds, if anything.
    #[must_use]
    pub fn get(&self, key: &Hash) -> Option<Hash> {
        self.entries.get(key).copied()
    }

    /// How many keys are populated.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the tree is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every entry, in ascending key order.
    pub fn iter(&self) -> impl Iterator<Item = (&Hash, &Hash)> {
        self.entries.iter()
    }

    /// The root digest.
    #[must_use]
    pub fn root(&self) -> Hash {
        let entries: Vec<(Hash, Hash)> =
            self.entries.iter().map(|(key, value)| (*key, *value)).collect();
        subtree_root(&entries, 0)
    }

    /// A proof about `key`, whether it is present or absent.
    #[must_use]
    pub fn prove(&self, key: &Hash) -> SmtProof {
        let entries: Vec<(Hash, Hash)> =
            self.entries.iter().map(|(k, v)| (*k, *v)).collect();
        let mut siblings = Vec::new();
        let terminal = walk(&entries, key, 0, &mut siblings);
        SmtProof { siblings, terminal }
    }
}

/// The root of a subtree holding `entries`, which are sorted by key.
fn subtree_root(entries: &[(Hash, Hash)], depth: usize) -> Hash {
    match entries.len() {
        0 => Hash::ZERO,
        // A subtree with one key collapses to its leaf, at any depth. The leaf
        // hash binds the key, so nothing is lost.
        1 => match entries.first() {
            Some((key, value)) => leaf_hash(key, value),
            None => Hash::ZERO,
        },
        _ => {
            if depth >= DEPTH {
                // Two distinct 32-byte keys cannot agree on all 256 bits, so
                // this is unreachable for well-formed input. Returning ZERO
                // rather than recursing keeps the function total.
                return Hash::ZERO;
            }
            let split = partition_point(entries, depth);
            let left = subtree_root(entries.get(..split).unwrap_or(&[]), depth.saturating_add(1));
            let right = subtree_root(entries.get(split..).unwrap_or(&[]), depth.saturating_add(1));
            combine(&left, &right)
        }
    }
}

/// Walks down towards `key`, collecting siblings, and returns what is found.
fn walk(
    entries: &[(Hash, Hash)],
    key: &Hash,
    depth: usize,
    siblings: &mut Vec<Hash>,
) -> Option<SmtLeaf> {
    match entries.len() {
        0 => None,
        1 => entries.first().map(|(k, v)| SmtLeaf { key: *k, value: *v }),
        _ => {
            if depth >= DEPTH {
                return None;
            }
            let split = partition_point(entries, depth);
            let left = entries.get(..split).unwrap_or(&[]);
            let right = entries.get(split..).unwrap_or(&[]);
            if key.bit(depth) {
                siblings.push(subtree_root(left, depth.saturating_add(1)));
                walk(right, key, depth.saturating_add(1), siblings)
            } else {
                siblings.push(subtree_root(right, depth.saturating_add(1)));
                walk(left, key, depth.saturating_add(1), siblings)
            }
        }
    }
}

/// Index of the first entry whose bit at `depth` is set.
///
/// The entries are sorted by key, and [`Hash::bit`] reads the most significant
/// bit first, so all the zeros precede all the ones at every depth. That is
/// what lets the whole tree be computed from one sorted slice.
fn partition_point(entries: &[(Hash, Hash)], depth: usize) -> usize {
    entries.partition_point(|(key, _)| !key.bit(depth))
}

#[cfg(test)]
mod tests {
    use super::{combine, leaf_hash, SmtLeaf, SmtProof, SparseMerkleTree, DEPTH};
    use std::collections::BTreeSet;
    use vanargand_types::codec::{Decode, Encode};
    use vanargand_types::Hash;

    fn key(byte: u8) -> Hash {
        // Vary the whole digest so that keys diverge at different depths.
        let mut bytes = [0_u8; 32];
        bytes[0] = byte;
        bytes[31] = byte.wrapping_mul(7);
        Hash::from_bytes(bytes)
    }

    fn value(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    #[test]
    fn an_empty_tree_has_the_zero_root() {
        assert_eq!(SparseMerkleTree::new().root(), Hash::ZERO);
        assert!(SparseMerkleTree::new().is_empty());
    }

    #[test]
    fn empty_subtrees_cost_nothing() {
        // The rule that makes a 256-level tree usable at all.
        assert_eq!(combine(&Hash::ZERO, &Hash::ZERO), Hash::ZERO);
        assert_ne!(combine(&Hash::ZERO, &value(1)), Hash::ZERO);
        assert_ne!(combine(&value(1), &Hash::ZERO), Hash::ZERO);
        // And the two orderings are distinguishable.
        assert_ne!(combine(&Hash::ZERO, &value(1)), combine(&value(1), &Hash::ZERO));
    }

    #[test]
    fn a_leaf_is_not_an_internal_node() {
        // Different domains, so a leaf can never be presented as a node. The
        // standard second-preimage defence.
        let left = value(1);
        let right = value(2);
        assert_ne!(leaf_hash(&left, &right), combine(&left, &right));
    }

    #[test]
    fn the_root_changes_with_every_change() {
        let mut tree = SparseMerkleTree::new();
        let mut roots = BTreeSet::new();
        roots.insert(tree.root());

        for byte in 0..16_u8 {
            tree.insert(key(byte), value(byte));
            assert!(roots.insert(tree.root()), "root repeated after inserting key {byte}");
        }
        // Changing a value changes the root.
        tree.insert(key(0), value(200));
        assert!(roots.insert(tree.root()));
        // Removing restores an earlier root exactly.
        tree.insert(key(0), value(0));
        tree.remove(&key(15));
        let expected = {
            let mut rebuilt = SparseMerkleTree::new();
            for byte in 0..15_u8 {
                rebuilt.insert(key(byte), value(byte));
            }
            rebuilt.root()
        };
        assert_eq!(tree.root(), expected, "removal did not restore the earlier root");
    }

    #[test]
    fn insertion_order_does_not_affect_the_root() {
        // The determinism requirement, in its most direct form: two honest
        // nodes applying the same changes in different orders must agree.
        let mut forwards = SparseMerkleTree::new();
        for byte in 0..20_u8 {
            forwards.insert(key(byte), value(byte));
        }
        let mut backwards = SparseMerkleTree::new();
        for byte in (0..20_u8).rev() {
            backwards.insert(key(byte), value(byte));
        }
        assert_eq!(forwards.root(), backwards.root());
    }

    #[test]
    fn a_present_key_proves_its_value() {
        let mut tree = SparseMerkleTree::new();
        for byte in 0..25_u8 {
            tree.insert(key(byte), value(byte));
        }
        let root = tree.root();

        for byte in 0..25_u8 {
            let proof = tree.prove(&key(byte));
            assert!(
                proof.verify(&root, &key(byte), Some(&value(byte))),
                "inclusion proof failed for key {byte}"
            );
        }
    }

    #[test]
    fn a_present_key_cannot_be_proved_to_hold_another_value() {
        let mut tree = SparseMerkleTree::new();
        for byte in 0..10_u8 {
            tree.insert(key(byte), value(byte));
        }
        let root = tree.root();
        let proof = tree.prove(&key(3));
        assert!(!proof.verify(&root, &key(3), Some(&value(4))));
        assert!(!proof.verify(&root, &key(3), None), "a present key proved absent");
    }

    #[test]
    fn an_absent_key_proves_its_absence() {
        // The half an ordinary Merkle tree cannot do, and the half Vanargand
        // needs most.
        let mut tree = SparseMerkleTree::new();
        for byte in 0..25_u8 {
            tree.insert(key(byte), value(byte));
        }
        let root = tree.root();

        for byte in 25..60_u8 {
            let proof = tree.prove(&key(byte));
            assert!(
                proof.verify(&root, &key(byte), None),
                "non-inclusion proof failed for absent key {byte}"
            );
            assert!(
                !proof.verify(&root, &key(byte), Some(&value(byte))),
                "an absent key proved present"
            );
        }
    }

    #[test]
    fn absence_in_an_empty_tree_is_provable() {
        let tree = SparseMerkleTree::new();
        let proof = tree.prove(&key(1));
        assert_eq!(proof.siblings.len(), 0);
        assert_eq!(proof.terminal, None);
        assert!(proof.verify(&Hash::ZERO, &key(1), None));
    }

    #[test]
    fn absence_in_a_single_entry_tree_is_provable() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(key(1), value(1));
        let root = tree.root();

        let proof = tree.prove(&key(2));
        // The occupying leaf is the witness.
        assert_eq!(proof.terminal, Some(SmtLeaf { key: key(1), value: value(1) }));
        assert!(proof.verify(&root, &key(2), None));
        assert!(proof.verify(&root, &key(1), Some(&value(1))));
    }

    #[test]
    fn a_stolen_leaf_cannot_prove_absence() {
        // The attack the prefix check exists for. Take a leaf from elsewhere in
        // the tree, attach it to the queried key's path, and claim the key is
        // empty. Without the check, recomputing upwards with the *queried*
        // key's bits would produce a root that verifies.
        let mut tree = SparseMerkleTree::new();
        for byte in 0..30_u8 {
            tree.insert(key(byte), value(byte));
        }
        let root = tree.root();

        let target = key(7);
        let honest = tree.prove(&target);
        let elsewhere = tree.prove(&key(20));

        let forged = SmtProof {
            siblings: honest.siblings.clone(),
            terminal: elsewhere.terminal,
        };
        assert!(
            !forged.verify(&root, &target, None),
            "a leaf from elsewhere in the tree proved a populated key absent"
        );
    }

    #[test]
    fn a_proof_does_not_verify_against_another_root() {
        let mut tree = SparseMerkleTree::new();
        for byte in 0..8_u8 {
            tree.insert(key(byte), value(byte));
        }
        let proof = tree.prove(&key(3));
        let root = tree.root();
        tree.insert(key(100), value(100));
        assert!(proof.verify(&root, &key(3), Some(&value(3))));
        assert!(!proof.verify(&tree.root(), &key(3), Some(&value(3))));
    }

    #[test]
    fn tampering_with_any_sibling_breaks_the_proof() {
        let mut tree = SparseMerkleTree::new();
        for byte in 0..30_u8 {
            tree.insert(key(byte), value(byte));
        }
        let root = tree.root();
        let proof = tree.prove(&key(11));
        assert!(!proof.siblings.is_empty(), "the test needs a proof with siblings");

        for index in 0..proof.siblings.len() {
            let mut tampered = proof.clone();
            if let Some(sibling) = tampered.siblings.get_mut(index) {
                let mut bytes = *sibling.as_bytes();
                bytes[0] ^= 0x01;
                *sibling = Hash::from_bytes(bytes);
            }
            assert!(
                !tampered.verify(&root, &key(11), Some(&value(11))),
                "flipping sibling {index} still verified"
            );
        }
    }

    #[test]
    fn a_truncated_proof_does_not_verify() {
        let mut tree = SparseMerkleTree::new();
        for byte in 0..30_u8 {
            tree.insert(key(byte), value(byte));
        }
        let root = tree.root();
        let proof = tree.prove(&key(5));
        for cut in 0..proof.siblings.len() {
            let shortened = SmtProof {
                siblings: proof.siblings.get(..cut).unwrap_or(&[]).to_vec(),
                terminal: proof.terminal,
            };
            assert!(
                !shortened.verify(&root, &key(5), Some(&value(5))),
                "a proof truncated to {cut} siblings verified"
            );
        }
    }

    #[test]
    fn an_empty_terminal_cannot_prove_presence() {
        let proof = SmtProof { siblings: vec![], terminal: None };
        assert_eq!(proof.compute_root(&key(1), Some(&value(1))), None);
    }

    #[test]
    fn proofs_round_trip_through_the_codec() {
        let mut tree = SparseMerkleTree::new();
        for byte in 0..12_u8 {
            tree.insert(key(byte), value(byte));
        }
        for probe in [key(3), key(200)] {
            let proof = tree.prove(&probe);
            let bytes = proof.to_canonical_bytes();
            assert_eq!(SmtProof::from_canonical_bytes(&bytes), Ok(proof));
        }
    }

    #[test]
    fn an_over_deep_proof_is_rejected_by_the_decoder() {
        let proof = SmtProof { siblings: vec![Hash::ZERO; DEPTH + 1], terminal: None };
        let bytes = proof.to_canonical_bytes();
        assert!(SmtProof::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn keys_that_diverge_only_in_their_last_bit_still_work() {
        // The deepest case the tree can reach: two keys sharing 255 bits.
        let mut first = [0_u8; 32];
        let mut second = [0_u8; 32];
        second[31] = 1;
        let (a, b) = (Hash::from_bytes(first), Hash::from_bytes(second));
        first[31] = 2;
        let c = Hash::from_bytes(first);

        let mut tree = SparseMerkleTree::new();
        tree.insert(a, value(1));
        tree.insert(b, value(2));
        let root = tree.root();

        assert!(tree.prove(&a).verify(&root, &a, Some(&value(1))));
        assert!(tree.prove(&b).verify(&root, &b, Some(&value(2))));
        assert!(tree.prove(&c).verify(&root, &c, None));
        // One sibling per level walked: the two keys agree on bits 0..=254 and
        // split at bit 255, so the path is the full depth of the tree.
        assert_eq!(tree.prove(&a).siblings.len(), 256);
        assert_eq!(tree.prove(&c).siblings.len(), 255);
    }
}
