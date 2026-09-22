// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The epoch seed: where the committee draw's randomness comes from.
//!
//! See `spec/draft/07-consensus.md` §3 and threat-model entry A4.
//!
//! # The shape of the mechanism
//!
//! Each validator seals a hash-chain root when it bonds. Proposing a block
//! reveals the next link. The proposer cannot **choose** the value — the chain
//! was fixed before it knew anything about this epoch — and cannot **withhold**
//! it without forfeiting its turn, because revealing and proposing are the same
//! act.
//!
//! That single property is why R2 was able to withdraw the R1 slashing penalty
//! for non-revelation. A crash and a deliberate withholding produce the same
//! silence; Vanargand seizes only faults that carry their own proof; and the
//! contradiction with C9 — which rests on silence under partition not being
//! guilt — disappears.
//!
//! # The part that is not finished
//!
//! The mixed reveals are meant to pass through a verifiable delay function
//! longer than the window in which the last proposer of an epoch could act, so
//! that even that proposer cannot test which variant suits it. Without the VDF,
//! the last proposer retains one bit of influence per position it controls.
//!
//! [`crate::vdf`] implements the delay itself — iterated hashing, inherently
//! sequential — together with a checkpointed proof of sequential work whose
//! soundness is stated rather than assumed. What it does **not** implement is
//! the succinct STARK that R2 puts on the critical launch path: without one,
//! full verification costs what evaluation cost, and the sampled check is
//! probabilistic.
//!
//! So there are three grades of seed, and the type records which one it is:
//! [`EpochSeed::from_delay_function`] for an output somebody has verified,
//! [`EpochSeed::without_delay_function`] for a test network that skipped the
//! delay entirely, and in between the sampled check of
//! [`crate::vdf::DelayProof::check_sampled`].

use std::collections::BTreeMap;

use vanargand_crypto::hash::{domain, Hash, Hasher};
use vanargand_types::id::AccountId;

/// Mixes an epoch's reveals into a pre-delay value.
///
/// The reveals are keyed by proposer so that the caller cannot supply them in
/// arrival order, which differs between nodes. A `BTreeMap` iterates in
/// ascending account order, which is the order the specification fixes.
///
/// The epoch number is folded in as eight big-endian bytes, so that two epochs
/// with coincidentally identical reveal sets still produce different seeds.
#[must_use]
pub fn mix_reveals(epoch: u64, reveals: &BTreeMap<AccountId, Hash>) -> Hash {
    let mut hasher = Hasher::new(domain::EPOCH_SEED);
    for reveal in reveals.values() {
        hasher.update(reveal.as_bytes());
    }
    hasher.update(&epoch.to_be_bytes());
    hasher.finalize()
}

/// The randomness an epoch's committee is drawn from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSeed {
    value: Hash,
    delayed: bool,
}

impl EpochSeed {
    /// A seed that has been through the verifiable delay function.
    ///
    /// The only form a production chain may use.
    #[must_use]
    pub const fn from_delay_function(output: Hash) -> Self {
        Self { value: output, delayed: true }
    }

    /// A seed that has **not** been through the delay function.
    ///
    /// The last proposer of an epoch keeps one bit of influence per position it
    /// controls, which is exactly the grinding A4 describes. Usable on a test
    /// network; [`EpochSeed::is_delayed`] is how a node refuses it elsewhere.
    ///
    /// Named at length on purpose. A function called `new` that quietly did
    /// this is how a test-network shortcut reaches a chain holding real money.
    #[must_use]
    pub const fn without_delay_function(mixed: Hash) -> Self {
        Self { value: mixed, delayed: false }
    }

    /// A seed from a delay proof, checked by sampling against `challenge`.
    ///
    /// The challenge must not be chosen by whoever produced the proof —
    /// otherwise it picks one that samples only the segments it computed
    /// honestly. In the protocol it comes from the block that publishes the
    /// proof.
    ///
    /// The resulting seed reports [`EpochSeed::is_delayed`] as true, because
    /// the delay really was performed to within the sampling bound. That bound
    /// is written out in [`crate::vdf`] and is weaker than a STARK's; a node
    /// that wants certainty calls
    /// [`crate::vdf::DelayProof::check_fully`] and pays the delay itself.
    pub fn from_checked_proof(
        mixed: &Hash,
        proof: &crate::vdf::DelayProof,
        challenge: &Hash,
        samples: u32,
    ) -> Result<Self, crate::vdf::DelayError> {
        proof.check_sampled(mixed, challenge, samples)?;
        Ok(Self { value: proof.output(), delayed: true })
    }

    /// The seed value.
    #[must_use]
    pub const fn value(&self) -> Hash {
        self.value
    }

    /// Whether this seed went through the delay function.
    #[must_use]
    pub const fn is_delayed(&self) -> bool {
        self.delayed
    }

    /// Derives a 32-byte draw value from this seed and a counter.
    ///
    /// Its own domain, so that a seed can never be presented as a draw value or
    /// the reverse — both are 32 bytes derived from the same input, which is
    /// the situation domain separation exists for.
    #[must_use]
    pub fn draw(&self, label: &[u8], counter: u64) -> Hash {
        Hasher::new(domain::COMMITTEE_DRAW)
            .update(self.value.as_bytes())
            .update(label)
            .update(&counter.to_be_bytes())
            .finalize()
    }

    /// The first 16 bytes of a draw value, as a big-endian `u128`.
    ///
    /// Used to pick a point in the cumulative weight. The reduction modulo a
    /// total below 2⁶⁴ leaves a bias under 2⁻⁶⁴, which is accepted rather than
    /// corrected: rejection sampling would make the number of hashes depend on
    /// the draw, and a variable-time consensus rule is a worse problem than a
    /// bias nobody can observe.
    #[must_use]
    pub fn draw_u128(&self, label: &[u8], counter: u64) -> u128 {
        let digest = self.draw(label, counter);
        let head: [u8; 16] = match digest.as_bytes().get(..16).and_then(|s| s.try_into().ok()) {
            Some(bytes) => bytes,
            // Unreachable: a digest is 32 bytes. Falling back to zero keeps the
            // function total without a panic in consensus code.
            None => [0_u8; 16],
        };
        u128::from_be_bytes(head)
    }
}

#[cfg(test)]
mod tests {
    use super::{mix_reveals, EpochSeed};
    use std::collections::{BTreeMap, BTreeSet};
    use vanargand_crypto::hash::Hash;
    use vanargand_types::id::AccountId;

    fn account(byte: u8) -> AccountId {
        AccountId::from_hash(Hash::from_bytes([byte; 32]))
    }

    fn reveal(byte: u8) -> Hash {
        Hash::from_bytes([byte.wrapping_mul(3); 32])
    }

    fn reveals(bytes: &[u8]) -> BTreeMap<AccountId, Hash> {
        bytes.iter().map(|byte| (account(*byte), reveal(*byte))).collect()
    }

    #[test]
    fn mixing_does_not_depend_on_insertion_order() {
        // The property that keeps two nodes agreeing: reveals arrive in
        // different orders on different machines, and the seed must not notice.
        let forwards = reveals(&[1, 2, 3, 4]);
        let mut backwards = BTreeMap::new();
        for byte in [4_u8, 3, 2, 1] {
            backwards.insert(account(byte), reveal(byte));
        }
        assert_eq!(mix_reveals(7, &forwards), mix_reveals(7, &backwards));
    }

    #[test]
    fn every_reveal_changes_the_seed() {
        let base = mix_reveals(7, &reveals(&[1, 2, 3]));
        assert_ne!(base, mix_reveals(7, &reveals(&[1, 2, 4])));
        assert_ne!(base, mix_reveals(7, &reveals(&[1, 2])));
        assert_ne!(base, mix_reveals(7, &reveals(&[1, 2, 3, 4])));
    }

    #[test]
    fn the_epoch_number_is_folded_in() {
        // Two epochs with coincidentally identical reveals must not share a
        // seed, or a committee repeats without anybody choosing it.
        let set = reveals(&[1, 2, 3]);
        assert_ne!(mix_reveals(7, &set), mix_reveals(8, &set));
    }

    #[test]
    fn an_empty_epoch_still_produces_a_seed() {
        // Degenerate but reachable: an epoch in which nobody proposed. It must
        // not panic, and it must still differ from its neighbours.
        let empty = BTreeMap::new();
        assert_ne!(mix_reveals(1, &empty), mix_reveals(2, &empty));
    }

    #[test]
    fn a_seed_without_the_delay_function_says_so() {
        // The one thing standing between a test-network shortcut and a chain
        // holding real money.
        let mixed = mix_reveals(1, &reveals(&[1]));
        assert!(!EpochSeed::without_delay_function(mixed).is_delayed());
        assert!(EpochSeed::from_delay_function(mixed).is_delayed());
        // Both carry the same value; only the label differs.
        assert_eq!(
            EpochSeed::without_delay_function(mixed).value(),
            EpochSeed::from_delay_function(mixed).value()
        );
    }

    #[test]
    fn draws_are_distinct_across_labels_and_counters() {
        let seed = EpochSeed::from_delay_function(mix_reveals(1, &reveals(&[1, 2])));
        let mut seen = BTreeSet::new();
        for counter in 0..64_u64 {
            assert!(seen.insert(seed.draw(b"", counter)), "draw repeated at {counter}");
            assert!(seen.insert(seed.draw(b"activate", counter)), "label collision at {counter}");
        }
    }

    #[test]
    fn two_seeds_produce_unrelated_draws() {
        let first = EpochSeed::from_delay_function(mix_reveals(1, &reveals(&[1])));
        let second = EpochSeed::from_delay_function(mix_reveals(2, &reveals(&[1])));
        assert_ne!(first.draw(b"", 0), second.draw(b"", 0));
        assert_ne!(first.draw_u128(b"", 0), second.draw_u128(b"", 0));
    }

    #[test]
    fn draw_u128_reads_the_leading_bytes_big_endian() {
        let seed = EpochSeed::from_delay_function(Hash::from_bytes([0; 32]));
        let digest = seed.draw(b"x", 3);
        let expected = u128::from_be_bytes(
            digest.as_bytes()[..16].try_into().expect("a digest is 32 bytes"),
        );
        assert_eq!(seed.draw_u128(b"x", 3), expected);
    }
}
