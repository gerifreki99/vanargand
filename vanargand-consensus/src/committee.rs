// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Drawing a committee, and deciding who is on duty.
//!
//! Implements `spec/draft/07-consensus.md` §4, which is normative in the
//! strongest sense the specification has: two implementations that differ here
//! draw different committees, and the chain splits. Everything in this module
//! is integer arithmetic over a sorted sequence, for that reason.

use vanargand_types::id::AccountId;

use crate::seed::EpochSeed;
use crate::validator::ValidatorSet;
use crate::weight::Weight;

/// How many members are drawn per epoch.
///
/// Three times the active count (R1). The oversampling is real; what it buys is
/// not unpredictability — see [`Committee::active_at`].
pub const SAMPLED: usize = 192;

/// How many of the sampled members are on duty at any one block.
pub const ACTIVE: usize = 64;

/// A drawn committee member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitteeMember {
    /// Whose seat this is.
    pub account: AccountId,
    /// The weight it carries, frozen at the moment of the draw.
    ///
    /// Frozen on purpose: a validator that tops up its bond mid-epoch does not
    /// gain voting power mid-epoch, and one that is slashed does not silently
    /// change the threshold every other node is computing against.
    pub weight: Weight,
}

/// A committee for one epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Committee {
    members: Vec<CommitteeMember>,
    /// Activation order: a permutation of `0..members.len()`.
    permutation: Vec<u16>,
    total_weight: Weight,
}

impl Committee {
    /// Draws a committee from the eligible candidates.
    ///
    /// Weighted, without replacement, deterministic. The algorithm is spelled
    /// out in the specification; the two properties that matter are that it
    /// walks the candidates in ascending account order — not in weight order,
    /// not in arrival order — and that a chosen candidate is **removed**, so
    /// that a validator holding forty per cent of the weight occupies one seat
    /// rather than forty per cent of them.
    #[must_use]
    pub fn draw(set: &ValidatorSet, seed: &EpochSeed) -> Self {
        let mut candidates: Vec<CommitteeMember> = set
            .eligible()
            .map(|record| CommitteeMember { account: record.account, weight: record.weight() })
            .collect();

        let mut remaining_weight = Weight::checked_sum(
            candidates.iter().map(|candidate| candidate.weight),
        )
        .unwrap_or(Weight::ZERO);

        let seats = SAMPLED.min(candidates.len());
        let mut members: Vec<CommitteeMember> = Vec::with_capacity(seats);

        let mut round: u64 = 0;
        while members.len() < seats && !candidates.is_empty() && !remaining_weight.is_zero() {
            let point = seed.draw_u128(b"draw", round) % remaining_weight.raw();
            let chosen = pick_by_cumulative_weight(&candidates, point);
            let Some(index) = chosen else { break };
            let Some(member) = candidates.get(index).copied() else { break };
            candidates.remove(index);
            remaining_weight = remaining_weight.checked_sub(member.weight).unwrap_or(Weight::ZERO);
            members.push(member);
            round = round.saturating_add(1);
        }

        let permutation = activation_permutation(members.len(), seed);
        let total_weight =
            Weight::checked_sum(members.iter().map(|member| member.weight)).unwrap_or(Weight::ZERO);

        Self { members, permutation, total_weight }
    }

    /// The drawn members, in draw order.
    #[must_use]
    pub fn members(&self) -> &[CommitteeMember] {
        &self.members
    }

    /// How many members were drawn.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether nobody was drawn.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The total weight of the whole committee.
    #[must_use]
    pub fn total_weight(&self) -> Weight {
        self.total_weight
    }

    /// Whether an account holds a seat.
    #[must_use]
    pub fn contains(&self, account: &AccountId) -> bool {
        self.members.iter().any(|member| member.account == *account)
    }

    /// An account's weight in this committee.
    #[must_use]
    pub fn weight_of(&self, account: &AccountId) -> Option<Weight> {
        self.members
            .iter()
            .find(|member| member.account == *account)
            .map(|member| member.weight)
    }

    /// The members on duty at block `block_in_epoch`.
    ///
    /// A sliding window of [`ACTIVE`] over the activation permutation, moving
    /// one place per block.
    ///
    /// # This schedule is known in advance, and says so
    ///
    /// The permutation is derived from the epoch seed, which is fixed when the
    /// epoch opens — so the whole hour's duty roster is computable an hour
    /// ahead. R2 requires that to be stated rather than dressed up: what
    /// protects a validator from being targeted is not an unpredictability it
    /// does not have, it is the sentinel architecture, rotating relays in front
    /// of the validator so that knowing an identity does not give an address.
    #[must_use]
    pub fn active_at(&self, block_in_epoch: u64) -> Vec<CommitteeMember> {
        let size = self.members.len();
        if size == 0 {
            return Vec::new();
        }
        let Ok(size_u64) = u64::try_from(size) else { return Vec::new() };
        let Ok(offset) = usize::try_from(block_in_epoch % size_u64) else { return Vec::new() };

        let count = ACTIVE.min(size);
        let mut active = Vec::with_capacity(count);
        for step in 0..count {
            let position = offset.saturating_add(step) % size;
            let Some(&index) = self.permutation.get(position) else { continue };
            let Ok(index) = usize::try_from(index) else { continue };
            if let Some(member) = self.members.get(index) {
                active.push(*member);
            }
        }
        active
    }

    /// The total weight on duty at a block.
    #[must_use]
    pub fn active_weight_at(&self, block_in_epoch: u64) -> Weight {
        Weight::checked_sum(self.active_at(block_in_epoch).into_iter().map(|member| member.weight))
            .unwrap_or(Weight::ZERO)
    }

    /// Whether an account is on duty at a block.
    #[must_use]
    pub fn is_active_at(&self, account: &AccountId, block_in_epoch: u64) -> bool {
        self.active_at(block_in_epoch).iter().any(|member| member.account == *account)
    }
}

/// Finds the candidate whose cumulative weight first exceeds `point`.
fn pick_by_cumulative_weight(candidates: &[CommitteeMember], point: u128) -> Option<usize> {
    let mut cumulative: u128 = 0;
    for (index, candidate) in candidates.iter().enumerate() {
        cumulative = cumulative.saturating_add(candidate.weight.raw());
        if cumulative > point {
            return Some(index);
        }
    }
    // Only reachable if `point` was drawn against a stale total. Falling back
    // to the last candidate keeps the draw total rather than silently returning
    // a short committee.
    candidates.len().checked_sub(1)
}

/// Fisher–Yates over `0..size`, driven by the seed.
fn activation_permutation(size: usize, seed: &EpochSeed) -> Vec<u16> {
    let mut order: Vec<u16> = (0..size).filter_map(|index| u16::try_from(index).ok()).collect();
    if order.len() < 2 {
        return order;
    }
    let mut index = order.len().saturating_sub(1);
    while index >= 1 {
        let span = u128::try_from(index).unwrap_or(0).saturating_add(1);
        let counter = u64::try_from(index).unwrap_or(0);
        let target = usize::try_from(seed.draw_u128(b"activate", counter) % span).unwrap_or(0);
        order.swap(index, target);
        index = index.saturating_sub(1);
    }
    order
}

#[cfg(test)]
mod tests {
    use super::{Committee, ACTIVE, SAMPLED};
    use crate::seed::{mix_reveals, EpochSeed};
    use crate::validator::{ValidatorRecord, ValidatorSet};
    use crate::weight::Weight;
    use std::collections::{BTreeMap, BTreeSet};
    use vanargand_crypto::algorithm::AlgorithmId;
    use vanargand_crypto::hash::Hash;
    use vanargand_crypto::sign::VerifyingKey;
    use vanargand_types::id::AccountId;
    use vanargand_types::Amount;

    fn account(index: u32) -> AccountId {
        let mut bytes = [0_u8; 32];
        bytes[..4].copy_from_slice(&index.to_be_bytes());
        AccountId::from_hash(Hash::from_bytes(bytes))
    }

    fn key(index: u32) -> VerifyingKey {
        let mut bytes = vec![0_u8; 32];
        bytes[..4].copy_from_slice(&index.to_be_bytes());
        VerifyingKey::new(AlgorithmId::InsecureTest, bytes).expect("32-byte test key")
    }

    /// A set of `count` candidates, each bonding `bond` ulf.
    fn uniform_set(count: u32, bond: u64) -> ValidatorSet {
        let mut set = ValidatorSet::new();
        for index in 0..count {
            set.insert(ValidatorRecord::new(
                account(index),
                key(index),
                Amount::from_ulf(bond),
                Hash::from_bytes([0xcc; 32]),
            ));
        }
        set
    }

    fn seed(epoch: u64) -> EpochSeed {
        let mut reveals = BTreeMap::new();
        reveals.insert(account(0), Hash::from_bytes([1; 32]));
        reveals.insert(account(1), Hash::from_bytes([2; 32]));
        EpochSeed::from_delay_function(mix_reveals(epoch, &reveals))
    }

    #[test]
    fn the_draw_is_deterministic() {
        // The property the whole module exists for.
        let set = uniform_set(300, 1_000);
        let first = Committee::draw(&set, &seed(1));
        let second = Committee::draw(&set, &seed(1));
        assert_eq!(first, second);
    }

    #[test]
    fn a_different_seed_gives_a_different_committee() {
        let set = uniform_set(300, 1_000);
        let first = Committee::draw(&set, &seed(1));
        let second = Committee::draw(&set, &seed(2));
        assert_ne!(
            first.members().iter().map(|m| m.account).collect::<Vec<_>>(),
            second.members().iter().map(|m| m.account).collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_committee_is_capped_at_the_sample_size() {
        let set = uniform_set(500, 1_000);
        let committee = Committee::draw(&set, &seed(1));
        assert_eq!(committee.len(), SAMPLED);
    }

    #[test]
    fn a_small_network_draws_everyone_and_no_one_twice() {
        // Sampling without replacement, checked where it is easiest to see.
        let set = uniform_set(10, 1_000);
        let committee = Committee::draw(&set, &seed(1));
        assert_eq!(committee.len(), 10);
        let unique: BTreeSet<AccountId> =
            committee.members().iter().map(|m| m.account).collect();
        assert_eq!(unique.len(), 10, "a candidate was drawn twice");
    }

    #[test]
    fn no_member_is_drawn_twice_in_a_large_draw() {
        let set = uniform_set(400, 1_000);
        let committee = Committee::draw(&set, &seed(3));
        let unique: BTreeSet<AccountId> =
            committee.members().iter().map(|m| m.account).collect();
        assert_eq!(unique.len(), committee.len(), "a candidate was drawn twice");
    }

    #[test]
    fn a_dominant_holder_occupies_one_seat_not_forty_per_cent_of_them() {
        // The reason the draw is without replacement. With replacement, a
        // validator holding 40% of the weight would take roughly 77 of 192
        // seats and own the committee outright.
        let mut set = ValidatorSet::new();
        set.insert(ValidatorRecord::new(
            account(0),
            key(0),
            Amount::from_ulf(400_000),
            Hash::from_bytes([1; 32]),
        ));
        for index in 1..300_u32 {
            set.insert(ValidatorRecord::new(
                account(index),
                key(index),
                Amount::from_ulf(2_000),
                Hash::from_bytes([1; 32]),
            ));
        }

        let committee = Committee::draw(&set, &seed(1));
        let seats = committee.members().iter().filter(|m| m.account == account(0)).count();
        assert_eq!(seats, 1, "the whale took {seats} seats");
    }

    #[test]
    fn zero_weight_candidates_are_never_drawn() {
        let mut set = uniform_set(5, 1_000);
        for index in 100..110_u32 {
            set.insert(ValidatorRecord::new(
                account(index),
                key(index),
                Amount::ZERO,
                Hash::from_bytes([1; 32]),
            ));
        }
        let committee = Committee::draw(&set, &seed(1));
        assert_eq!(committee.len(), 5);
        for index in 100..110_u32 {
            assert!(!committee.contains(&account(index)));
        }
    }

    #[test]
    fn an_empty_set_draws_an_empty_committee() {
        // Degenerate and reachable — a chain whose validators have all unbonded.
        // It must not panic.
        let committee = Committee::draw(&ValidatorSet::new(), &seed(1));
        assert!(committee.is_empty());
        assert_eq!(committee.total_weight(), Weight::ZERO);
        assert!(committee.active_at(0).is_empty());
        assert_eq!(committee.active_weight_at(0), Weight::ZERO);
    }

    #[test]
    fn a_single_candidate_is_the_whole_committee() {
        let committee = Committee::draw(&uniform_set(1, 500), &seed(1));
        assert_eq!(committee.len(), 1);
        assert_eq!(committee.active_at(0).len(), 1);
        assert_eq!(committee.active_at(999).len(), 1);
    }

    #[test]
    fn weight_influences_the_draw() {
        // Not a distribution test — a smoke test that weight is used at all,
        // which is the failure mode a refactor actually produces.
        //
        // Ten heavy candidates among a hundred, at a hundred to one. Uniform
        // sampling would put about one of them in each epoch's first ten seats,
        // so about 30 across 30 epochs. Weighted sampling should put nearly all
        // ten there every time.
        let mut set = ValidatorSet::new();
        for index in 0..100_u32 {
            let bond = if index < 10 { 100_000 } else { 1_000 };
            set.insert(ValidatorRecord::new(
                account(index),
                key(index),
                Amount::from_ulf(bond),
                Hash::from_bytes([1; 32]),
            ));
        }

        let epochs = 30_u64;
        let mut heavy_seats = 0_usize;
        for epoch in 0..epochs {
            let committee = Committee::draw(&set, &seed(epoch));
            heavy_seats += committee
                .members()
                .iter()
                .take(10)
                .filter(|member| member.weight > Weight::from_raw(50_000))
                .count();
        }

        assert!(
            heavy_seats > 150,
            "weight appears not to influence the draw: {heavy_seats} heavy seats in {} \
             (uniform sampling would give about 30)",
            epochs.saturating_mul(10)
        );
    }

    #[test]
    fn the_active_window_has_the_right_size() {
        let committee = Committee::draw(&uniform_set(300, 1_000), &seed(1));
        for block in [0_u64, 1, 63, 64, 191, 192, 719] {
            assert_eq!(committee.active_at(block).len(), ACTIVE, "at block {block}");
        }
    }

    #[test]
    fn the_active_window_holds_no_duplicates() {
        let committee = Committee::draw(&uniform_set(300, 1_000), &seed(1));
        for block in 0..200_u64 {
            let active = committee.active_at(block);
            let unique: BTreeSet<AccountId> = active.iter().map(|m| m.account).collect();
            assert_eq!(unique.len(), active.len(), "duplicate on duty at block {block}");
        }
    }

    #[test]
    fn every_member_serves_within_one_committee_length() {
        // The bug the stride change fixed: with a stride that shares a factor
        // with the committee size, a member can sit out the entire epoch.
        for size in [1_u32, 2, 5, 64, 65, 100, 192, 300] {
            let committee = Committee::draw(&uniform_set(size, 1_000), &seed(1));
            let length = committee.len();
            let laps = u64::try_from(length).expect("a committee is at most 192");
            let mut served: BTreeSet<AccountId> = BTreeSet::new();
            for block in 0..laps {
                for member in committee.active_at(block) {
                    served.insert(member.account);
                }
            }
            assert_eq!(
                served.len(),
                length,
                "with {size} candidates, {} of {length} members never served",
                length - served.len()
            );
        }
    }

    #[test]
    fn the_window_slides_by_one_and_wraps() {
        let committee = Committee::draw(&uniform_set(300, 1_000), &seed(1));
        let size = u64::try_from(committee.len()).expect("a committee is at most 192");
        // A full lap returns to the same roster.
        assert_eq!(committee.active_at(0), committee.active_at(size));
        // And consecutive blocks differ by exactly one member at each end.
        let first: BTreeSet<AccountId> =
            committee.active_at(0).iter().map(|m| m.account).collect();
        let second: BTreeSet<AccountId> =
            committee.active_at(1).iter().map(|m| m.account).collect();
        assert_eq!(first.difference(&second).count(), 1);
        assert_eq!(second.difference(&first).count(), 1);
    }

    #[test]
    fn the_activation_schedule_is_deterministic_and_seed_dependent() {
        let set = uniform_set(300, 1_000);
        let first = Committee::draw(&set, &seed(1));
        let again = Committee::draw(&set, &seed(1));
        assert_eq!(first.active_at(5), again.active_at(5));

        let other = Committee::draw(&set, &seed(2));
        assert_ne!(first.active_at(5), other.active_at(5));
    }

    #[test]
    fn active_weight_is_the_sum_of_the_roster() {
        let committee = Committee::draw(&uniform_set(300, 1_000), &seed(1));
        let roster = committee.active_at(7);
        let expected =
            Weight::checked_sum(roster.iter().map(|m| m.weight)).expect("no overflow");
        assert_eq!(committee.active_weight_at(7), expected);
        assert!(committee.active_weight_at(7) < committee.total_weight());
    }

    #[test]
    fn membership_queries_agree_with_the_roster() {
        let committee = Committee::draw(&uniform_set(300, 1_000), &seed(1));
        let roster = committee.active_at(3);
        for member in &roster {
            assert!(committee.is_active_at(&member.account, 3));
            assert!(committee.contains(&member.account));
            assert_eq!(committee.weight_of(&member.account), Some(member.weight));
        }
        assert!(!committee.contains(&account(9_999)));
        assert_eq!(committee.weight_of(&account(9_999)), None);
    }
}
