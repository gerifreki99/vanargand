// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The inactivity leak.
//!
//! When rung-2 finality cannot be reached because too many members are
//! unreachable, the chain does not stop. It drops to rung 1 and the *effective*
//! weight of silent members decays, until those present are again above two
//! thirds of what remains and finality resumes with no one intervening.
//!
//! # It is a liveness mechanism, not a punishment
//!
//! This is the distinction the whole module turns on, and R2 corrected the
//! Proof of Service FAQ specifically to get it right — the earlier text
//! promised a re-draw, which would have required the finality that had just
//! been lost.
//!
//! Being unreachable is the normal condition this protocol was built for. So:
//!
//! - the decay is **graduated**, and the order matters: the service score
//!   first, then rewards, and the bond itself only after weeks. Only the
//!   effective-weight decay lives here; the reward and bond schedules belong to
//!   emission.
//! - a member that signs again **resets immediately**. Recovery is not
//!   proportional to the outage.
//! - nothing here is ever slashed. Slashing is for equivocation, which carries
//!   its own proof; absence is not attributable, and R2's first acknowledged
//!   error was punishing it.
//!
//! The point is to restore liveness without ruining the minority side of a
//! partition at the very moment it reconnects.

use std::collections::{BTreeMap, BTreeSet};

use vanargand_types::block::params::EPOCH_BLOCKS;
use vanargand_types::id::AccountId;

use crate::committee::{Committee, CommitteeMember};
use crate::weight::Weight;

/// Missed blocks tolerated before any decay begins.
///
/// Two epochs, about two hours. Long enough that an ordinary restart, a
/// software update or a brief outage costs nothing at all.
pub const LEAK_GRACE_BLOCKS: u64 = 2 * EPOCH_BLOCKS;

/// Blocks over which a silent member's weight decays from full to zero, once
/// the grace period has passed.
///
/// Twelve epochs, about half a day. Long enough that a real partition is not
/// punished for being brief; short enough that a chain can recover finality
/// within a working day.
pub const LEAK_PERIOD_BLOCKS: u64 = 12 * EPOCH_BLOCKS;

/// How long each member has been silent.
///
/// A `BTreeMap`, like everything that feeds consensus: this structure decides
/// the denominator of the finality test, and a randomised iteration order would
/// diverge honest nodes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeakState {
    missed: BTreeMap<AccountId, u64>,
}

impl LeakState {
    /// Nobody has missed anything.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one provisional block: who was on duty, and who signed.
    ///
    /// Call this **only for blocks that failed to reach rung 2**. The leak
    /// exists to unblock a chain that cannot finalise; running it while
    /// finality is healthy would penalise members who were simply not needed.
    pub fn observe(&mut self, on_duty: &[CommitteeMember], signers: &BTreeSet<AccountId>) {
        for member in on_duty {
            if signers.contains(&member.account) {
                self.missed.remove(&member.account);
            } else {
                let counter = self.missed.entry(member.account).or_insert(0);
                *counter = counter.saturating_add(1);
            }
        }
    }

    /// Clears a member's counter.
    ///
    /// Recovery is immediate and total, never proportional to the outage.
    pub fn reset(&mut self, account: &AccountId) {
        self.missed.remove(account);
    }

    /// Clears every counter. Called when the chain regains rung-2 finality.
    pub fn clear(&mut self) {
        self.missed.clear();
    }

    /// How many consecutive blocks a member has missed.
    #[must_use]
    pub fn missed(&self, account: &AccountId) -> u64 {
        self.missed.get(account).copied().unwrap_or(0)
    }

    /// The fraction of its weight a member still counts for, as
    /// `(numerator, denominator)`.
    ///
    /// Linear rather than geometric, because linear is exact in integers and
    /// geometric is not.
    #[must_use]
    pub fn remaining_fraction(&self, account: &AccountId) -> (u64, u64) {
        let beyond_grace = self.missed(account).saturating_sub(LEAK_GRACE_BLOCKS);
        let remaining = LEAK_PERIOD_BLOCKS.saturating_sub(beyond_grace);
        (remaining, LEAK_PERIOD_BLOCKS)
    }

    /// A member's effective weight after decay.
    #[must_use]
    pub fn effective_weight(&self, account: &AccountId, weight: Weight) -> Weight {
        let (numerator, denominator) = self.remaining_fraction(account);
        weight.scaled(numerator, denominator)
    }

    /// The effective weight on duty at a block, which is the denominator of the
    /// two-thirds test while the leak is running.
    #[must_use]
    pub fn effective_active_weight(&self, committee: &Committee, block_in_epoch: u64) -> Weight {
        Weight::checked_sum(
            committee
                .active_at(block_in_epoch)
                .into_iter()
                .map(|member| self.effective_weight(&member.account, member.weight)),
        )
        .unwrap_or(Weight::ZERO)
    }

    /// The effective weight of a set of signers on duty at a block.
    #[must_use]
    pub fn effective_signed_weight(
        &self,
        committee: &Committee,
        block_in_epoch: u64,
        signers: &BTreeSet<AccountId>,
    ) -> Weight {
        Weight::checked_sum(
            committee
                .active_at(block_in_epoch)
                .into_iter()
                .filter(|member| signers.contains(&member.account))
                .map(|member| self.effective_weight(&member.account, member.weight)),
        )
        .unwrap_or(Weight::ZERO)
    }

    /// Whether the present signers now carry more than two thirds of the
    /// remaining effective weight.
    ///
    /// This is the question the leak exists to turn from "no" into "yes"
    /// without anybody doing anything.
    #[must_use]
    pub fn restores_finality(
        &self,
        committee: &Committee,
        block_in_epoch: u64,
        signers: &BTreeSet<AccountId>,
    ) -> bool {
        let signed = self.effective_signed_weight(committee, block_in_epoch, signers);
        let total = self.effective_active_weight(committee, block_in_epoch);
        signed.exceeds_two_thirds_of(total)
    }

    /// How many members are being leaked against.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.missed.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{LeakState, LEAK_GRACE_BLOCKS, LEAK_PERIOD_BLOCKS};
    use crate::committee::{Committee, CommitteeMember};
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

    fn committee_of(count: u32) -> Committee {
        let mut set = ValidatorSet::new();
        for index in 0..count {
            set.insert(ValidatorRecord::new(
                account(index),
                key(index),
                Amount::from_ulf(1_000),
                Hash::from_bytes([0xcc; 32]),
            ));
        }
        let mut reveals = BTreeMap::new();
        reveals.insert(account(0), Hash::from_bytes([1; 32]));
        Committee::draw(&set, &EpochSeed::from_delay_function(mix_reveals(1, &reveals)))
    }

    fn member(index: u32) -> CommitteeMember {
        CommitteeMember { account: account(index), weight: Weight::from_raw(1_000) }
    }

    #[test]
    fn silence_within_the_grace_period_costs_nothing() {
        // An ordinary restart, a software update, a brief outage.
        let mut leak = LeakState::new();
        let on_duty = [member(0), member(1)];
        let silent = BTreeSet::new();

        for _ in 0..LEAK_GRACE_BLOCKS {
            leak.observe(&on_duty, &silent);
        }
        assert_eq!(leak.missed(&account(0)), LEAK_GRACE_BLOCKS);
        assert_eq!(
            leak.effective_weight(&account(0), Weight::from_raw(1_000)),
            Weight::from_raw(1_000),
            "weight decayed inside the grace period"
        );
    }

    #[test]
    fn weight_decays_linearly_after_the_grace_period() {
        let mut leak = LeakState::new();
        let on_duty = [member(0)];
        let silent = BTreeSet::new();

        let halfway = LEAK_GRACE_BLOCKS + LEAK_PERIOD_BLOCKS / 2;
        for _ in 0..halfway {
            leak.observe(&on_duty, &silent);
        }
        let effective = leak.effective_weight(&account(0), Weight::from_raw(1_000));
        assert_eq!(effective, Weight::from_raw(500), "half the period should halve the weight");
    }

    #[test]
    fn weight_reaches_zero_and_stops_there() {
        let mut leak = LeakState::new();
        let on_duty = [member(0)];
        let silent = BTreeSet::new();

        for _ in 0..(LEAK_GRACE_BLOCKS + LEAK_PERIOD_BLOCKS) {
            leak.observe(&on_duty, &silent);
        }
        assert_eq!(leak.effective_weight(&account(0), Weight::from_raw(1_000)), Weight::ZERO);

        // And it does not go negative, wrap, or come back.
        for _ in 0..1_000 {
            leak.observe(&on_duty, &silent);
        }
        assert_eq!(leak.effective_weight(&account(0), Weight::from_raw(1_000)), Weight::ZERO);
    }

    #[test]
    fn signing_again_resets_immediately() {
        // Recovery is not proportional to the outage. Being unreachable is the
        // normal condition this protocol was built for.
        let mut leak = LeakState::new();
        let on_duty = [member(0)];
        let silent = BTreeSet::new();
        let present: BTreeSet<AccountId> = [account(0)].into_iter().collect();

        for _ in 0..(LEAK_GRACE_BLOCKS + LEAK_PERIOD_BLOCKS / 2) {
            leak.observe(&on_duty, &silent);
        }
        assert!(leak.missed(&account(0)) > 0);

        leak.observe(&on_duty, &present);
        assert_eq!(leak.missed(&account(0)), 0);
        assert_eq!(
            leak.effective_weight(&account(0), Weight::from_raw(1_000)),
            Weight::from_raw(1_000)
        );
        assert_eq!(leak.tracked(), 0);
    }

    #[test]
    fn a_present_member_is_never_penalised_for_an_absent_one() {
        let mut leak = LeakState::new();
        let on_duty = [member(0), member(1)];
        let only_zero: BTreeSet<AccountId> = [account(0)].into_iter().collect();

        for _ in 0..(LEAK_GRACE_BLOCKS + LEAK_PERIOD_BLOCKS) {
            leak.observe(&on_duty, &only_zero);
        }
        assert_eq!(
            leak.effective_weight(&account(0), Weight::from_raw(1_000)),
            Weight::from_raw(1_000)
        );
        assert_eq!(leak.effective_weight(&account(1), Weight::from_raw(1_000)), Weight::ZERO);
    }

    #[test]
    fn the_leak_restores_finality_without_anyone_intervening() {
        // The scenario the mechanism exists for. Half the committee vanishes,
        // so the present half cannot reach two thirds and the chain drops to
        // rung 1. Nobody does anything. After the leak runs, the present half
        // is above two thirds of what remains and finality resumes.
        let committee = committee_of(100);
        let on_duty = committee.active_at(0);
        let half = on_duty.len() / 2;
        let present: BTreeSet<AccountId> =
            on_duty.iter().take(half).map(|member| member.account).collect();

        let mut leak = LeakState::new();
        assert!(
            !leak.restores_finality(&committee, 0, &present),
            "half the committee should not be able to finalise on its own"
        );

        for _ in 0..(LEAK_GRACE_BLOCKS + LEAK_PERIOD_BLOCKS) {
            leak.observe(&on_duty, &present);
        }

        assert!(
            leak.restores_finality(&committee, 0, &present),
            "the leak did not restore finality to the present members"
        );
    }

    #[test]
    fn the_leak_does_not_restore_finality_prematurely() {
        // Safety in the other direction: while the absent members still carry
        // weight, the present minority must not be able to finalise.
        let committee = committee_of(100);
        let on_duty = committee.active_at(0);
        let third = on_duty.len() / 3;
        let present: BTreeSet<AccountId> =
            on_duty.iter().take(third).map(|member| member.account).collect();

        let mut leak = LeakState::new();
        for _ in 0..LEAK_GRACE_BLOCKS {
            leak.observe(&on_duty, &present);
        }
        assert!(
            !leak.restores_finality(&committee, 0, &present),
            "a third of the committee finalised while the rest still counted"
        );
    }

    #[test]
    fn nobody_present_never_finalises() {
        // The degenerate end of the decay: if everyone is silent, the effective
        // total reaches zero, and zero must not be "more than two thirds of
        // zero". Otherwise a dead chain would declare itself final.
        let committee = committee_of(100);
        let on_duty = committee.active_at(0);
        let nobody = BTreeSet::new();

        let mut leak = LeakState::new();
        for _ in 0..(LEAK_GRACE_BLOCKS + LEAK_PERIOD_BLOCKS) {
            leak.observe(&on_duty, &nobody);
        }
        assert_eq!(leak.effective_active_weight(&committee, 0), Weight::ZERO);
        assert!(
            !leak.restores_finality(&committee, 0, &nobody),
            "an empty chain declared itself final"
        );
    }

    #[test]
    fn clearing_returns_everyone_to_full_weight() {
        let committee = committee_of(100);
        let on_duty = committee.active_at(0);
        let nobody = BTreeSet::new();

        let mut leak = LeakState::new();
        for _ in 0..(LEAK_GRACE_BLOCKS + LEAK_PERIOD_BLOCKS / 2) {
            leak.observe(&on_duty, &nobody);
        }
        let decayed = leak.effective_active_weight(&committee, 0);
        leak.clear();
        assert!(leak.effective_active_weight(&committee, 0) > decayed);
        assert_eq!(leak.effective_active_weight(&committee, 0), committee.active_weight_at(0));
    }

    #[test]
    fn an_untracked_member_counts_in_full() {
        let leak = LeakState::new();
        assert_eq!(leak.missed(&account(42)), 0);
        assert_eq!(leak.remaining_fraction(&account(42)), (LEAK_PERIOD_BLOCKS, LEAK_PERIOD_BLOCKS));
        assert_eq!(
            leak.effective_weight(&account(42), Weight::from_raw(7)),
            Weight::from_raw(7)
        );
    }
}
