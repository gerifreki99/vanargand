// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validator candidates and the set of them.
//!
//! Anyone may become a candidate: lock a bond, seal a commitment chain, run a
//! small computer. No special hardware, no permission. The bond is a promise
//! made seizable, and the commitment chain is what makes the epoch randomness
//! unchooseable (A4).

use std::collections::BTreeMap;

use vanargand_crypto::hash::Hash;
use vanargand_crypto::sign::VerifyingKey;
use vanargand_types::codec::{CodecError, Decode, Decoder, Encode, Encoder};
use vanargand_types::id::AccountId;
use vanargand_types::Amount;

use crate::weight::{Multiplier, Weight};

/// A validator candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorRecord {
    /// The candidate's account.
    pub account: AccountId,
    /// The key that signs its blocks and votes.
    ///
    /// A device subkey of the account, not the account root: the root signs as
    /// rarely as possible, and a validator key lives in a process that is
    /// online by definition.
    pub key: VerifyingKey,
    /// The locked bond.
    pub bond: Amount,
    /// The service multiplier. Frozen at ×1.0 for phase 1.
    pub multiplier: Multiplier,
    /// Root of the commitment chain sealed when the bond was placed.
    ///
    /// Proposing a block reveals the next link. The proposer can neither choose
    /// it — the chain was fixed before it knew anything about the epoch — nor
    /// withhold it without forfeiting its turn.
    pub commitment_root: Hash,
    /// The last link this validator has revealed, or the root if it has never
    /// proposed.
    pub last_reveal: Hash,
}

impl ValidatorRecord {
    /// A candidate with the launch configuration: multiplier frozen at ×1.0.
    #[must_use]
    pub fn new(
        account: AccountId,
        key: VerifyingKey,
        bond: Amount,
        commitment_root: Hash,
    ) -> Self {
        Self {
            account,
            key,
            bond,
            multiplier: Multiplier::ONE,
            commitment_root,
            last_reveal: commitment_root,
        }
    }

    /// This candidate's consensus weight.
    #[must_use]
    pub fn weight(&self) -> Weight {
        Weight::of(self.bond, self.multiplier)
    }

    /// Whether this candidate may be drawn into a committee.
    ///
    /// A zero bond is not a candidate. Note that this admits the
    /// **self-constituting bond** of R2: a validator starts at zero at genesis
    /// and its rewards are locked as bond until the minimum is reached, so
    /// eligibility is a property that grows rather than a gate to be passed
    /// once.
    #[must_use]
    pub fn is_eligible(&self) -> bool {
        !self.weight().is_zero()
    }
}

impl Encode for ValidatorRecord {
    fn encode(&self, out: &mut Encoder) {
        self.account.encode(out);
        self.key.encode(out);
        self.bond.encode(out);
        self.multiplier.encode(out);
        self.commitment_root.encode(out);
        self.last_reveal.encode(out);
    }
}

impl Decode for ValidatorRecord {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            account: AccountId::decode(input)?,
            key: VerifyingKey::decode(input)?,
            bond: Amount::decode(input)?,
            multiplier: Multiplier::decode(input)?,
            commitment_root: Hash::decode(input)?,
            last_reveal: Hash::decode(input)?,
        })
    }
}

/// The set of validator candidates.
///
/// A `BTreeMap` keyed by account identifier, and the ordering is not a
/// convenience: [`crate::committee`] iterates this set to draw a committee, and
/// two nodes iterating in different orders draw different committees and split
/// the chain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidatorSet {
    entries: BTreeMap<AccountId, ValidatorRecord>,
}

impl ValidatorSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts or replaces a candidate.
    pub fn insert(&mut self, record: ValidatorRecord) {
        self.entries.insert(record.account, record);
    }

    /// Removes a candidate.
    pub fn remove(&mut self, account: &AccountId) -> Option<ValidatorRecord> {
        self.entries.remove(account)
    }

    /// A candidate by account.
    #[must_use]
    pub fn get(&self, account: &AccountId) -> Option<&ValidatorRecord> {
        self.entries.get(account)
    }

    /// A candidate by account, mutably.
    pub fn get_mut(&mut self, account: &AccountId) -> Option<&mut ValidatorRecord> {
        self.entries.get_mut(account)
    }

    /// How many candidates.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every candidate, in ascending account order.
    pub fn iter(&self) -> impl Iterator<Item = &ValidatorRecord> {
        self.entries.values()
    }

    /// Every **eligible** candidate, in ascending account order.
    ///
    /// This is the sequence the committee draw walks, and the order is
    /// consensus.
    pub fn eligible(&self) -> impl Iterator<Item = &ValidatorRecord> {
        self.entries.values().filter(|record| record.is_eligible())
    }

    /// Total weight of the eligible candidates, or `None` on overflow.
    #[must_use]
    pub fn total_eligible_weight(&self) -> Option<Weight> {
        Weight::checked_sum(self.eligible().map(ValidatorRecord::weight))
    }

    /// The security budget: a third of the bonded stake.
    ///
    /// What it actually costs to attack finality, published in every block
    /// header per `docs/05-emission.pdf` §4. A third and not two thirds:
    /// blocking the chain is the cheaper attack, and the cheaper attack is the
    /// one a budget should quote.
    #[must_use]
    pub fn security_budget(&self) -> Option<Amount> {
        let total = Amount::checked_sum(self.iter().map(|record| record.bond))?;
        total.mul_div_floor(1, 3)
    }
}

#[cfg(test)]
mod tests {
    use super::{ValidatorRecord, ValidatorSet};
    use crate::weight::{Multiplier, Weight};
    use vanargand_crypto::algorithm::AlgorithmId;
    use vanargand_crypto::hash::Hash;
    use vanargand_crypto::sign::VerifyingKey;
    use vanargand_types::codec::{Decode, Encode};
    use vanargand_types::id::AccountId;
    use vanargand_types::Amount;

    fn key(byte: u8) -> VerifyingKey {
        VerifyingKey::new(AlgorithmId::InsecureTest, vec![byte; 32])
            .expect("32 bytes is the test algorithm's key length")
    }

    fn account(byte: u8) -> AccountId {
        AccountId::from_hash(Hash::from_bytes([byte; 32]))
    }

    fn candidate(byte: u8, bond: u64) -> ValidatorRecord {
        ValidatorRecord::new(
            account(byte),
            key(byte),
            Amount::from_ulf(bond),
            Hash::from_bytes([byte.wrapping_add(100); 32]),
        )
    }

    #[test]
    fn a_new_candidate_starts_at_the_launch_configuration() {
        let record = candidate(1, 10_000);
        assert_eq!(record.multiplier, Multiplier::ONE, "phase 1 freezes the multiplier at 1");
        assert_eq!(record.last_reveal, record.commitment_root, "nothing revealed yet");
        assert_eq!(record.weight(), Weight::from_raw(10_000));
        assert!(record.is_eligible());
    }

    #[test]
    fn a_zero_bond_is_not_a_candidate() {
        assert!(!candidate(1, 0).is_eligible());
    }

    #[test]
    fn records_round_trip() {
        let mut record = candidate(3, 42);
        record.multiplier = Multiplier::new(1_750);
        record.last_reveal = Hash::from_bytes([0xab; 32]);
        let bytes = record.to_canonical_bytes();
        assert_eq!(ValidatorRecord::from_canonical_bytes(&bytes), Ok(record));
    }

    #[test]
    fn the_set_iterates_in_account_order() {
        // Consensus-critical: the committee draw walks this sequence, and two
        // nodes walking it differently draw different committees.
        let mut set = ValidatorSet::new();
        for byte in [7_u8, 1, 5, 3] {
            set.insert(candidate(byte, 100));
        }
        let observed: Vec<AccountId> = set.iter().map(|record| record.account).collect();
        let mut expected = observed.clone();
        expected.sort_unstable();
        assert_eq!(observed, expected);
    }

    #[test]
    fn eligibility_filters_without_disturbing_the_order() {
        let mut set = ValidatorSet::new();
        set.insert(candidate(1, 100));
        set.insert(candidate(2, 0));
        set.insert(candidate(3, 300));
        let observed: Vec<AccountId> = set.eligible().map(|record| record.account).collect();
        assert_eq!(observed, vec![account(1), account(3)]);
        assert_eq!(set.total_eligible_weight(), Some(Weight::from_raw(400)));
    }

    #[test]
    fn the_security_budget_is_a_third_of_the_bond() {
        let mut set = ValidatorSet::new();
        set.insert(candidate(1, 300));
        set.insert(candidate(2, 300));
        set.insert(candidate(3, 300));
        assert_eq!(set.security_budget(), Some(Amount::from_ulf(300)));
    }

    #[test]
    fn an_empty_set_has_no_weight_and_no_budget() {
        let set = ValidatorSet::new();
        assert!(set.is_empty());
        assert_eq!(set.total_eligible_weight(), Some(Weight::ZERO));
        assert_eq!(set.security_budget(), Some(Amount::ZERO));
    }
}
