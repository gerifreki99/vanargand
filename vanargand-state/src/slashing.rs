// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Punishing equivocation — the one fault Vanargand seizes for.
//!
//! > On ne saisit que les fautes qui portent leur propre preuve.
//!
//! That sentence is R2's, written after withdrawing the R1 penalty for
//! non-revelation, and it is the whole of this module's remit. Unavailability
//! is never punished here: a crash and a deliberate silence are the same
//! observable, and a protocol that claims partition as its normal regime cannot
//! punish being unreachable. Absence costs graduated penalties and score
//! erosion, which live in `vanargand-consensus`.
//!
//! # Two equivocations, one shape
//!
//! **A validator** signs two different blocks at one height. Classical, and
//! resolved by construction since A2.
//!
//! **An account** signs two different transactions on one device's lane at one
//! sequence number. This is R2's extension of the same idea from validators to
//! ordinary people, and it is the design's signature claim: because a nomad
//! spend travels on a single sequenced lane belonging to one device, spending
//! the same offline credit in two partitions **necessarily manufactures the
//! evidence against itself**. It is not detected. It is produced by the act.
//!
//! # The split
//!
//! `docs/05-emission.pdf`: *"Une moitié prime le dénonciateur ou finance la
//! réparation, l'autre moitié part au feu."* Half to whoever published the
//! proof, half destroyed, with the rounding remainder going to the fire — the
//! same convention as a fee, and for the same reason: the fire is the only
//! destination with no incentive to steer amounts towards itself.
//!
//! Paying the denouncer is not decoration. A proof nobody is paid to publish is
//! a proof nobody publishes, and every contestation window in the protocol
//! assumes somebody is watching.

use std::collections::BTreeSet;

use core::fmt;

use vanargand_crypto::hash::{domain, Hash, Hasher};
use vanargand_types::codec::{CodecError, Decode, Decoder, Encode, Encoder};
use vanargand_types::id::{AccountId, DeviceId};
use vanargand_types::nonce::Lane;
use vanargand_types::Amount;

/// The slot an account equivocated in.
///
/// Identifies the offence, not the offender: two different evidences about the
/// same slot describe one crime and earn one bounty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccountOffence {
    /// The account.
    pub account: AccountId,
    /// The device subkey that signed both.
    pub device: DeviceId,
    /// The lane.
    pub lane: Lane,
    /// The sequence number within that lane.
    pub sequence: u64,
}

impl Encode for AccountOffence {
    fn encode(&self, out: &mut Encoder) {
        self.account.encode(out);
        self.device.encode(out);
        self.lane.encode(out);
        out.write_varint(self.sequence);
    }
}

impl Decode for AccountOffence {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            account: AccountId::decode(input)?,
            device: DeviceId::decode(input)?,
            lane: Lane::decode(input)?,
            sequence: input.read_varint()?,
        })
    }
}

/// The height a validator equivocated at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ValidatorOffence {
    /// The accused.
    pub validator: AccountId,
    /// The height it signed twice at.
    pub height: u64,
}

impl Encode for ValidatorOffence {
    fn encode(&self, out: &mut Encoder) {
        self.validator.encode(out);
        out.write_varint(self.height);
    }
}

impl Decode for ValidatorOffence {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self { validator: AccountId::decode(input)?, height: input.read_varint()? })
    }
}

/// How a seizure is divided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Penalty {
    /// What was taken.
    pub seized: Amount,
    /// Paid to whoever published the proof.
    pub to_denouncer: Amount,
    /// Destroyed.
    pub burned: Amount,
}

impl Penalty {
    /// Splits a seizure in half, remainder to the fire.
    ///
    /// The remainder goes to the fire for the same reason it does in a fee
    /// split: every other destination is a party with an incentive, and the
    /// fire has none. It also means the burn is never *under*-paid, which keeps
    /// the "every closed loop loses money" invariant sound at small amounts.
    #[must_use]
    pub fn split(seized: Amount) -> Self {
        let to_denouncer = seized.mul_div_floor(1, 2).unwrap_or(Amount::ZERO);
        let burned = seized.checked_sub(to_denouncer).unwrap_or(Amount::ZERO);
        Self { seized, to_denouncer, burned }
    }

    /// The two parts summed, which must equal what was seized.
    #[must_use]
    pub fn total(self) -> Option<Amount> {
        self.to_denouncer.checked_add(self.burned)
    }

    /// Whether anything was actually taken.
    ///
    /// An equivocation by an account with no bonded margin seizes nothing, and
    /// that is R2's design rather than an oversight: bonding the nomad credit
    /// is *optional*. The unbonded cheat is still convicted and its conflicting
    /// spend still unwinds on reconciliation — there is simply nothing to take.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.seized.is_zero()
    }
}

/// Why a seizure was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SlashingError {
    /// This exact offence has already been punished.
    ///
    /// Without this check, a denouncer could re-publish the same proof after
    /// the offender re-funded its margin, and collect again for one crime.
    AlreadyPunished,
}

impl fmt::Display for SlashingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyPunished => write!(f, "this equivocation has already been punished"),
        }
    }
}

impl std::error::Error for SlashingError {}

/// Every equivocation that has been punished.
///
/// Grows only with actual convictions, which are rare by construction: each
/// costs the offender its margin or its bond. It is committed to the state root
/// so that "has this already been paid out?" is a question a light client can
/// answer for itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SlashingBook {
    accounts: BTreeSet<AccountOffence>,
    validators: BTreeSet<ValidatorOffence>,
}

impl SlashingBook {
    /// Nothing has been punished.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many convictions are recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.accounts.len().saturating_add(self.validators.len())
    }

    /// Whether nothing has been punished.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty() && self.validators.is_empty()
    }

    /// Whether an account offence is already recorded.
    #[must_use]
    pub fn knows_account(&self, offence: &AccountOffence) -> bool {
        self.accounts.contains(offence)
    }

    /// Whether a validator offence is already recorded.
    #[must_use]
    pub fn knows_validator(&self, offence: &ValidatorOffence) -> bool {
        self.validators.contains(offence)
    }

    /// Records an account equivocation, refusing a repeat.
    pub fn record_account(&mut self, offence: AccountOffence) -> Result<(), SlashingError> {
        if !self.accounts.insert(offence) {
            return Err(SlashingError::AlreadyPunished);
        }
        Ok(())
    }

    /// Records a validator equivocation, refusing a repeat.
    pub fn record_validator(&mut self, offence: ValidatorOffence) -> Result<(), SlashingError> {
        if !self.validators.insert(offence) {
            return Err(SlashingError::AlreadyPunished);
        }
        Ok(())
    }

    /// Every account offence, in ascending order.
    pub fn account_offences(&self) -> impl Iterator<Item = &AccountOffence> {
        self.accounts.iter()
    }

    /// Every validator offence, in ascending order.
    pub fn validator_offences(&self) -> impl Iterator<Item = &ValidatorOffence> {
        self.validators.iter()
    }

    /// The digest an offence is recorded under.
    #[must_use]
    pub fn digest<T: Encode>(offence: &T) -> Hash {
        Hasher::new(domain::STATE_VALUE).update(&offence.to_canonical_bytes()).finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::{AccountOffence, Penalty, SlashingBook, SlashingError, ValidatorOffence};
    use vanargand_crypto::hash::Hash;
    use vanargand_types::codec::{Decode, Encode};
    use vanargand_types::id::{AccountId, DeviceId};
    use vanargand_types::nonce::Lane;
    use vanargand_types::Amount;

    fn account(byte: u8) -> AccountId {
        AccountId::from_hash(Hash::from_bytes([byte; 32]))
    }

    fn offence(byte: u8, sequence: u64) -> AccountOffence {
        AccountOffence {
            account: account(byte),
            device: DeviceId::from_hash(Hash::from_bytes([byte.wrapping_add(1); 32])),
            lane: Lane::FIRST,
            sequence,
        }
    }

    #[test]
    fn a_seizure_is_split_in_half_with_the_remainder_burned() {
        let even = Penalty::split(Amount::from_ulf(100));
        assert_eq!(even.to_denouncer, Amount::from_ulf(50));
        assert_eq!(even.burned, Amount::from_ulf(50));
        assert_eq!(even.total(), Some(Amount::from_ulf(100)));

        let odd = Penalty::split(Amount::from_ulf(101));
        assert_eq!(odd.to_denouncer, Amount::from_ulf(50));
        assert_eq!(odd.burned, Amount::from_ulf(51), "the remainder did not go to the fire");
        assert_eq!(odd.total(), Some(Amount::from_ulf(101)));
    }

    #[test]
    fn a_seizure_never_creates_or_loses_value() {
        for ulf in 0_u64..500 {
            let penalty = Penalty::split(Amount::from_ulf(ulf));
            assert_eq!(
                penalty.total(),
                Some(Amount::from_ulf(ulf)),
                "the split lost or created value at {ulf} ulf"
            );
        }
        let whole = Penalty::split(Amount::MAX);
        assert_eq!(whole.total(), Some(Amount::MAX));
    }

    #[test]
    fn an_unbonded_equivocation_seizes_nothing_and_says_so() {
        // R2 makes bonding the nomad credit optional. The unbonded cheat is
        // still convicted and its conflicting spend still unwinds; there is
        // simply nothing to take.
        let nothing = Penalty::split(Amount::ZERO);
        assert!(nothing.is_empty());
        assert_eq!(nothing.to_denouncer, Amount::ZERO);
        assert_eq!(nothing.burned, Amount::ZERO);
    }

    #[test]
    fn one_crime_earns_one_bounty() {
        // The check that matters: without it, a denouncer republishes the same
        // proof after the offender re-funds its margin and collects again.
        let mut book = SlashingBook::new();
        assert!(book.record_account(offence(1, 7)).is_ok());
        assert_eq!(book.record_account(offence(1, 7)), Err(SlashingError::AlreadyPunished));
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn different_slots_are_different_crimes() {
        let mut book = SlashingBook::new();
        book.record_account(offence(1, 7)).expect("first");
        book.record_account(offence(1, 8)).expect("a different sequence");
        book.record_account(offence(2, 7)).expect("a different account");

        let mut other_lane = offence(1, 7);
        other_lane.lane = Lane::new(1);
        book.record_account(other_lane).expect("a different lane");

        assert_eq!(book.len(), 4);
        assert!(book.knows_account(&offence(1, 7)));
        assert!(!book.knows_account(&offence(3, 7)));
    }

    #[test]
    fn a_validator_is_punished_once_per_height() {
        let mut book = SlashingBook::new();
        let first = ValidatorOffence { validator: account(1), height: 42 };
        assert!(book.record_validator(first).is_ok());
        assert_eq!(book.record_validator(first), Err(SlashingError::AlreadyPunished));

        let elsewhere = ValidatorOffence { validator: account(1), height: 43 };
        assert!(book.record_validator(elsewhere).is_ok());
        assert!(book.knows_validator(&first));
        assert_eq!(book.len(), 2);
    }

    #[test]
    fn account_and_validator_offences_do_not_collide() {
        // They are recorded in different sets and hash to different digests,
        // so a validator's conviction can never be mistaken for an account's.
        let account_offence = offence(1, 42);
        let validator_offence = ValidatorOffence { validator: account(1), height: 42 };
        assert_ne!(
            SlashingBook::digest(&account_offence),
            SlashingBook::digest(&validator_offence)
        );
    }

    #[test]
    fn offences_iterate_in_order() {
        // Consensus-critical: these entries are hashed into the state root.
        let mut book = SlashingBook::new();
        for sequence in [5_u64, 1, 3] {
            book.record_account(offence(1, sequence)).expect("distinct");
        }
        let observed: Vec<u64> = book.account_offences().map(|item| item.sequence).collect();
        assert_eq!(observed, vec![1, 3, 5]);
    }

    #[test]
    fn offences_round_trip() {
        let item = offence(9, 12_345);
        assert_eq!(AccountOffence::from_canonical_bytes(&item.to_canonical_bytes()), Ok(item));

        let validator = ValidatorOffence { validator: account(3), height: u64::MAX };
        assert_eq!(
            ValidatorOffence::from_canonical_bytes(&validator.to_canonical_bytes()),
            Ok(validator)
        );
    }
}
