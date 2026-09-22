// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Social recovery: getting an identity back after losing every device.
//!
//! `docs/01-concept.pdf` promises that losing a phone does not mean losing a
//! digital life, and that nobody has to copy twenty-four words onto paper. This
//! is the machinery behind that promise, and it is also, honestly, the most
//! dangerous machinery in the protocol: a mechanism for taking an account away
//! from whoever currently holds its keys is a mechanism for taking an account.
//!
//! # How the threshold is collected
//!
//! A transaction envelope carries **one** signature, so a three-of-five
//! recovery cannot be a single transaction. It could carry a list of guardian
//! signatures in its payload; instead, each guardian sends its own ordinary
//! `recovery_start` naming the same target and the same new root key, and the
//! approvals accumulate on chain.
//!
//! That is a choice, and worth stating as one. It needs no aggregate-signature
//! format, each guardian signs with its own device under its own nonce lane,
//! and — the reason that matters here — guardians can approve from different
//! sides of a partition without coordinating, which is the normal condition
//! this protocol was built for.
//!
//! The cost is that a recovery takes several transactions and several fees.
//!
//! # The window, and what it protects
//!
//! Approvals open a contestation window counted in **finalised** height. While
//! it runs, any surviving device of the account can cancel the whole thing.
//! That is the real defence: the guardians can start a recovery, but they
//! cannot finish one against an owner who is still there.
//!
//! Counting in finalised height is the identity-layer instance of the C9
//! parade. A recovery started inside a partition does not mature inside it —
//! otherwise an attacker who can cut a victim off can also lock them out.
//!
//! # G4 is not solved here, and is not claimed to be
//!
//! Collusion among your trusted contacts, or their being phished, steals your
//! identity. High thresholds, the cancellation window and notification on every
//! channel raise the cost; none of them is a proof. It is an attack on people
//! rather than on mathematics, and the threat model says so.

use std::collections::{BTreeMap, BTreeSet};

use core::fmt;

use vanargand_crypto::hash::{domain, Hash, Hasher};
use vanargand_crypto::sign::VerifyingKey;
use vanargand_types::block::{params::EPOCH_BLOCKS, ContestationWindow};
use vanargand_types::codec::{CodecError, Decode, Decoder, Encode, Encoder};
use vanargand_types::id::AccountId;

/// How long a recovery must wait before it can be completed, in **finalised**
/// blocks.
///
/// Seventy-two epochs, about three days of healthy chain. Long enough that an
/// owner who is merely travelling notices and cancels; short enough that
/// someone who really has lost everything is not locked out for a fortnight.
///
/// A parameter, and one that trades two real harms against each other rather
/// than optimising a number.
pub const RECOVERY_WINDOW_FINALIZED_BLOCKS: u64 = 72 * EPOCH_BLOCKS;

/// A recovery in progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRecovery {
    /// The proposed new root key.
    pub new_root_key: VerifyingKey,
    /// Which guardians have approved.
    pub approvals: BTreeSet<AccountId>,
    /// The window, in finalised height.
    pub window: ContestationWindow,
}

impl PendingRecovery {
    /// The digest stored in the state tree.
    #[must_use]
    pub fn value_hash(&self) -> Hash {
        Hasher::new(domain::STATE_VALUE).update(&self.to_canonical_bytes()).finalize()
    }

    /// How many guardians have approved.
    #[must_use]
    pub fn approval_count(&self) -> u32 {
        u32::try_from(self.approvals.len()).unwrap_or(u32::MAX)
    }
}

impl Encode for PendingRecovery {
    fn encode(&self, out: &mut Encoder) {
        self.new_root_key.encode(out);
        out.write_ordered_set(&self.approvals);
        out.write_varint(self.window.opened_at_finalized);
        out.write_varint(self.window.duration);
    }
}

impl Decode for PendingRecovery {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let new_root_key = VerifyingKey::decode(input)?;
        let approvals: BTreeSet<AccountId> = input.read_set::<AccountId>()?.into_iter().collect();
        let opened_at_finalized = input.read_varint()?;
        let duration = input.read_varint()?;
        Ok(Self {
            new_root_key,
            approvals,
            window: ContestationWindow { opened_at_finalized, duration },
        })
    }
}

/// Why a recovery operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecoveryError {
    /// The approver is not a guardian of this account.
    NotAGuardian(AccountId),
    /// The account has named no guardians, so nothing can be recovered.
    NoGuardians,
    /// This guardian has already approved.
    AlreadyApproved(AccountId),
    /// A recovery is under way for a **different** key.
    ///
    /// The important one. Without it, a single rogue guardian approving a
    /// recovery with its own key would redirect a legitimate recovery that the
    /// other guardians had already approved — turning a three-of-five into a
    /// one-of-five in favour of whoever approved last.
    ConflictingKey,
    /// No recovery is under way.
    NotRecovering,
    /// The window has not elapsed in finalised height.
    WindowOpen {
        /// The finalised height supplied.
        finalized_height: u64,
        /// When the window closes.
        closes_at: u64,
    },
    /// Not enough guardians have approved.
    BelowThreshold {
        /// How many have.
        approvals: u32,
        /// How many are needed.
        threshold: u32,
    },
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAGuardian(account) => write!(f, "{account} is not a guardian"),
            Self::NoGuardians => write!(f, "the account has named no guardians"),
            Self::AlreadyApproved(account) => write!(f, "{account} has already approved"),
            Self::ConflictingKey => {
                write!(f, "a recovery is already under way for a different key")
            }
            Self::NotRecovering => write!(f, "no recovery is under way"),
            Self::WindowOpen { finalized_height, closes_at } => write!(
                f,
                "the window closes at finalised height {closes_at}, now {finalized_height}"
            ),
            Self::BelowThreshold { approvals, threshold } => {
                write!(f, "{approvals} of {threshold} guardians have approved")
            }
        }
    }
}

impl std::error::Error for RecoveryError {}

/// Recoveries in progress, by the account being recovered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryBook {
    pending: BTreeMap<AccountId, PendingRecovery>,
}

impl RecoveryBook {
    /// No recoveries under way.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The recovery under way for an account, if any.
    #[must_use]
    pub fn get(&self, target: &AccountId) -> Option<&PendingRecovery> {
        self.pending.get(target)
    }

    /// How many recoveries are under way.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether none are.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Every recovery, in ascending account order.
    pub fn iter(&self) -> impl Iterator<Item = (&AccountId, &PendingRecovery)> {
        self.pending.iter()
    }

    /// Records one guardian's approval, opening the window if it is the first.
    ///
    /// `guardians` is the account's guardian set; the caller reads it from the
    /// account being recovered, which is the only place it can come from.
    pub fn approve(
        &mut self,
        target: AccountId,
        new_root_key: &VerifyingKey,
        guardian: AccountId,
        guardians: &BTreeSet<AccountId>,
        window: ContestationWindow,
    ) -> Result<(), RecoveryError> {
        if guardians.is_empty() {
            return Err(RecoveryError::NoGuardians);
        }
        if !guardians.contains(&guardian) {
            return Err(RecoveryError::NotAGuardian(guardian));
        }

        match self.pending.get_mut(&target) {
            Some(existing) => {
                if existing.new_root_key != *new_root_key {
                    return Err(RecoveryError::ConflictingKey);
                }
                if !existing.approvals.insert(guardian) {
                    return Err(RecoveryError::AlreadyApproved(guardian));
                }
            }
            None => {
                // The first approval starts the clock. Later ones do not
                // restart it: otherwise a guardian could hold one approval back
                // and keep the window open indefinitely, so that an owner who
                // cancelled once has to keep cancelling.
                self.pending.insert(
                    target,
                    PendingRecovery {
                        new_root_key: new_root_key.clone(),
                        approvals: [guardian].into_iter().collect(),
                        window,
                    },
                );
            }
        }
        Ok(())
    }

    /// Cancels a recovery.
    ///
    /// The owner's remedy, and the one that makes the whole mechanism safe to
    /// offer: the guardians can start a recovery, and cannot finish one against
    /// an owner who is still holding a device. The caller has already
    /// established that the canceller is the account itself.
    pub fn cancel(&mut self, target: &AccountId) -> Result<PendingRecovery, RecoveryError> {
        self.pending.remove(target).ok_or(RecoveryError::NotRecovering)
    }

    /// Completes a recovery, returning the key that becomes the account's root.
    ///
    /// Requires both the threshold **and** the elapsed window. Either alone is
    /// not enough: the threshold without the window would let colluding
    /// guardians act before the owner could notice, and the window without the
    /// threshold would let one guardian wait out three days.
    pub fn finalise(
        &mut self,
        target: &AccountId,
        threshold: u32,
        finalized_height: u64,
    ) -> Result<VerifyingKey, RecoveryError> {
        let pending = self.pending.get(target).ok_or(RecoveryError::NotRecovering)?;

        let approvals = pending.approval_count();
        if approvals < threshold {
            return Err(RecoveryError::BelowThreshold { approvals, threshold });
        }
        if !pending.window.has_elapsed(finalized_height) {
            return Err(RecoveryError::WindowOpen {
                finalized_height,
                closes_at: pending
                    .window
                    .opened_at_finalized
                    .saturating_add(pending.window.duration),
            });
        }

        let key = pending.new_root_key.clone();
        self.pending.remove(target);
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::{RecoveryBook, RecoveryError, RECOVERY_WINDOW_FINALIZED_BLOCKS};
    use std::collections::BTreeSet;
    use vanargand_crypto::algorithm::AlgorithmId;
    use vanargand_crypto::hash::Hash;
    use vanargand_crypto::sign::VerifyingKey;
    use vanargand_types::block::ContestationWindow;
    use vanargand_types::codec::{Decode, Encode};
    use vanargand_types::id::AccountId;

    fn account(byte: u8) -> AccountId {
        AccountId::from_hash(Hash::from_bytes([byte; 32]))
    }

    fn key(byte: u8) -> VerifyingKey {
        VerifyingKey::new(AlgorithmId::InsecureTest, vec![byte; 32]).expect("a 32-byte test key")
    }

    fn guardians() -> BTreeSet<AccountId> {
        (10..15_u8).map(account).collect()
    }

    fn window(finalized: u64) -> ContestationWindow {
        ContestationWindow {
            opened_at_finalized: finalized,
            duration: RECOVERY_WINDOW_FINALIZED_BLOCKS,
        }
    }

    /// Marie lost every device; three of her five guardians approve.
    fn three_of_five(book: &mut RecoveryBook, at: u64) {
        for guardian in [account(10), account(11), account(12)] {
            book.approve(account(1), &key(9), guardian, &guardians(), window(at))
                .expect("a guardian approving");
        }
    }

    #[test]
    fn a_threshold_of_guardians_recovers_an_account() {
        let mut book = RecoveryBook::new();
        three_of_five(&mut book, 100);
        assert_eq!(book.get(&account(1)).expect("pending").approval_count(), 3);

        let recovered = book
            .finalise(&account(1), 3, 100 + RECOVERY_WINDOW_FINALIZED_BLOCKS)
            .expect("threshold met and window elapsed");
        assert_eq!(recovered, key(9));
        assert!(book.is_empty(), "a completed recovery stayed in state");
    }

    #[test]
    fn the_threshold_alone_is_not_enough() {
        // Colluding guardians must not be able to act before the owner could
        // notice. That is what the window is for.
        let mut book = RecoveryBook::new();
        three_of_five(&mut book, 100);
        assert!(matches!(
            book.finalise(&account(1), 3, 100),
            Err(RecoveryError::WindowOpen { .. })
        ));
        assert!(matches!(
            book.finalise(&account(1), 3, 100 + RECOVERY_WINDOW_FINALIZED_BLOCKS - 1),
            Err(RecoveryError::WindowOpen { .. })
        ));
    }

    #[test]
    fn the_window_alone_is_not_enough() {
        // One guardian must not be able to take an account by waiting.
        let mut book = RecoveryBook::new();
        book.approve(account(1), &key(9), account(10), &guardians(), window(100)).unwrap();
        assert_eq!(
            book.finalise(&account(1), 3, 100 + RECOVERY_WINDOW_FINALIZED_BLOCKS),
            Err(RecoveryError::BelowThreshold { approvals: 1, threshold: 3 })
        );
    }

    #[test]
    fn a_surviving_device_cancels_everything() {
        // The defence that makes the mechanism safe to offer at all: the
        // guardians can start a recovery and cannot finish one against an owner
        // who is still there.
        let mut book = RecoveryBook::new();
        three_of_five(&mut book, 100);

        book.cancel(&account(1)).expect("the owner objects");
        assert!(book.is_empty());
        assert_eq!(
            book.finalise(&account(1), 3, 100 + RECOVERY_WINDOW_FINALIZED_BLOCKS),
            Err(RecoveryError::NotRecovering)
        );
    }

    #[test]
    fn a_rogue_guardian_cannot_redirect_a_recovery() {
        // Without the conflicting-key check, the last guardian to approve picks
        // the key, turning a three-of-five into a one-of-five in its own favour.
        let mut book = RecoveryBook::new();
        book.approve(account(1), &key(9), account(10), &guardians(), window(100)).unwrap();
        book.approve(account(1), &key(9), account(11), &guardians(), window(100)).unwrap();

        assert_eq!(
            book.approve(account(1), &key(8), account(12), &guardians(), window(100)),
            Err(RecoveryError::ConflictingKey),
            "a guardian redirected a recovery already approved by others"
        );
        assert_eq!(book.get(&account(1)).expect("pending").new_root_key, key(9));
    }

    #[test]
    fn a_guardian_counts_once() {
        let mut book = RecoveryBook::new();
        book.approve(account(1), &key(9), account(10), &guardians(), window(100)).unwrap();
        assert_eq!(
            book.approve(account(1), &key(9), account(10), &guardians(), window(100)),
            Err(RecoveryError::AlreadyApproved(account(10)))
        );
        assert_eq!(book.get(&account(1)).expect("pending").approval_count(), 1);
    }

    #[test]
    fn a_stranger_is_not_a_guardian() {
        let mut book = RecoveryBook::new();
        assert_eq!(
            book.approve(account(1), &key(9), account(99), &guardians(), window(100)),
            Err(RecoveryError::NotAGuardian(account(99)))
        );
        assert!(book.is_empty());
    }

    #[test]
    fn an_account_with_no_guardians_cannot_be_recovered() {
        // Or taken. Naming no guardians is a choice with a cost on both sides,
        // and the protocol enforces it in both directions.
        let mut book = RecoveryBook::new();
        assert_eq!(
            book.approve(account(1), &key(9), account(10), &BTreeSet::new(), window(100)),
            Err(RecoveryError::NoGuardians)
        );
    }

    #[test]
    fn later_approvals_do_not_restart_the_clock() {
        // Otherwise a guardian holds one approval back and keeps the window
        // open for ever, so that an owner who cancelled once has to keep
        // cancelling.
        let mut book = RecoveryBook::new();
        book.approve(account(1), &key(9), account(10), &guardians(), window(100)).unwrap();
        book.approve(account(1), &key(9), account(11), &guardians(), window(5_000)).unwrap();
        book.approve(account(1), &key(9), account(12), &guardians(), window(9_000)).unwrap();

        assert_eq!(book.get(&account(1)).expect("pending").window.opened_at_finalized, 100);
        assert!(book.finalise(&account(1), 3, 100 + RECOVERY_WINDOW_FINALIZED_BLOCKS).is_ok());
    }

    #[test]
    fn a_partition_does_not_mature_a_recovery() {
        // The identity-layer instance of C9: an attacker who can cut a victim
        // off must not thereby be able to lock them out.
        let mut book = RecoveryBook::new();
        three_of_five(&mut book, 40);

        // The ordinary height runs away; the finalised tip does not move.
        assert!(matches!(
            book.finalise(&account(1), 3, 40),
            Err(RecoveryError::WindowOpen { .. })
        ));
        assert!(book.finalise(&account(1), 3, 40 + RECOVERY_WINDOW_FINALIZED_BLOCKS).is_ok());
    }

    #[test]
    fn recoveries_round_trip() {
        let mut book = RecoveryBook::new();
        three_of_five(&mut book, 100);
        let pending = book.get(&account(1)).expect("pending").clone();
        let bytes = pending.to_canonical_bytes();
        assert_eq!(super::PendingRecovery::from_canonical_bytes(&bytes), Ok(pending));
    }
}
