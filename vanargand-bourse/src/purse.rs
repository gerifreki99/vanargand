// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The on-chain half of a channel: the record, and how it closes.
//!
//! Two parties lock a sum on the ledger, exchange signed acknowledgements
//! off-chain for free, and write only the final balance. A thousand
//! micro-payments cost two entries in the register.
//!
//! # C9, which is why this module is shaped the way it is
//!
//! Closing a channel is where a payment channel and a partition meet, and
//! nothing in either literature covers the combination. Publish a **stale**
//! unilateral closure into provisional blocks while the counterparty and its
//! watchtower are on the far side of a partition, and the contestation window
//! runs out in a world where the objector cannot exist.
//!
//! The parade is two rules, and both are enforced outside this module — which
//! is worth knowing, because reading only this file would make them invisible:
//!
//! 1. `purse_close_unilateral` and `purse_dispute` are **grammatically
//!    illegal** in a provisional block
//!    (`vanargand_types::tx::TxKind::allowed_in_provisional`). The cooperative
//!    closure is whitelisted, because both parties signed it and there is no
//!    absent victim.
//! 2. Every deadline here is a
//!    [`vanargand_types::block::ContestationWindow`], which takes a **finalised**
//!    height and has no overload taking an ordinary one. A partition raises
//!    the height freely and cannot move the finalised tip at all, so the window
//!    stands still for exactly as long as the objector cannot speak.
//!
//! # The asymmetry that makes disputes simple
//!
//! Only the **payer** can lie. A unilateral closure claims a number of
//! tranches, and a claim is only believed if it comes with the PayWord token
//! that proves it — so over-claiming would require a preimage. The payee
//! therefore cannot inflate what it is owed, and the payer's only attack is to
//! *under*-claim. That is the one thing a dispute has to answer, and it answers
//! it by presenting a larger token.

use core::fmt;

use vanargand_crypto::hash::Hash;
use vanargand_types::block::{params::EPOCH_BLOCKS, ContestationWindow};
use vanargand_types::codec::{CodecError, Decode, Decoder, Encode, Encoder};
use vanargand_types::id::{AccountId, AssetId, TxId};
use vanargand_types::Amount;

use crate::payword::{value_of, verify_against_root, PayWordError, PayWordToken};

/// A channel is identified by the transaction that opened it.
pub type PurseId = TxId;

/// How long a unilateral closure can be contested, in **finalised** blocks.
///
/// Twenty-four epochs, about a day of healthy chain. Long enough that a
/// watchtower on a domestic connection has many chances to notice; short enough
/// that an honest closure is not a week of waiting.
///
/// A point of departure to be fixed by simulation. What is *not* a parameter is
/// the unit: finalised blocks, never ordinary ones.
pub const DISPUTE_WINDOW_FINALIZED_BLOCKS: u64 = 24 * EPOCH_BLOCKS;

/// A unilateral closure waiting out its window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingClosure {
    /// Who published it.
    pub claimant: AccountId,
    /// How many tranches the claimant admits were spent.
    pub claimed_tranches: u32,
    /// The window, in finalised height.
    pub window: ContestationWindow,
    /// Whether a dispute has already proved the claim stale.
    pub disputed: bool,
}

/// How a channel's deposit is divided when it settles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settlement {
    /// Returned to the party that funded the channel.
    pub to_payer: Amount,
    /// Paid to the party that was served.
    pub to_payee: Amount,
}

impl Settlement {
    /// The two parts summed, which must equal the deposit.
    #[must_use]
    pub fn total(self) -> Option<Amount> {
        self.to_payer.checked_add(self.to_payee)
    }
}

/// Why a channel operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PurseError {
    /// The account is neither party to this channel.
    NotAParty(AccountId),
    /// A channel between an account and itself.
    SelfChannel,
    /// A closure is already pending.
    AlreadyClosing,
    /// No closure is pending, so there is nothing to dispute or settle.
    NotClosing,
    /// The window has not elapsed in finalised height.
    WindowOpen {
        /// The finalised height supplied.
        finalized_height: u64,
        /// The finalised height at which the window closes.
        closes_at: u64,
    },
    /// The dispute does not improve on the claim.
    ///
    /// A dispute must present **strictly more** tranches. Equal is not fraud,
    /// and fewer is the disputer arguing against itself.
    NotAnImprovement {
        /// What the closure claimed.
        claimed: u32,
        /// What the dispute claimed.
        disputed: u32,
    },
    /// The PayWord token did not verify.
    PayWord(PayWordError),
    /// A claim beyond the chain the channel committed to.
    BeyondCapacity {
        /// What was claimed.
        claimed: u32,
        /// What the chain holds.
        capacity: u32,
    },
    /// The cooperative balances do not sum to the deposit.
    ///
    /// Not a rounding complaint: a cooperative closure that created or
    /// destroyed value would be a mint or a burn that both parties signed and
    /// nobody audited.
    UnbalancedSettlement {
        /// What the two balances sum to.
        total: Amount,
        /// What was locked.
        deposit: Amount,
    },
    /// Value arithmetic overflowed.
    Overflow,
}

impl fmt::Display for PurseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAParty(account) => write!(f, "{account} is not a party to this channel"),
            Self::SelfChannel => write!(f, "a channel needs two parties"),
            Self::AlreadyClosing => write!(f, "a closure is already pending"),
            Self::NotClosing => write!(f, "no closure is pending"),
            Self::WindowOpen { finalized_height, closes_at } => write!(
                f,
                "the window closes at finalised height {closes_at}, now {finalized_height}"
            ),
            Self::NotAnImprovement { claimed, disputed } => {
                write!(f, "a dispute of {disputed} does not improve on a claim of {claimed}")
            }
            Self::PayWord(error) => write!(f, "{error}"),
            Self::BeyondCapacity { claimed, capacity } => {
                write!(f, "claimed {claimed} tranches of a {capacity}-tranche chain")
            }
            Self::UnbalancedSettlement { total, deposit } => {
                write!(f, "balances total {total}, deposit is {deposit}")
            }
            Self::Overflow => write!(f, "value arithmetic overflowed"),
        }
    }
}

impl std::error::Error for PurseError {}

impl From<PayWordError> for PurseError {
    fn from(error: PayWordError) -> Self {
        Self::PayWord(error)
    }
}

/// A channel, as the ledger holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Purse {
    /// The party that locked the deposit and spends tokens.
    pub payer: AccountId,
    /// The party that is served and collects them.
    pub payee: AccountId,
    /// Which asset, or `None` for VAN.
    pub asset: Option<AssetId>,
    /// The locked sum.
    pub deposit: Amount,
    /// The root of the payer's PayWord chain.
    pub payword_root: Hash,
    /// What one tranche is worth.
    pub tranche_value: Amount,
    /// How many tranches the chain holds.
    pub capacity: u32,
    /// The hygiene deadline, in finalised height.
    ///
    /// Not a liveness mechanism: the payer can always close unilaterally with
    /// the true count, so a payee that vanishes never strands the deposit.
    /// Expiry exists so that a forgotten channel eventually stops occupying
    /// state, which is the requirement of `docs/01-concept.pdf` that settled
    /// obligations leave the ledger.
    pub expiry_finalized_height: u64,
    /// A unilateral closure in progress.
    pub closing: Option<PendingClosure>,
}

impl Purse {
    /// Opens a channel.
    pub fn open(
        payer: AccountId,
        payee: AccountId,
        asset: Option<AssetId>,
        deposit: Amount,
        payword_root: Hash,
        tranche_value: Amount,
        capacity: u32,
        expiry_finalized_height: u64,
    ) -> Result<Self, PurseError> {
        if payer == payee {
            return Err(PurseError::SelfChannel);
        }
        Ok(Self {
            payer,
            payee,
            asset,
            deposit,
            payword_root,
            tranche_value,
            capacity,
            expiry_finalized_height,
            closing: None,
        })
    }

    /// Whether `account` is one of the two parties.
    #[must_use]
    pub fn is_party(&self, account: &AccountId) -> bool {
        *account == self.payer || *account == self.payee
    }

    /// Whether the hygiene deadline has passed.
    #[must_use]
    pub const fn is_expired(&self, finalized_height: u64) -> bool {
        finalized_height >= self.expiry_finalized_height
    }

    /// What `tranches` tranches are worth, capped at the deposit.
    ///
    /// Capping rather than failing: the payer cannot spend more than it locked,
    /// so a claim above the deposit is a claim the chain was longer than the
    /// money. The payee gets everything there is, which is the honest answer,
    /// and the surplus claim buys nothing.
    pub fn owed_for(&self, tranches: u32) -> Result<Amount, PurseError> {
        let raw = value_of(tranches, self.tranche_value)?;
        Ok(raw.min(self.deposit))
    }

    /// Closes the channel with both parties' agreement.
    ///
    /// No window, because there is no absent victim: a closure both parties
    /// signed cannot defraud either of them. That is exactly why R2 whitelists
    /// this transaction in provisional blocks while keeping the unilateral one
    /// grammatically illegal — and why the application prompts a user to close
    /// their channels before a planned outage.
    ///
    /// This function does not check signatures. Establishing that both parties
    /// agreed is the transaction layer's job; this decides what the agreement
    /// means.
    pub fn settle_cooperative(
        &self,
        to_payer: Amount,
        to_payee: Amount,
    ) -> Result<Settlement, PurseError> {
        let total = to_payer.checked_add(to_payee).ok_or(PurseError::Overflow)?;
        if total != self.deposit {
            return Err(PurseError::UnbalancedSettlement { total, deposit: self.deposit });
        }
        Ok(Settlement { to_payer, to_payee })
    }

    /// Begins a unilateral closure, opening the contestation window.
    ///
    /// The claim must come with the token that proves it: `claimed_tranches` of
    /// zero closes with nothing spent and needs no token, and any other claim
    /// must verify against the committed root at exactly that index.
    ///
    /// The caller supplies the window rather than a block, because a channel
    /// has no business knowing what a block header is. The C9 discipline lives
    /// in [`ContestationWindow`] itself: its anchor field is named
    /// `opened_at_finalized`, and
    /// [`ContestationWindow::open`](vanargand_types::block::ContestationWindow::open)
    /// takes a whole header so that reaching for `height` by mistake is not a
    /// thing a caller can do without noticing.
    pub fn begin_unilateral(
        &mut self,
        claimant: AccountId,
        claimed_tranches: u32,
        token: Option<&PayWordToken>,
        window: ContestationWindow,
    ) -> Result<(), PurseError> {
        if !self.is_party(&claimant) {
            return Err(PurseError::NotAParty(claimant));
        }
        if self.closing.is_some() {
            return Err(PurseError::AlreadyClosing);
        }
        if claimed_tranches > self.capacity {
            return Err(PurseError::BeyondCapacity {
                claimed: claimed_tranches,
                capacity: self.capacity,
            });
        }
        self.check_claim(claimed_tranches, token)?;

        self.closing = Some(PendingClosure { claimant, claimed_tranches, window, disputed: false });
        Ok(())
    }

    /// Contests a pending closure with a larger token.
    ///
    /// C5, and the reason watchtowers are paid. Every device of an owner is
    /// automatically a watchtower for that owner's channels (R1.6), so the
    /// common case is that the victim's own laptop objects while the victim
    /// sleeps.
    ///
    /// A successful dispute proves the claimant under-stated what it spent,
    /// which is attributable fraud — so the penalty applies. See
    /// [`Purse::settle`].
    pub fn dispute(
        &mut self,
        disputed_tranches: u32,
        token: &PayWordToken,
    ) -> Result<(), PurseError> {
        let Some(pending) = self.closing else {
            return Err(PurseError::NotClosing);
        };
        if disputed_tranches <= pending.claimed_tranches {
            return Err(PurseError::NotAnImprovement {
                claimed: pending.claimed_tranches,
                disputed: disputed_tranches,
            });
        }
        if disputed_tranches > self.capacity {
            return Err(PurseError::BeyondCapacity {
                claimed: disputed_tranches,
                capacity: self.capacity,
            });
        }
        self.check_claim(disputed_tranches, Some(token))?;

        self.closing = Some(PendingClosure {
            claimed_tranches: disputed_tranches,
            disputed: true,
            ..pending
        });
        Ok(())
    }

    /// Settles a pending closure whose window has elapsed.
    ///
    /// `current_finalized_height` is a **finalised** height. Passing an
    /// ordinary one is the C9 bug, and
    /// [`vanargand_types::block::ContestationWindow`] deliberately offers no
    /// way to do it by accident.
    ///
    /// # The penalty
    ///
    /// If the closure was disputed, the payer forfeits its whole remaining
    /// share: "le fraudeur perd sa mise". The size of that penalty is a
    /// parameter — what is not a parameter is that it exists and that it goes
    /// to the party that was cheated, because a watchtower that is not paid is
    /// a watchtower that is not watching.
    ///
    /// A dispute against a closure published by the **payee** cannot happen:
    /// over-claiming needs a preimage, so the payee's claim is honest by
    /// construction.
    pub fn settle(&self, current_finalized_height: u64) -> Result<Settlement, PurseError> {
        let Some(pending) = self.closing else {
            return Err(PurseError::NotClosing);
        };
        if !pending.window.has_elapsed(current_finalized_height) {
            return Err(PurseError::WindowOpen {
                finalized_height: current_finalized_height,
                closes_at: pending
                    .window
                    .opened_at_finalized
                    .saturating_add(pending.window.duration),
            });
        }

        if pending.disputed {
            return Ok(Settlement { to_payer: Amount::ZERO, to_payee: self.deposit });
        }

        let to_payee = self.owed_for(pending.claimed_tranches)?;
        let to_payer = self.deposit.checked_sub(to_payee).ok_or(PurseError::Overflow)?;
        Ok(Settlement { to_payer, to_payee })
    }

    fn check_claim(
        &self,
        tranches: u32,
        token: Option<&PayWordToken>,
    ) -> Result<(), PurseError> {
        if tranches == 0 {
            // Nothing spent needs nothing proved. The payee's remedy against a
            // false zero is a dispute, which is the whole mechanism.
            return Ok(());
        }
        let Some(token) = token else {
            return Err(PurseError::PayWord(PayWordError::BadToken { index: tranches }));
        };
        if token.index != tranches {
            return Err(PurseError::PayWord(PayWordError::IndexMismatch {
                claimed: tranches,
                actual: token.index,
            }));
        }
        verify_against_root(&self.payword_root, token)?;
        Ok(())
    }
}

impl Encode for PendingClosure {
    fn encode(&self, out: &mut Encoder) {
        self.claimant.encode(out);
        out.write_varint(u64::from(self.claimed_tranches));
        out.write_varint(self.window.opened_at_finalized);
        out.write_varint(self.window.duration);
        out.write_bool(self.disputed);
    }
}

impl Decode for PendingClosure {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let claimant = AccountId::decode(input)?;
        let claimed_tranches = input.read_varint_u32()?;
        let opened_at_finalized = input.read_varint()?;
        let duration = input.read_varint()?;
        let disputed = input.read_bool()?;
        Ok(Self {
            claimant,
            claimed_tranches,
            window: ContestationWindow { opened_at_finalized, duration },
            disputed,
        })
    }
}

impl Encode for Purse {
    fn encode(&self, out: &mut Encoder) {
        self.payer.encode(out);
        self.payee.encode(out);
        out.write_option(self.asset.as_ref());
        self.deposit.encode(out);
        self.payword_root.encode(out);
        self.tranche_value.encode(out);
        out.write_varint(u64::from(self.capacity));
        out.write_varint(self.expiry_finalized_height);
        out.write_option(self.closing.as_ref());
    }
}

impl Decode for Purse {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            payer: AccountId::decode(input)?,
            payee: AccountId::decode(input)?,
            asset: input.read_option::<AssetId>()?,
            deposit: Amount::decode(input)?,
            payword_root: Hash::decode(input)?,
            tranche_value: Amount::decode(input)?,
            capacity: input.read_varint_u32()?,
            expiry_finalized_height: input.read_varint()?,
            closing: input.read_option::<PendingClosure>()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Purse, PurseError, Settlement, DISPUTE_WINDOW_FINALIZED_BLOCKS};
    use crate::payword::{PayWordPayer, PayWordToken};
    use vanargand_crypto::hash::Hash;
    use vanargand_types::amount::Ratio;
    use vanargand_types::block::{
        BlockHeader, ContestationWindow, FinalityRung, HEADER_VERSION,
    };
    use vanargand_types::codec::{Decode, Encode};
    use vanargand_types::id::{AccountId, BlockId, ChainId};
    use vanargand_types::Amount;

    const CAPACITY: u32 = 1_000;

    fn account(byte: u8) -> AccountId {
        AccountId::from_hash(Hash::from_bytes([byte; 32]))
    }

    /// A header at a given finalised height. Provisional so that `height` and
    /// `finalized_height` are free to differ, which is the whole point.
    fn header(height: u64, finalized: u64) -> BlockHeader {
        BlockHeader {
            version: HEADER_VERSION,
            chain: ChainId::from_hash(Hash::from_bytes([0x11; 32])),
            height,
            parent: BlockId::from_hash(Hash::from_bytes([0x22; 32])),
            rung: FinalityRung::Provisional,
            finalized_height: finalized,
            state_root: Hash::from_bytes([0x33; 32]),
            tx_root: Hash::from_bytes([0x44; 32]),
            proposer: account(0xee),
            randomness_reveal: Hash::from_bytes([0x66; 32]),
            archive_commitment: Hash::from_bytes([0x77; 32]),
            emitted_supply: Amount::from_ulf(1),
            security_budget: Amount::from_ulf(1),
            fee_emission_ratio: Ratio::new(1, 1),
        }
    }

    /// A contestation window anchored at a finalised height.
    ///
    /// Built through `ContestationWindow::open`, which takes a whole header, so
    /// that these tests exercise the constructor a node actually uses rather
    /// than assembling the struct by hand. The ordinary height is deliberately
    /// far ahead of the finalised one: if anything ever reads the wrong field,
    /// every window here is wrong by sixty blocks and the tests say so.
    fn window(finalized: u64) -> ContestationWindow {
        ContestationWindow::open(
            &header(finalized.saturating_add(60), finalized),
            DISPUTE_WINDOW_FINALIZED_BLOCKS,
        )
    }

    /// A funded channel and the payer's chain.
    fn channel() -> (Purse, PayWordPayer) {
        let payer_chain =
            PayWordPayer::open(&Hash::from_bytes([7; 32]), CAPACITY, Amount::from_ulf(10))
                .expect("a short chain");
        let purse = Purse::open(
            account(1),
            account(2),
            None,
            Amount::from_ulf(10_000),
            payer_chain.root(),
            Amount::from_ulf(10),
            CAPACITY,
            1_000_000,
        )
        .expect("two distinct parties");
        (purse, payer_chain)
    }

    #[test]
    fn a_channel_needs_two_parties() {
        assert_eq!(
            Purse::open(
                account(1),
                account(1),
                None,
                Amount::from_ulf(1),
                Hash::ZERO,
                Amount::from_ulf(1),
                1,
                0,
            ),
            Err(PurseError::SelfChannel)
        );
    }

    #[test]
    fn a_cooperative_closure_must_conserve_the_deposit() {
        // A closure that created or destroyed value would be a mint or a burn
        // that both parties signed and nobody audited.
        let (purse, _) = channel();
        assert_eq!(
            purse.settle_cooperative(Amount::from_ulf(6_000), Amount::from_ulf(4_000)),
            Ok(Settlement { to_payer: Amount::from_ulf(6_000), to_payee: Amount::from_ulf(4_000) })
        );
        assert!(matches!(
            purse.settle_cooperative(Amount::from_ulf(6_000), Amount::from_ulf(5_000)),
            Err(PurseError::UnbalancedSettlement { .. })
        ));
        assert!(matches!(
            purse.settle_cooperative(Amount::from_ulf(1), Amount::from_ulf(1)),
            Err(PurseError::UnbalancedSettlement { .. })
        ));
    }

    #[test]
    fn an_honest_unilateral_closure_settles_after_the_window() {
        let (mut purse, mut chain) = channel();
        let token = chain.spend(40).expect("tranches remain");

        purse
            .begin_unilateral(account(1), 40, Some(&token), window(40))
            .expect("an honest claim with its proof");

        assert!(matches!(purse.settle(40), Err(PurseError::WindowOpen { .. })));
        let settlement = purse
            .settle(40 + DISPUTE_WINDOW_FINALIZED_BLOCKS)
            .expect("the window has elapsed");
        assert_eq!(settlement.to_payee, Amount::from_ulf(400));
        assert_eq!(settlement.to_payer, Amount::from_ulf(9_600));
        assert_eq!(settlement.total(), Some(purse.deposit));
    }

    #[test]
    fn the_window_does_not_run_during_a_partition() {
        // C9 end to end. The closure opens at finalised height 40. The
        // partition then produces sixty thousand provisional blocks — far more
        // than the window's duration — and the finalised tip does not move.
        // The window has not run at all.
        let (mut purse, mut chain) = channel();
        let token = chain.spend(10).expect("tranches remain");
        purse.begin_unilateral(account(1), 10, Some(&token), window(40)).expect("valid claim");

        let deep_in_the_partition = header(60_100, 40);
        assert!(
            purse.settle(deep_in_the_partition.finalized_height).is_err(),
            "the window expired inside a partition; C9 is open"
        );

        // Only finalised progress moves it.
        assert!(purse.settle(40 + DISPUTE_WINDOW_FINALIZED_BLOCKS - 1).is_err());
        assert!(purse.settle(40 + DISPUTE_WINDOW_FINALIZED_BLOCKS).is_ok());
    }

    #[test]
    fn a_stale_claim_is_overturned_and_punished() {
        // The whole reason watchtowers exist. The payer spent 400 tranches and
        // closes claiming 40.
        let (mut purse, mut chain) = channel();
        let stale = chain.spend(40).expect("tranches remain");
        let truth = chain.spend(360).expect("tranches remain");
        assert_eq!(truth.index, 400);

        purse
            .begin_unilateral(account(1), 40, Some(&stale), window(40))
            .expect("the stale claim is structurally valid");

        purse.dispute(400, &truth).expect("a larger token overturns it");

        let settlement = purse
            .settle(40 + DISPUTE_WINDOW_FINALIZED_BLOCKS)
            .expect("the window has elapsed");
        assert_eq!(settlement.to_payee, purse.deposit, "the cheat kept something");
        assert_eq!(settlement.to_payer, Amount::ZERO);
        assert_eq!(settlement.total(), Some(purse.deposit));
    }

    #[test]
    fn a_dispute_must_improve_on_the_claim() {
        let (mut purse, mut chain) = channel();
        let token = chain.spend(40).expect("tranches remain");
        purse
            .begin_unilateral(account(1), 40, Some(&token), window(40))
            .expect("valid claim");

        assert_eq!(
            purse.dispute(40, &token),
            Err(PurseError::NotAnImprovement { claimed: 40, disputed: 40 }),
            "an equal claim is not fraud"
        );
        assert_eq!(
            purse.dispute(10, &token),
            Err(PurseError::NotAnImprovement { claimed: 40, disputed: 10 })
        );
    }

    #[test]
    fn a_dispute_needs_a_genuine_token() {
        let (mut purse, mut chain) = channel();
        let token = chain.spend(40).expect("tranches remain");
        purse
            .begin_unilateral(account(1), 40, Some(&token), window(40))
            .expect("valid claim");

        let forged = PayWordToken { index: 400, link: Hash::from_bytes([0xab; 32]) };
        assert!(matches!(purse.dispute(400, &forged), Err(PurseError::PayWord(_))));

        // And the closure is untouched by the failed attempt.
        let settlement = purse.settle(40 + DISPUTE_WINDOW_FINALIZED_BLOCKS).expect("elapsed");
        assert_eq!(settlement.to_payee, Amount::from_ulf(400));
    }

    #[test]
    fn a_claim_without_its_proof_is_refused() {
        let (mut purse, _) = channel();
        assert!(matches!(
            purse.begin_unilateral(account(1), 40, None, window(40)),
            Err(PurseError::PayWord(_))
        ));
    }

    #[test]
    fn a_claim_of_nothing_needs_no_proof_and_can_be_disputed() {
        // The most dishonest closure available to a payer, and the ordinary
        // case for a channel that was opened and never used. The protocol
        // cannot tell them apart, which is exactly why there is a window.
        let (mut purse, mut chain) = channel();
        purse
            .begin_unilateral(account(1), 0, None, window(40))
            .expect("nothing spent needs nothing proved");

        let truth = chain.spend(250).expect("tranches remain");
        purse.dispute(250, &truth).expect("the payee objects");

        let settlement = purse.settle(40 + DISPUTE_WINDOW_FINALIZED_BLOCKS).expect("elapsed");
        assert_eq!(settlement.to_payee, purse.deposit);
    }

    #[test]
    fn a_claim_beyond_the_deposit_is_capped() {
        // The payer cannot spend more than it locked. A chain longer than the
        // money buys nothing, and the payee gets everything there is.
        let (mut purse, mut chain) = channel();
        assert_eq!(purse.owed_for(CAPACITY), Ok(purse.deposit));
        assert_eq!(
            purse.owed_for(CAPACITY.saturating_mul(3)),
            Ok(purse.deposit),
            "a claim above the deposit was not capped"
        );

        let token = chain.spend(CAPACITY).expect("the chain holds a thousand");
        purse
            .begin_unilateral(account(2), CAPACITY, Some(&token), window(40))
            .expect("the payee closes with everything");
        let settlement = purse.settle(40 + DISPUTE_WINDOW_FINALIZED_BLOCKS).expect("elapsed");
        assert_eq!(settlement.to_payee, purse.deposit);
        assert_eq!(settlement.to_payer, Amount::ZERO);
    }

    #[test]
    fn a_claim_beyond_the_chain_is_refused() {
        let (mut purse, _) = channel();
        let bogus = PayWordToken { index: CAPACITY + 1, link: Hash::ZERO };
        assert_eq!(
            purse.begin_unilateral(account(1), CAPACITY + 1, Some(&bogus), window(40)),
            Err(PurseError::BeyondCapacity { claimed: CAPACITY + 1, capacity: CAPACITY })
        );
    }

    #[test]
    fn only_a_party_may_close() {
        let (mut purse, _) = channel();
        assert_eq!(
            purse.begin_unilateral(account(9), 0, None, window(40)),
            Err(PurseError::NotAParty(account(9)))
        );
        assert!(purse.is_party(&account(1)));
        assert!(purse.is_party(&account(2)));
        assert!(!purse.is_party(&account(9)));
    }

    #[test]
    fn a_second_closure_is_refused() {
        let (mut purse, _) = channel();
        purse.begin_unilateral(account(1), 0, None, window(40)).expect("first closure");
        assert_eq!(
            purse.begin_unilateral(account(2), 0, None, window(41)),
            Err(PurseError::AlreadyClosing)
        );
    }

    #[test]
    fn settling_or_disputing_without_a_closure_is_refused() {
        let (mut purse, mut chain) = channel();
        assert_eq!(purse.settle(1_000_000), Err(PurseError::NotClosing));
        let token = chain.spend(1).expect("tranches remain");
        assert_eq!(purse.dispute(1, &token), Err(PurseError::NotClosing));
    }

    #[test]
    fn expiry_is_hygiene_and_not_liveness() {
        // A payee that vanishes never strands the deposit: the payer closes
        // unilaterally with the true count and the window runs out unopposed.
        let (mut purse, mut chain) = channel();
        let token = chain.spend(7).expect("tranches remain");
        assert!(!purse.is_expired(0));
        assert!(purse.is_expired(1_000_000));

        purse
            .begin_unilateral(account(1), 7, Some(&token), window(40))
            .expect("closing an abandoned channel");
        assert!(purse.settle(40 + DISPUTE_WINDOW_FINALIZED_BLOCKS).is_ok());
    }

    #[test]
    fn purses_round_trip() {
        let (mut purse, mut chain) = channel();
        let open_bytes = purse.to_canonical_bytes();
        assert_eq!(Purse::from_canonical_bytes(&open_bytes), Ok(purse.clone()));

        let token = chain.spend(3).expect("tranches remain");
        purse.begin_unilateral(account(1), 3, Some(&token), window(40)).expect("valid");
        let closing_bytes = purse.to_canonical_bytes();
        assert_eq!(Purse::from_canonical_bytes(&closing_bytes), Ok(purse));
    }
}
