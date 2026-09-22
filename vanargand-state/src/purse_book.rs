// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Where the ledger keeps its channels.
//!
//! `vanargand-bourse` owns what a channel *means* — PayWord, the closing state
//! machine, the contestation window. This module owns where they live and what
//! settling one pays out. The split is the same one as for assets: the rules
//! and the money are in different files, so that a rule bug and an accounting
//! bug cannot hide in each other.
//!
//! # Settlement happens by itself
//!
//! There is no `purse_settle` transaction, and there should not be. A channel
//! whose window has elapsed is paid out by the block that notices, not by
//! whoever remembers to ask.
//!
//! That is not a convenience. If settlement needed a transaction, a party would
//! have to be online and hold a fee to collect what it is already owed — and
//! the party most likely to be neither is the one that was cheated and is
//! waiting for a window to close. Making it automatic means the worst an
//! adversary achieves by going quiet is a delay.

use std::collections::BTreeMap;

use core::fmt;

use vanargand_bourse::payword::PayWordToken;
use vanargand_bourse::purse::{Purse, PurseError, PurseId, Settlement};
use vanargand_crypto::hash::{domain, Hash, Hasher};
use vanargand_types::block::ContestationWindow;
use vanargand_types::codec::Encode;
use vanargand_types::id::{AccountId, AssetId};
use vanargand_types::Amount;

/// What settling a channel pays, and to whom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Payout {
    /// The channel that settled.
    pub purse: PurseId,
    /// The party that funded it.
    pub payer: AccountId,
    /// The party that was served.
    pub payee: AccountId,
    /// Which asset, or `None` for VAN.
    pub asset: Option<AssetId>,
    /// The split.
    pub settlement: Settlement,
}

impl Payout {
    /// The two parts summed, which must equal what was locked.
    #[must_use]
    pub fn total(&self) -> Option<Amount> {
        self.settlement.total()
    }
}

/// Why a channel operation failed at the ledger level.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PurseBookError {
    /// No such channel.
    NoSuchPurse(PurseId),
    /// A channel already exists under that identifier.
    ///
    /// Unreachable while identifiers are transaction ids, which the nonce rules
    /// make unique. Checked anyway: the alternative is silently replacing an
    /// open channel, deposit and all.
    PurseExists(PurseId),
    /// The caller is not a party to this channel.
    NotAParty(AccountId),
    /// The channel logic refused.
    Purse(PurseError),
}

impl fmt::Display for PurseBookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSuchPurse(id) => write!(f, "no such channel {id}"),
            Self::PurseExists(id) => write!(f, "channel {id} already exists"),
            Self::NotAParty(account) => write!(f, "{account} is not a party to this channel"),
            Self::Purse(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for PurseBookError {}

impl From<PurseError> for PurseBookError {
    fn from(error: PurseError) -> Self {
        Self::Purse(error)
    }
}

/// Every open channel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PurseBook {
    purses: BTreeMap<PurseId, Purse>,
}

impl PurseBook {
    /// No channels.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A channel, if it exists.
    #[must_use]
    pub fn get(&self, id: &PurseId) -> Option<&Purse> {
        self.purses.get(id)
    }

    /// How many are open.
    #[must_use]
    pub fn len(&self) -> usize {
        self.purses.len()
    }

    /// Whether none are open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.purses.is_empty()
    }

    /// Every channel, in ascending identifier order.
    pub fn iter(&self) -> impl Iterator<Item = (&PurseId, &Purse)> {
        self.purses.iter()
    }

    /// Records a newly opened channel.
    ///
    /// The deposit has already been debited by the caller; this only files the
    /// record.
    pub fn open(&mut self, id: PurseId, purse: Purse) -> Result<(), PurseBookError> {
        if self.purses.contains_key(&id) {
            return Err(PurseBookError::PurseExists(id));
        }
        self.purses.insert(id, purse);
        Ok(())
    }

    /// Closes a channel by agreement, removing it and returning the payout.
    ///
    /// The caller must be one of the two parties. Checking that both agreed is
    /// the transaction layer's job — this decides what the agreement settles
    /// to.
    pub fn close_cooperative(
        &mut self,
        id: &PurseId,
        caller: AccountId,
        to_payer: Amount,
        to_payee: Amount,
    ) -> Result<Payout, PurseBookError> {
        let purse = self.purses.get(id).ok_or(PurseBookError::NoSuchPurse(*id))?;
        if !purse.is_party(&caller) {
            return Err(PurseBookError::NotAParty(caller));
        }
        let settlement = purse.settle_cooperative(to_payer, to_payee)?;
        let payout = Payout {
            purse: *id,
            payer: purse.payer,
            payee: purse.payee,
            asset: purse.asset,
            settlement,
        };
        // Settled obligations leave state the moment they close.
        self.purses.remove(id);
        Ok(payout)
    }

    /// Begins a unilateral closure, opening the contestation window.
    ///
    /// The window is built by the caller, from the block being executed. Its
    /// anchor field is named `opened_at_finalized`, which is the whole C9
    /// discipline: a partition raises the ordinary height freely and cannot
    /// move the finalised tip.
    pub fn begin_unilateral(
        &mut self,
        id: &PurseId,
        caller: AccountId,
        claimed_tranches: u32,
        token: Option<&PayWordToken>,
        window: ContestationWindow,
    ) -> Result<(), PurseBookError> {
        let purse = self.purses.get_mut(id).ok_or(PurseBookError::NoSuchPurse(*id))?;
        purse.begin_unilateral(caller, claimed_tranches, token, window)?;
        Ok(())
    }

    /// Contests a pending closure with a larger token.
    ///
    /// **Anyone may do this**, party or not. That is not an oversight: R1.6
    /// makes every device of an owner a watchtower for that owner's channels,
    /// and paid third-party watchtowers are the fallback for someone with one
    /// device. Requiring the victim to object in person would mean the victim
    /// has to be awake, which is exactly the assumption C9 attacks.
    ///
    /// A dispute that does not carry a larger, genuine token simply fails.
    pub fn dispute(
        &mut self,
        id: &PurseId,
        disputed_tranches: u32,
        token: &PayWordToken,
    ) -> Result<(), PurseBookError> {
        let purse = self.purses.get_mut(id).ok_or(PurseBookError::NoSuchPurse(*id))?;
        purse.dispute(disputed_tranches, token)?;
        Ok(())
    }

    /// Settles every channel whose window has elapsed, removing them.
    ///
    /// `current_finalized_height` is a **finalised** height. Passing an ordinary
    /// one would be the C9 bug, and the window type it reaches offers no way to
    /// do it by accident.
    ///
    /// Returns the payouts in ascending channel order, so that two nodes credit
    /// the same accounts in the same sequence and compute the same state root.
    pub fn settle_elapsed(&mut self, current_finalized_height: u64) -> Vec<Payout> {
        let ready: Vec<(PurseId, Payout)> = self
            .purses
            .iter()
            .filter_map(|(id, purse)| {
                purse.settle(current_finalized_height).ok().map(|settlement| {
                    (
                        *id,
                        Payout {
                            purse: *id,
                            payer: purse.payer,
                            payee: purse.payee,
                            asset: purse.asset,
                            settlement,
                        },
                    )
                })
            })
            .collect();

        let mut payouts = Vec::with_capacity(ready.len());
        for (id, payout) in ready {
            self.purses.remove(&id);
            payouts.push(payout);
        }
        payouts
    }

    /// The digest of a channel, as stored in the state tree.
    #[must_use]
    pub fn value_hash(purse: &Purse) -> Hash {
        Hasher::new(domain::STATE_VALUE).update(&purse.to_canonical_bytes()).finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::{PurseBook, PurseBookError};
    use vanargand_bourse::payword::{PayWordPayer, PayWordToken};
    use vanargand_bourse::purse::{Purse, PurseError, PurseId, DISPUTE_WINDOW_FINALIZED_BLOCKS};
    use vanargand_crypto::hash::Hash;
    use vanargand_types::amount::Ratio;
    use vanargand_types::block::{
        BlockHeader, ContestationWindow, FinalityRung, HEADER_VERSION,
    };
    use vanargand_types::id::{AccountId, BlockId, ChainId};
    use vanargand_types::Amount;

    const CAPACITY: u32 = 1_000;

    fn account(byte: u8) -> AccountId {
        AccountId::from_hash(Hash::from_bytes([byte; 32]))
    }

    fn purse_id(byte: u8) -> PurseId {
        PurseId::from_hash(Hash::from_bytes([byte; 32]))
    }

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

    /// A contestation window anchored at a finalised height, built through the
    /// header-taking constructor a node actually uses.
    fn window(finalized: u64) -> ContestationWindow {
        ContestationWindow::open(
            &header(finalized.saturating_add(60), finalized),
            DISPUTE_WINDOW_FINALIZED_BLOCKS,
        )
    }

    fn channel(seed: u8) -> (Purse, PayWordPayer) {
        let chain =
            PayWordPayer::open(&Hash::from_bytes([seed; 32]), CAPACITY, Amount::from_ulf(10))
                .expect("a short chain");
        let purse = Purse::open(
            account(1),
            account(2),
            None,
            Amount::from_ulf(10_000),
            chain.root(),
            Amount::from_ulf(10),
            CAPACITY,
            1_000_000,
        )
        .expect("two distinct parties");
        (purse, chain)
    }

    #[test]
    fn a_cooperative_closure_pays_out_and_leaves_state() {
        let mut book = PurseBook::new();
        let (purse, _) = channel(7);
        book.open(purse_id(1), purse).expect("a fresh identifier");
        assert_eq!(book.len(), 1);

        let payout = book
            .close_cooperative(
                &purse_id(1),
                account(1),
                Amount::from_ulf(6_000),
                Amount::from_ulf(4_000),
            )
            .expect("a balanced closure");

        assert_eq!(payout.settlement.to_payer, Amount::from_ulf(6_000));
        assert_eq!(payout.settlement.to_payee, Amount::from_ulf(4_000));
        assert_eq!(payout.total(), Some(Amount::from_ulf(10_000)));
        assert!(book.is_empty(), "a settled channel stayed in state");
    }

    #[test]
    fn only_a_party_may_close_cooperatively() {
        let mut book = PurseBook::new();
        let (purse, _) = channel(7);
        book.open(purse_id(1), purse).expect("fresh");
        assert_eq!(
            book.close_cooperative(&purse_id(1), account(9), Amount::ZERO, Amount::ZERO),
            Err(PurseBookError::NotAParty(account(9)))
        );
        assert_eq!(book.len(), 1, "a refused closure removed the channel");
    }

    #[test]
    fn an_unbalanced_closure_leaves_the_channel_alone() {
        let mut book = PurseBook::new();
        let (purse, _) = channel(7);
        book.open(purse_id(1), purse).expect("fresh");
        assert!(matches!(
            book.close_cooperative(
                &purse_id(1),
                account(1),
                Amount::from_ulf(1),
                Amount::from_ulf(1)
            ),
            Err(PurseBookError::Purse(PurseError::UnbalancedSettlement { .. }))
        ));
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn a_channel_settles_by_itself_when_the_window_elapses() {
        // Nobody sends a settlement transaction. The block that notices pays.
        let mut book = PurseBook::new();
        let (purse, mut chain) = channel(7);
        book.open(purse_id(1), purse).expect("fresh");
        let token = chain.spend(40).expect("tranches remain");
        book.begin_unilateral(&purse_id(1), account(1), 40, Some(&token), window(40))
            .expect("an honest claim");

        assert!(book.settle_elapsed(40).is_empty(), "settled before the window closed");
        assert_eq!(book.len(), 1);

        let payouts = book.settle_elapsed(40 + DISPUTE_WINDOW_FINALIZED_BLOCKS);
        assert_eq!(payouts.len(), 1);
        let payout = payouts.first().copied().expect("one payout");
        assert_eq!(payout.settlement.to_payee, Amount::from_ulf(400));
        assert_eq!(payout.settlement.to_payer, Amount::from_ulf(9_600));
        assert!(book.is_empty());
    }

    #[test]
    fn a_partition_does_not_settle_anything() {
        // C9 at the ledger level: sixty thousand provisional blocks, and the
        // finalised tip has not moved, so nothing is owed to anybody yet.
        let mut book = PurseBook::new();
        let (purse, mut chain) = channel(7);
        book.open(purse_id(1), purse).expect("fresh");
        let stale = chain.spend(10).expect("tranches remain");
        book.begin_unilateral(&purse_id(1), account(1), 10, Some(&stale), window(40))
            .expect("valid claim");

        let deep_in_the_partition = header(60_100, 40);
        assert!(
            book.settle_elapsed(deep_in_the_partition.finalized_height).is_empty(),
            "a channel settled inside a partition; C9 is open"
        );
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn anyone_may_dispute_which_is_what_makes_watchtowers_possible() {
        // Requiring the victim to object in person would mean the victim has to
        // be awake, which is exactly the assumption C9 attacks.
        let mut book = PurseBook::new();
        let (purse, mut chain) = channel(7);
        book.open(purse_id(1), purse).expect("fresh");
        let stale = chain.spend(40).expect("tranches remain");
        let truth = chain.spend(360).expect("tranches remain");

        book.begin_unilateral(&purse_id(1), account(1), 40, Some(&stale), window(40))
            .expect("the stale claim is structurally valid");

        // A third party — the payee's laptop, or a paid watchtower — objects.
        book.dispute(&purse_id(1), 400, &truth).expect("a genuine larger token");

        let payouts = book.settle_elapsed(40 + DISPUTE_WINDOW_FINALIZED_BLOCKS);
        let payout = payouts.first().copied().expect("one payout");
        assert_eq!(payout.settlement.to_payee, Amount::from_ulf(10_000), "the cheat kept something");
        assert_eq!(payout.settlement.to_payer, Amount::ZERO);
    }

    #[test]
    fn a_forged_dispute_changes_nothing() {
        let mut book = PurseBook::new();
        let (purse, mut chain) = channel(7);
        book.open(purse_id(1), purse).expect("fresh");
        let token = chain.spend(40).expect("tranches remain");
        book.begin_unilateral(&purse_id(1), account(1), 40, Some(&token), window(40))
            .expect("valid");

        let forged = PayWordToken { index: 400, link: Hash::from_bytes([0xab; 32]) };
        assert!(matches!(
            book.dispute(&purse_id(1), 400, &forged),
            Err(PurseBookError::Purse(PurseError::PayWord(_)))
        ));

        let payouts = book.settle_elapsed(40 + DISPUTE_WINDOW_FINALIZED_BLOCKS);
        let payout = payouts.first().copied().expect("one payout");
        assert_eq!(payout.settlement.to_payee, Amount::from_ulf(400), "a forgery was believed");
    }

    #[test]
    fn several_channels_settle_in_identifier_order() {
        // Consensus-critical: two nodes must credit the same accounts in the
        // same sequence, or their state roots differ.
        let mut book = PurseBook::new();
        for byte in [5_u8, 1, 3] {
            let (purse, mut chain) = channel(byte);
            book.open(purse_id(byte), purse).expect("fresh");
            let token = chain.spend(1).expect("tranches remain");
            book.begin_unilateral(&purse_id(byte), account(1), 1, Some(&token), window(40))
                .expect("valid");
        }

        let payouts = book.settle_elapsed(40 + DISPUTE_WINDOW_FINALIZED_BLOCKS);
        let order: Vec<PurseId> = payouts.iter().map(|payout| payout.purse).collect();
        let mut expected = order.clone();
        expected.sort_unstable();
        assert_eq!(order, expected);
        assert!(book.is_empty());
    }

    #[test]
    fn an_open_channel_is_never_silently_replaced() {
        let mut book = PurseBook::new();
        let (first, _) = channel(7);
        let (second, _) = channel(8);
        book.open(purse_id(1), first).expect("fresh");
        assert_eq!(
            book.open(purse_id(1), second),
            Err(PurseBookError::PurseExists(purse_id(1)))
        );
    }

    #[test]
    fn operations_on_an_unknown_channel_are_refused() {
        let mut book = PurseBook::new();
        let token = PayWordToken { index: 1, link: Hash::ZERO };
        assert_eq!(
            book.dispute(&purse_id(1), 1, &token),
            Err(PurseBookError::NoSuchPurse(purse_id(1)))
        );
        assert_eq!(
            book.begin_unilateral(&purse_id(1), account(1), 0, None, window(1)),
            Err(PurseBookError::NoSuchPurse(purse_id(1)))
        );
        assert_eq!(
            book.close_cooperative(&purse_id(1), account(1), Amount::ZERO, Amount::ZERO),
            Err(PurseBookError::NoSuchPurse(purse_id(1)))
        );
    }
}
