// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The watchtower: what objects to a stale closure while the victim sleeps.
//!
//! A contestation window is only worth something if somebody is awake for it.
//! R1.6 makes that structural rather than a service you remember to buy:
//!
//! > chaque appareil du propriétaire est automatiquement gardien de son
//! > identité et guetteur de ses bourses
//!
//! So the ordinary case is that the victim's own laptop objects. A paid
//! third-party watchtower is the fallback for someone who owns one device.
//!
//! # What a watchtower has to hold
//!
//! Almost nothing: the best token it has seen per channel, which is 32 bytes
//! and an index. It needs no secret, so it is safe to replicate across every
//! device an owner has, and safe to hand to a paid third party — the worst a
//! dishonest watchtower can do is fail to act, never steal.
//!
//! That property is not incidental. It is what makes "every device is a
//! watchtower" a design rather than a slogan: a watchtower that needed a
//! signing key would mean the key living on every device, which is the thing
//! the root-key hierarchy exists to avoid.

use std::collections::BTreeMap;

use vanargand_types::id::AccountId;

use crate::payword::{PayWordToken, MAX_TRANCHES};
use crate::purse::{Purse, PurseId};

/// What a watchtower should do about a channel right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing is happening, or the pending closure is honest.
    Quiet,
    /// A closure understates what was spent. Publish this token.
    Dispute {
        /// The true number of tranches.
        tranches: u32,
        /// The token that proves it.
        token: PayWordToken,
    },
    /// A closure is pending and this watchtower has nothing better than the
    /// claim.
    ///
    /// Reported separately from [`Verdict::Quiet`] because it is the case where
    /// a watchtower that has fallen behind should say so loudly rather than
    /// stay silent: it may simply have missed the newest tokens.
    NothingBetter {
        /// What the closure claims.
        claimed: u32,
        /// The best this watchtower has.
        held: u32,
    },
}

/// A store of the best token seen per channel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Watchtower {
    owner: Option<AccountId>,
    best: BTreeMap<PurseId, PayWordToken>,
}

impl Watchtower {
    /// A watchtower watching nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A watchtower acting for `owner`.
    #[must_use]
    pub fn for_owner(owner: AccountId) -> Self {
        Self { owner: Some(owner), best: BTreeMap::new() }
    }

    /// Whose channels this watches, if it was told.
    #[must_use]
    pub fn owner(&self) -> Option<AccountId> {
        self.owner
    }

    /// How many channels are being watched.
    #[must_use]
    pub fn len(&self) -> usize {
        self.best.len()
    }

    /// Whether it is watching nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.best.is_empty()
    }

    /// Records a token, keeping it only if it beats what is already held.
    ///
    /// Returns `true` if the store moved forward.
    ///
    /// **Does not verify the token.** A watchtower is handed tokens by the
    /// payee it works for, which has already verified them against the chain
    /// root; re-verifying would mean walking the chain on every tranche, which
    /// is the cost PayWord exists to avoid. A watchtower given a forged token
    /// publishes a dispute that simply fails, costing it a fee and nobody else
    /// anything.
    pub fn observe(&mut self, purse: PurseId, token: PayWordToken) -> bool {
        if token.index == 0 || token.index > MAX_TRANCHES {
            return false;
        }
        match self.best.get(&purse) {
            Some(held) if held.index >= token.index => false,
            _ => {
                self.best.insert(purse, token);
                true
            }
        }
    }

    /// The best token held for a channel.
    #[must_use]
    pub fn best(&self, purse: &PurseId) -> Option<PayWordToken> {
        self.best.get(purse).copied()
    }

    /// Forgets a channel, once it has settled.
    ///
    /// Settled obligations leave state, and that applies to a watchtower's
    /// memory as much as to the ledger's.
    pub fn forget(&mut self, purse: &PurseId) -> Option<PayWordToken> {
        self.best.remove(purse)
    }

    /// Decides what to do about a channel as the ledger currently holds it.
    #[must_use]
    pub fn inspect(&self, purse_id: &PurseId, purse: &Purse) -> Verdict {
        let Some(pending) = purse.closing else {
            return Verdict::Quiet;
        };
        let Some(held) = self.best(purse_id) else {
            return Verdict::NothingBetter { claimed: pending.claimed_tranches, held: 0 };
        };
        if held.index > pending.claimed_tranches {
            Verdict::Dispute { tranches: held.index, token: held }
        } else {
            Verdict::NothingBetter { claimed: pending.claimed_tranches, held: held.index }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Verdict, Watchtower};
    use crate::payword::{PayWordPayer, PayWordToken};
    use crate::purse::{Purse, PurseId};
    use vanargand_crypto::hash::Hash;
    use vanargand_types::amount::Ratio;
    use vanargand_types::block::{
        BlockHeader, ContestationWindow, FinalityRung, HEADER_VERSION,
    };
    use vanargand_types::id::{AccountId, BlockId, ChainId};
    use vanargand_types::Amount;

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
            crate::purse::DISPUTE_WINDOW_FINALIZED_BLOCKS,
        )
    }

    fn channel() -> (Purse, PayWordPayer) {
        let chain = PayWordPayer::open(&Hash::from_bytes([7; 32]), 1_000, Amount::from_ulf(10))
            .expect("a short chain");
        let purse = Purse::open(
            account(1),
            account(2),
            None,
            Amount::from_ulf(10_000),
            chain.root(),
            Amount::from_ulf(10),
            1_000,
            1_000_000,
        )
        .expect("two distinct parties");
        (purse, chain)
    }

    #[test]
    fn a_watchtower_keeps_only_the_newest_token() {
        let mut tower = Watchtower::new();
        let (_, mut chain) = channel();
        let early = chain.spend(10).expect("tranches remain");
        let later = chain.spend(30).expect("tranches remain");

        assert!(tower.observe(purse_id(1), early));
        assert!(tower.observe(purse_id(1), later));
        assert_eq!(tower.best(&purse_id(1)), Some(later));

        // An older one does not move the store backwards.
        assert!(!tower.observe(purse_id(1), early));
        assert_eq!(tower.best(&purse_id(1)), Some(later));
        // Nor does the same one twice.
        assert!(!tower.observe(purse_id(1), later));
    }

    #[test]
    fn a_watchtower_ignores_a_meaningless_token() {
        let mut tower = Watchtower::new();
        let zero = PayWordToken { index: 0, link: Hash::ZERO };
        assert!(!tower.observe(purse_id(1), zero));
        assert!(tower.is_empty());
    }

    #[test]
    fn a_quiet_channel_needs_no_action() {
        let tower = Watchtower::new();
        let (purse, _) = channel();
        assert_eq!(tower.inspect(&purse_id(1), &purse), Verdict::Quiet);
    }

    #[test]
    fn a_stale_closure_produces_a_dispute() {
        // The scenario the whole mechanism exists for: the payer closes
        // claiming forty of the four hundred tranches it spent, and the
        // victim's own laptop objects.
        let (mut purse, mut chain) = channel();
        let stale = chain.spend(40).expect("tranches remain");
        let truth = chain.spend(360).expect("tranches remain");

        let mut tower = Watchtower::for_owner(account(2));
        tower.observe(purse_id(1), truth);

        purse
            .begin_unilateral(account(1), 40, Some(&stale), window(40))
            .expect("the stale claim is structurally valid");

        let verdict = tower.inspect(&purse_id(1), &purse);
        assert_eq!(verdict, Verdict::Dispute { tranches: 400, token: truth });

        // And acting on it overturns the closure.
        let Verdict::Dispute { tranches, token } = verdict else {
            panic!("expected a dispute");
        };
        purse.dispute(tranches, &token).expect("the watchtower's token is genuine");
    }

    #[test]
    fn an_honest_closure_draws_no_objection() {
        let (mut purse, mut chain) = channel();
        let token = chain.spend(40).expect("tranches remain");

        let mut tower = Watchtower::for_owner(account(2));
        tower.observe(purse_id(1), token);
        purse.begin_unilateral(account(1), 40, Some(&token), window(40)).expect("valid");

        assert_eq!(
            tower.inspect(&purse_id(1), &purse),
            Verdict::NothingBetter { claimed: 40, held: 40 }
        );
    }

    #[test]
    fn a_watchtower_that_has_fallen_behind_says_so() {
        // Distinguished from "quiet" on purpose: a watchtower holding less than
        // the claim may simply have missed the newest tokens, and the operator
        // should hear about it rather than be reassured.
        let (mut purse, mut chain) = channel();
        let old = chain.spend(10).expect("tranches remain");
        let newer = chain.spend(30).expect("tranches remain");

        let mut tower = Watchtower::for_owner(account(2));
        tower.observe(purse_id(1), old);
        purse.begin_unilateral(account(1), 40, Some(&newer), window(40)).expect("valid");

        assert_eq!(
            tower.inspect(&purse_id(1), &purse),
            Verdict::NothingBetter { claimed: 40, held: 10 }
        );

        let empty = Watchtower::new();
        assert_eq!(
            empty.inspect(&purse_id(1), &purse),
            Verdict::NothingBetter { claimed: 40, held: 0 }
        );
    }

    #[test]
    fn channels_are_watched_independently() {
        let mut tower = Watchtower::new();
        let (_, mut first) = channel();
        let token = first.spend(5).expect("tranches remain");
        tower.observe(purse_id(1), token);

        assert_eq!(tower.best(&purse_id(1)), Some(token));
        assert_eq!(tower.best(&purse_id(2)), None);
        assert_eq!(tower.len(), 1);
    }

    #[test]
    fn a_settled_channel_is_forgotten() {
        let mut tower = Watchtower::new();
        let (_, mut chain) = channel();
        let token = chain.spend(5).expect("tranches remain");
        tower.observe(purse_id(1), token);

        assert_eq!(tower.forget(&purse_id(1)), Some(token));
        assert!(tower.is_empty());
        assert_eq!(tower.forget(&purse_id(1)), None);
    }

    #[test]
    fn a_watchtower_holds_no_secret() {
        // The property that makes "every device is a watchtower" a design
        // rather than a slogan. Cloning one is safe, which is the whole point:
        // a watchtower needing a signing key would put that key on every
        // device.
        let mut tower = Watchtower::for_owner(account(2));
        let (_, mut chain) = channel();
        tower.observe(purse_id(1), chain.spend(5).expect("tranches remain"));
        let replica = tower.clone();
        assert_eq!(replica, tower);
        assert_eq!(replica.owner(), Some(account(2)));
    }
}
