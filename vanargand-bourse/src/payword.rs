// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! PayWord: the off-chain half of a channel.
//!
//! Rivest and Shamir, 1997, adopted unchanged by R2 — which is the point worth
//! keeping in view. R2's note on it is a design principle in miniature:
//!
//! > La solution éprouvée est si bien adaptée que l'innovation est inutile.
//!
//! # What it costs
//!
//! One ML-DSA signature opens the slate, committing to the root of a hash
//! chain. Each tranche afterwards is paid by revealing **32 bytes**, verified
//! in one hash. Settlement signs once more.
//!
//! Against 2420 bytes and a lattice verification per micro-payment, that is the
//! difference between "pay per megabyte for a shared connection" being a design
//! and being a slide. A phone on a train buying connectivity from three
//! passengers is sending 32 bytes per tranche, not two and a half kilobytes.
//!
//! # Direction
//!
//! Hashing moves **towards the root**; revealing moves **away from it**. The
//! payer seals the chain and walks outward, one link per tranche. The payee
//! holds the last link it received and walks any new one forward until it
//! matches. Getting this backwards is the classic mistake, so the types are
//! named for their roles rather than for the direction.

use core::fmt;

use vanargand_crypto::chain::{ChainCursor, HashChain, MAX_CHAIN_LEN};
use vanargand_crypto::hash::{domain, Hash};
use vanargand_types::codec::{CodecError, Decode, Decoder, Encode, Encoder};
use vanargand_types::Amount;

/// Longest PayWord chain a channel may commit to.
///
/// 65 536 tranches. At 64 KiB a tranche that is four gibibytes of gateway
/// traffic, which is a long train journey; at a hundredth of a unit a tranche
/// it is 655 units of value. Longer chains are possible but should be a
/// deliberate act with their own memory budget: generating one costs 32 bytes
/// per link up front.
pub const MAX_TRANCHES: u32 = MAX_CHAIN_LEN;

/// A payment: the *i*-th link of the chain.
///
/// Thirty-two bytes and an index. The index is not redundant — without it a
/// verifier walking from the root cannot tell "this is tranche 40" from "this
/// is tranche 41 and I should charge for one more".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayWordToken {
    /// How many tranches this token pays for, counting from the channel's
    /// opening.
    pub index: u32,
    /// The revealed link.
    pub link: Hash,
}

impl Encode for PayWordToken {
    fn encode(&self, out: &mut Encoder) {
        out.write_varint(u64::from(self.index));
        self.link.encode(out);
    }
}

impl Decode for PayWordToken {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let index = input.read_varint_u32()?;
        if index > MAX_TRANCHES {
            return Err(CodecError::Invalid { reason: "payword index beyond the maximum chain" });
        }
        Ok(Self { index, link: Hash::decode(input)? })
    }
}

/// Why a PayWord operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PayWordError {
    /// A chain longer than [`MAX_TRANCHES`] was requested.
    ChainTooLong(u32),
    /// The chain has no tranches left.
    Exhausted {
        /// How many the chain holds.
        capacity: u32,
        /// How many have been spent.
        spent: u32,
    },
    /// The token did not hash forward to the value it should have.
    ///
    /// Covers both a forgery and a **replay**: re-presenting an already-spent
    /// token fails here, because the cursor has already moved past it. A payee
    /// that accepted a replay would be paid twice for one tranche and would
    /// settle for less than it was owed.
    BadToken {
        /// The index the token claimed.
        index: u32,
    },
    /// The token's index does not match how far it actually is from the value
    /// being verified against.
    ///
    /// A token that verifies but claims the wrong index is an attempt to be
    /// charged for fewer tranches than were spent.
    IndexMismatch {
        /// What the token claimed.
        claimed: u32,
        /// What the walk actually found.
        actual: u32,
    },
    /// Value arithmetic overflowed.
    Overflow,
}

impl fmt::Display for PayWordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChainTooLong(length) => {
                write!(f, "{length} tranches exceeds the maximum of {MAX_TRANCHES}")
            }
            Self::Exhausted { capacity, spent } => {
                write!(f, "the chain holds {capacity} tranches and {spent} are spent")
            }
            Self::BadToken { index } => write!(f, "token {index} did not verify"),
            Self::IndexMismatch { claimed, actual } => {
                write!(f, "token claims tranche {claimed} but is tranche {actual}")
            }
            Self::Overflow => write!(f, "value arithmetic overflowed"),
        }
    }
}

impl std::error::Error for PayWordError {}

/// Verifies a token against a channel's committed root.
///
/// Walks the token forward `token.index` times and checks that it arrives at
/// the root — and that it takes exactly that many steps, which is what stops a
/// payer claiming tranche 5 while presenting the link for tranche 40.
///
/// Costs `token.index` hashes. That is why [`MAX_TRANCHES`] exists: without a
/// bound, a claim of four billion tranches is a denial of service against every
/// node that validates the closing transaction (A6).
pub fn verify_against_root(root: &Hash, token: &PayWordToken) -> Result<(), PayWordError> {
    if token.index == 0 || token.index > MAX_TRANCHES {
        return Err(PayWordError::BadToken { index: token.index });
    }
    let mut cursor = ChainCursor::new(domain::PAYWORD, *root, MAX_TRANCHES);
    let steps = cursor
        .advance(&token.link)
        .map_err(|_| PayWordError::BadToken { index: token.index })?;
    if steps != token.index {
        return Err(PayWordError::IndexMismatch { claimed: token.index, actual: steps });
    }
    Ok(())
}

/// The value of `tranches` tranches.
pub fn value_of(tranches: u32, tranche_value: Amount) -> Result<Amount, PayWordError> {
    tranche_value.checked_mul(u64::from(tranches)).ok_or(PayWordError::Overflow)
}

/// The payer's half: the sealed chain, and how far along it we are.
///
/// Holds secret material — every unrevealed link is a payment nobody has made
/// yet — so it is never encoded and never leaves the wallet.
#[derive(Debug, Clone)]
pub struct PayWordPayer {
    chain: HashChain,
    spent: u32,
    tranche_value: Amount,
}

impl PayWordPayer {
    /// Seals a chain of `tranches` links from `seed`.
    ///
    /// The seed comes from the key hierarchy at
    /// `vanargand_crypto::derive::DerivationPath::payword(channel_index)`, so
    /// that two channels never share a chain. Sharing one would let the second
    /// payee spend the first payee's tokens, and deriving per channel makes
    /// that a bug somebody has to write on purpose.
    pub fn open(
        seed: &Hash,
        tranches: u32,
        tranche_value: Amount,
    ) -> Result<Self, PayWordError> {
        if tranches > MAX_TRANCHES {
            return Err(PayWordError::ChainTooLong(tranches));
        }
        let chain = HashChain::generate(domain::PAYWORD, seed, tranches)
            .map_err(|_| PayWordError::ChainTooLong(tranches))?;
        Ok(Self { chain, spent: 0, tranche_value })
    }

    /// The root, which goes on chain when the channel opens.
    #[must_use]
    pub fn root(&self) -> Hash {
        self.chain.root()
    }

    /// How many tranches the chain holds.
    #[must_use]
    pub fn capacity(&self) -> u32 {
        self.chain.len()
    }

    /// How many have been spent.
    #[must_use]
    pub fn spent(&self) -> u32 {
        self.spent
    }

    /// How many remain.
    #[must_use]
    pub fn remaining(&self) -> u32 {
        self.capacity().saturating_sub(self.spent)
    }

    /// The value spent so far.
    pub fn spent_value(&self) -> Result<Amount, PayWordError> {
        value_of(self.spent, self.tranche_value)
    }

    /// Spends `tranches` more, returning the token that pays for all of them.
    ///
    /// One token settles every tranche up to its index, so a payer that owes
    /// forty tranches sends one 32-byte value rather than forty. That is also
    /// why a payee can miss messages without anything being lost.
    pub fn spend(&mut self, tranches: u32) -> Result<PayWordToken, PayWordError> {
        let next = self.spent.checked_add(tranches).ok_or(PayWordError::Overflow)?;
        if next > self.capacity() {
            return Err(PayWordError::Exhausted {
                capacity: self.capacity(),
                spent: self.spent,
            });
        }
        let link = self
            .chain
            .reveal(next)
            .ok_or(PayWordError::Exhausted { capacity: self.capacity(), spent: self.spent })?;
        self.spent = next;
        Ok(PayWordToken { index: next, link })
    }

    /// The token for everything spent so far, without spending more.
    #[must_use]
    pub fn latest(&self) -> Option<PayWordToken> {
        self.chain.reveal(self.spent).map(|link| PayWordToken { index: self.spent, link })
    }
}

/// The payee's half: what has been received, and what it is worth.
///
/// Holds no secret. A watchtower keeps one of these on the payee's behalf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayWordPayee {
    root: Hash,
    cursor: ChainCursor,
    accepted: u32,
    capacity: u32,
    tranche_value: Amount,
    best: Option<PayWordToken>,
}

impl PayWordPayee {
    /// Starts tracking a channel from its published root.
    #[must_use]
    pub fn new(root: Hash, capacity: u32, tranche_value: Amount) -> Self {
        let bounded = capacity.min(MAX_TRANCHES);
        Self {
            root,
            cursor: ChainCursor::new(domain::PAYWORD, root, bounded),
            accepted: 0,
            capacity: bounded,
            tranche_value,
            best: None,
        }
    }

    /// The committed root.
    #[must_use]
    pub fn root(&self) -> Hash {
        self.root
    }

    /// How many tranches have been accepted.
    #[must_use]
    pub fn accepted(&self) -> u32 {
        self.accepted
    }

    /// The value earned so far.
    pub fn earned(&self) -> Result<Amount, PayWordError> {
        value_of(self.accepted, self.tranche_value)
    }

    /// The best token seen, which is the evidence to settle or to dispute with.
    #[must_use]
    pub fn best(&self) -> Option<PayWordToken> {
        self.best
    }

    /// Accepts a token, returning the value it added.
    ///
    /// Returns an error for a forged token, for a replay, and for a token whose
    /// index does not match the distance actually walked. A payee that accepted
    /// any of the three would settle for less than it is owed.
    pub fn accept(&mut self, token: &PayWordToken) -> Result<Amount, PayWordError> {
        if token.index == 0 || token.index > self.capacity {
            return Err(PayWordError::BadToken { index: token.index });
        }

        // Probe before committing. `ChainCursor::advance` moves on success, so
        // checking the index *after* advancing would leave the cursor ahead of
        // `accepted` on a rejected token — and a hostile payer could
        // desynchronise the payee's accounting at will by sending one token
        // with a deliberately wrong index. The extra walk is bounded by the
        // capacity and costs one hash per tranche.
        let steps = self
            .cursor
            .would_advance(&token.link)
            .map_err(|_| PayWordError::BadToken { index: token.index })?;

        let expected = token
            .index
            .checked_sub(self.accepted)
            .ok_or(PayWordError::BadToken { index: token.index })?;
        if steps != expected {
            return Err(PayWordError::IndexMismatch { claimed: token.index, actual: steps });
        }

        self.cursor
            .advance(&token.link)
            .map_err(|_| PayWordError::BadToken { index: token.index })?;
        self.accepted = token.index;
        self.best = Some(*token);
        value_of(steps, self.tranche_value)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        value_of, verify_against_root, PayWordError, PayWordPayee, PayWordPayer, PayWordToken,
        MAX_TRANCHES,
    };
    use vanargand_crypto::hash::Hash;
    use vanargand_types::codec::{Decode, Encode};
    use vanargand_types::Amount;

    fn seed(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    fn tranche() -> Amount {
        Amount::from_ulf(10)
    }

    fn channel(tranches: u32) -> (PayWordPayer, PayWordPayee) {
        let payer = PayWordPayer::open(&seed(1), tranches, tranche()).expect("a short chain");
        let payee = PayWordPayee::new(payer.root(), tranches, tranche());
        (payer, payee)
    }

    #[test]
    fn a_tranche_costs_thirty_two_bytes_on_the_wire() {
        // The number the whole scheme exists for: 32 bytes and an index,
        // against a 2420-byte ML-DSA signature per micro-payment.
        let (mut payer, _) = channel(100);
        let token = payer.spend(1).expect("the chain has tranches");
        let encoded = token.to_canonical_bytes();
        assert_eq!(encoded.len(), 33, "one varint index plus the link");
        assert_eq!(PayWordToken::from_canonical_bytes(&encoded), Ok(token));
    }

    #[test]
    fn paying_one_tranche_at_a_time_works() {
        let (mut payer, mut payee) = channel(20);
        for index in 1..=20_u32 {
            let token = payer.spend(1).expect("tranches remain");
            assert_eq!(token.index, index);
            assert_eq!(payee.accept(&token), Ok(tranche()));
            assert_eq!(payee.accepted(), index);
        }
        assert_eq!(payee.earned(), Ok(Amount::from_ulf(200)));
        assert_eq!(payer.remaining(), 0);
    }

    #[test]
    fn one_token_settles_every_tranche_below_it() {
        // Why a payee can miss messages without losing anything: the newest
        // token pays for all of them.
        let (mut payer, mut payee) = channel(100);
        let _ = payer.spend(1).expect("tranches remain");
        let _ = payer.spend(1).expect("tranches remain");
        let token = payer.spend(38).expect("tranches remain");
        assert_eq!(token.index, 40);

        // The payee never saw the first two tokens.
        assert_eq!(payee.accept(&token), Ok(Amount::from_ulf(400)));
        assert_eq!(payee.accepted(), 40);
    }

    #[test]
    fn a_replayed_token_is_refused() {
        // Accepting one would pay the payee twice for a single tranche, and it
        // would settle for less than it was owed.
        let (mut payer, mut payee) = channel(20);
        let token = payer.spend(5).expect("tranches remain");
        assert_eq!(payee.accept(&token), Ok(Amount::from_ulf(50)));
        assert_eq!(payee.accept(&token), Err(PayWordError::BadToken { index: 5 }));
        assert_eq!(payee.accepted(), 5, "a refused token moved the accounting");
    }

    #[test]
    fn an_older_token_is_refused() {
        let (mut payer, mut payee) = channel(20);
        let early = payer.spend(3).expect("tranches remain");
        let later = payer.spend(4).expect("tranches remain");
        assert!(payee.accept(&later).is_ok());
        assert_eq!(payee.accept(&early), Err(PayWordError::BadToken { index: 3 }));
    }

    #[test]
    fn a_forged_token_is_refused() {
        let (_, mut payee) = channel(20);
        let forged = PayWordToken { index: 1, link: Hash::from_bytes([0xab; 32]) };
        assert_eq!(payee.accept(&forged), Err(PayWordError::BadToken { index: 1 }));
    }

    #[test]
    fn a_token_claiming_the_wrong_index_is_refused() {
        // A payer presenting the link for tranche 40 while claiming tranche 5
        // is asking to be charged for 5. The index is part of the token so
        // that this is detectable at all.
        let (mut payer, mut payee) = channel(100);
        let genuine = payer.spend(40).expect("tranches remain");
        let understated = PayWordToken { index: 5, link: genuine.link };

        let before = payee.clone();
        assert_eq!(
            payee.accept(&understated),
            Err(PayWordError::IndexMismatch { claimed: 5, actual: 40 })
        );
        assert_eq!(
            payee, before,
            "a rejected token moved the payee's cursor; a hostile payer could \
             desynchronise the accounting at will"
        );
        // And the genuine token is still accepted afterwards.
        assert_eq!(payee.accept(&genuine), Ok(Amount::from_ulf(400)));

        assert_eq!(
            verify_against_root(&payer.root(), &understated),
            Err(PayWordError::IndexMismatch { claimed: 5, actual: 40 })
        );
        // And the genuine one is fine.
        assert_eq!(verify_against_root(&payer.root(), &genuine), Ok(()));
    }

    #[test]
    fn a_token_from_another_channel_is_refused() {
        // Two channels must never share a chain: the second payee could
        // otherwise spend the first payee's tokens. Deriving the seed per
        // channel is what makes this a bug somebody has to write on purpose.
        let first = PayWordPayer::open(&seed(1), 20, tranche()).expect("a short chain");
        let mut second_payee = PayWordPayee::new(
            PayWordPayer::open(&seed(2), 20, tranche()).expect("a short chain").root(),
            20,
            tranche(),
        );
        let mut payer = first;
        let token = payer.spend(1).expect("tranches remain");
        assert_eq!(second_payee.accept(&token), Err(PayWordError::BadToken { index: 1 }));
    }

    #[test]
    fn the_chain_cannot_be_overspent() {
        let (mut payer, _) = channel(5);
        assert!(payer.spend(5).is_ok());
        assert_eq!(
            payer.spend(1),
            Err(PayWordError::Exhausted { capacity: 5, spent: 5 })
        );
        assert_eq!(payer.remaining(), 0);
    }

    #[test]
    fn spending_more_than_the_chain_holds_changes_nothing() {
        let (mut payer, _) = channel(5);
        assert!(payer.spend(6).is_err());
        assert_eq!(payer.spent(), 0, "a refused spend moved the payer's counter");
        assert!(payer.spend(5).is_ok());
    }

    #[test]
    fn verification_against_the_root_rejects_index_zero() {
        // Index zero is the root itself, which is public. Accepting it would
        // let anyone "pay" nothing and claim to have paid.
        let (payer, _) = channel(10);
        let root_as_token = PayWordToken { index: 0, link: payer.root() };
        assert_eq!(
            verify_against_root(&payer.root(), &root_as_token),
            Err(PayWordError::BadToken { index: 0 })
        );
    }

    #[test]
    fn verification_rejects_an_index_beyond_the_bound() {
        // A6: without the bound, a claim of four billion tranches is a denial
        // of service against every node validating the closing transaction.
        let (payer, _) = channel(10);
        let absurd =
            PayWordToken { index: MAX_TRANCHES.saturating_add(1), link: payer.root() };
        assert_eq!(
            verify_against_root(&payer.root(), &absurd),
            Err(PayWordError::BadToken { index: MAX_TRANCHES + 1 })
        );
    }

    #[test]
    fn an_over_long_index_is_rejected_on_the_wire() {
        let mut encoder = vanargand_types::codec::Encoder::new();
        encoder.write_varint(u64::from(MAX_TRANCHES) + 1);
        encoder.write_raw(&[0_u8; 32]);
        assert!(PayWordToken::from_canonical_bytes(&encoder.finish()).is_err());
    }

    #[test]
    fn an_over_long_chain_is_refused() {
        assert!(PayWordPayer::open(&seed(1), MAX_TRANCHES + 1, tranche()).is_err());
    }

    #[test]
    fn the_latest_token_does_not_spend() {
        let (mut payer, _) = channel(10);
        let _ = payer.spend(3).expect("tranches remain");
        let latest = payer.latest().expect("something has been spent");
        assert_eq!(latest.index, 3);
        assert_eq!(payer.spent(), 3, "reading the latest token spent one");
    }

    #[test]
    fn values_are_computed_without_overflow() {
        assert_eq!(value_of(0, tranche()), Ok(Amount::ZERO));
        assert_eq!(value_of(10, tranche()), Ok(Amount::from_ulf(100)));
        assert_eq!(
            value_of(MAX_TRANCHES, Amount::from_ulf(u64::MAX)),
            Err(PayWordError::Overflow)
        );
    }

    #[test]
    fn the_payee_tracks_the_best_token_for_settlement() {
        let (mut payer, mut payee) = channel(50);
        assert_eq!(payee.best(), None);
        let first = payer.spend(10).expect("tranches remain");
        payee.accept(&first).expect("valid");
        let second = payer.spend(15).expect("tranches remain");
        payee.accept(&second).expect("valid");
        assert_eq!(payee.best(), Some(second));
        assert_eq!(payee.accepted(), 25);
    }
}
