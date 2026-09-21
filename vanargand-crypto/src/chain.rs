// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hash chains.
//!
//! Two mechanisms in Vanargand are the same construction read in opposite
//! directions, and they are specified together in `spec/draft/02-hashing.md` §4
//! for one reason: they share a failure mode, and it is easier to see side by
//! side.
//!
//! - **The commitment chain (A4).** A validator seals a chain root when it
//!   bonds. Proposing a block reveals the next link. The proposer cannot choose
//!   the value — the chain was sealed in advance — and cannot withhold it
//!   without forfeiting the proposal. That is why R2 was able to remove the
//!   slashing penalty for non-revelation: withholding and crashing produce the
//!   same observable, and Vanargand only slashes faults that carry their own
//!   proof.
//!
//! - **PayWord.** Rivest and Shamir, 1997, adopted unchanged by R2. The payer
//!   seals a chain when opening a channel; paying for the *i*-th tranche means
//!   sending the *i*-th link, 32 bytes, verified in one hash. It replaces a
//!   2420-byte ML-DSA signature per micro-payment with 32 bytes, which is what
//!   makes paying per megabyte for a shared connection affordable.
//!
//! # The shared failure mode
//!
//! A chain must never be used twice. Two channels sharing a chain means the
//! second payee can spend the first payee's tokens; two bond periods sharing a
//! chain means the randomness for the second is known before it starts. The
//! defence is that seeds come from the key hierarchy at a path that includes
//! the channel or bond index ([`crate::derive`]), so reuse has to be written on
//! purpose.

use crate::error::CryptoError;
use crate::hash::{hash, Context, Hash};

/// The largest chain this crate will build in one allocation.
///
/// A PayWord chain of 65 536 links at, say, 64 KiB per tranche covers 4 GiB of
/// gateway traffic, which is a long train journey. Building a longer one is
/// possible but should be a deliberate act with its own memory budget, not a
/// slip of a caller's arithmetic.
pub const MAX_CHAIN_LEN: u32 = 65_536;

/// Applies one link of a chain: `H[context](next)`.
///
/// The direction is worth stating, because it is the one thing people get
/// backwards: hashing moves *towards the root*, revealing moves *away from it*.
#[must_use]
pub fn link(context: Context, next: &Hash) -> Hash {
    hash(context, next.as_bytes())
}

/// A sealed hash chain, held by the party that generated it.
///
/// Index 0 is the root — the value published on chain. Index `len` is the
/// seed. Revealing proceeds 1, 2, 3, …, towards the seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashChain {
    context: Context,
    links: Vec<Hash>,
}

impl HashChain {
    /// Builds a chain of `length` links from `seed`.
    ///
    /// Costs `length` hashes and `32 * (length + 1)` bytes. A chain of length
    /// zero is the degenerate case where the root *is* the seed; it is legal,
    /// and it is what an exhausted chain looks like.
    pub fn generate(context: Context, seed: &Hash, length: u32) -> Result<Self, CryptoError> {
        if length > MAX_CHAIN_LEN {
            return Err(CryptoError::BadChainLink { max_steps: MAX_CHAIN_LEN });
        }
        let count = usize::try_from(length)
            .map_err(|_| CryptoError::BadChainLink { max_steps: MAX_CHAIN_LEN })?;
        let mut links = vec![Hash::ZERO; count.saturating_add(1)];
        if let Some(last) = links.last_mut() {
            *last = *seed;
        }
        // Walk down from the seed to the root, each link hashing its successor.
        for index in (0..count).rev() {
            let Some(next) = links.get(index.saturating_add(1)).copied() else {
                return Err(CryptoError::BadChainLink { max_steps: MAX_CHAIN_LEN });
            };
            let Some(slot) = links.get_mut(index) else {
                return Err(CryptoError::BadChainLink { max_steps: MAX_CHAIN_LEN });
            };
            *slot = link(context, &next);
        }
        Ok(Self { context, links })
    }

    /// The value published on chain when the chain is sealed.
    #[must_use]
    pub fn root(&self) -> Hash {
        self.links.first().copied().unwrap_or(Hash::ZERO)
    }

    /// Number of links, i.e. how many reveals the chain can support.
    #[must_use]
    pub fn len(&self) -> u32 {
        // `links` holds `length + 1` entries and `length <= MAX_CHAIN_LEN`, so
        // this conversion cannot fail; saturating rather than unwrapping keeps
        // the no-panic rule absolute.
        u32::try_from(self.links.len().saturating_sub(1)).unwrap_or(u32::MAX)
    }

    /// Whether the chain has no links left to reveal.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The domain this chain was built in.
    #[must_use]
    pub fn context(&self) -> Context {
        self.context
    }

    /// The `index`-th reveal, where index 1 is the first.
    ///
    /// Returns `None` past the end of the chain rather than wrapping or
    /// panicking: an exhausted chain is an ordinary operational state — a
    /// channel that has spent its last tranche — not an error condition.
    #[must_use]
    pub fn reveal(&self, index: u32) -> Option<Hash> {
        let index = usize::try_from(index).ok()?;
        if index == 0 {
            return None;
        }
        self.links.get(index).copied()
    }
}

/// The verifier's half: the last value seen, and how far it will walk forward.
///
/// Holds no secret. A watchtower, a payee or a consensus node keeps one of
/// these per chain it is tracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainCursor {
    context: Context,
    committed: Hash,
    consumed: u32,
    max_steps: u32,
}

impl ChainCursor {
    /// Starts tracking a chain from its published root.
    #[must_use]
    pub fn new(context: Context, root: Hash, max_steps: u32) -> Self {
        Self { context, committed: root, consumed: 0, max_steps }
    }

    /// The value a reveal must hash forward to.
    #[must_use]
    pub fn committed(&self) -> Hash {
        self.committed
    }

    /// How many links have been consumed so far.
    #[must_use]
    pub fn consumed(&self) -> u32 {
        self.consumed
    }

    /// Checks a reveal and advances the cursor.
    ///
    /// Returns how many links the reveal covered: 1 for the next link in
    /// sequence, more when the counterparty skipped ahead — which is normal,
    /// since a PayWord payer sends only the newest token and a validator may
    /// have missed epochs.
    ///
    /// The walk is bounded by `max_steps`. An unbounded "hash until it matches"
    /// is a CPU exhaustion vector: a peer sends a random 32 bytes and the node
    /// hashes forever (A6). The bound is why this returns a `Result` at all.
    pub fn advance(&mut self, reveal: &Hash) -> Result<u32, CryptoError> {
        let mut current = *reveal;
        let mut steps: u32 = 0;
        while steps < self.max_steps {
            current = link(self.context, &current);
            steps = steps.saturating_add(1);
            if current == self.committed {
                self.committed = *reveal;
                self.consumed = self.consumed.saturating_add(steps);
                return Ok(steps);
            }
        }
        Err(CryptoError::BadChainLink { max_steps: self.max_steps })
    }

    /// Checks a reveal without advancing.
    ///
    /// For a watchtower deciding whether a token it was handed is worth acting
    /// on before it commits to remembering it.
    pub fn would_advance(&self, reveal: &Hash) -> Result<u32, CryptoError> {
        let mut probe = self.clone();
        probe.advance(reveal)
    }
}

#[cfg(test)]
mod tests {
    use super::{link, ChainCursor, HashChain, MAX_CHAIN_LEN};
    use crate::error::CryptoError;
    use crate::hash::{domain, Hash};

    fn seed(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    #[test]
    fn reveals_hash_forward_to_the_root() {
        let chain = HashChain::generate(domain::PAYWORD, &seed(7), 10).unwrap();
        let mut expected = chain.root();
        for index in 1..=10 {
            let reveal = chain.reveal(index).unwrap();
            assert_eq!(link(domain::PAYWORD, &reveal), expected);
            expected = reveal;
        }
    }

    #[test]
    fn a_cursor_accepts_reveals_in_order() {
        let chain = HashChain::generate(domain::PAYWORD, &seed(1), 5).unwrap();
        let mut cursor = ChainCursor::new(domain::PAYWORD, chain.root(), 8);
        for index in 1..=5 {
            let steps = cursor.advance(&chain.reveal(index).unwrap()).unwrap();
            assert_eq!(steps, 1);
            assert_eq!(cursor.consumed(), index);
        }
    }

    #[test]
    fn a_cursor_accepts_a_skip_and_charges_for_it() {
        // The PayWord case: the payer sends only the newest token, and the
        // number of steps is how many tranches are being settled at once.
        let chain = HashChain::generate(domain::PAYWORD, &seed(2), 100).unwrap();
        let mut cursor = ChainCursor::new(domain::PAYWORD, chain.root(), 128);
        assert_eq!(cursor.advance(&chain.reveal(40).unwrap()).unwrap(), 40);
        assert_eq!(cursor.consumed(), 40);
        assert_eq!(cursor.advance(&chain.reveal(75).unwrap()).unwrap(), 35);
        assert_eq!(cursor.consumed(), 75);
    }

    #[test]
    fn a_cursor_refuses_to_walk_backwards() {
        let chain = HashChain::generate(domain::PAYWORD, &seed(3), 20).unwrap();
        let mut cursor = ChainCursor::new(domain::PAYWORD, chain.root(), 32);
        cursor.advance(&chain.reveal(10).unwrap()).unwrap();
        // Re-presenting an older token must fail: it is the double-spend of a
        // micro-payment channel.
        assert!(cursor.advance(&chain.reveal(5).unwrap()).is_err());
        assert!(cursor.advance(&chain.reveal(10).unwrap()).is_err());
        assert_eq!(cursor.consumed(), 10, "a rejected reveal must not move the cursor");
    }

    #[test]
    fn the_catch_up_bound_is_enforced() {
        // The A6 defence: a peer sending random bytes must not be able to make
        // a node hash indefinitely.
        let chain = HashChain::generate(domain::PAYWORD, &seed(4), 100).unwrap();
        let mut cursor = ChainCursor::new(domain::PAYWORD, chain.root(), 10);
        let far = chain.reveal(50).unwrap();
        assert_eq!(
            cursor.advance(&far),
            Err(CryptoError::BadChainLink { max_steps: 10 }),
            "a reveal 50 links ahead was accepted with a 10-step budget"
        );
        assert_eq!(cursor.consumed(), 0);
    }

    #[test]
    fn junk_is_rejected_in_bounded_time() {
        let chain = HashChain::generate(domain::COMMITMENT_CHAIN, &seed(5), 16).unwrap();
        let mut cursor = ChainCursor::new(domain::COMMITMENT_CHAIN, chain.root(), 16);
        assert!(cursor.advance(&Hash::from_bytes([0xab; 32])).is_err());
    }

    #[test]
    fn chains_in_different_domains_do_not_interchange() {
        // The property that stops a PayWord token from being presented as a
        // consensus randomness reveal.
        let payword = HashChain::generate(domain::PAYWORD, &seed(6), 4).unwrap();
        let consensus = HashChain::generate(domain::COMMITMENT_CHAIN, &seed(6), 4).unwrap();
        assert_ne!(payword.root(), consensus.root(), "same seed, same root across domains");

        let mut cursor = ChainCursor::new(domain::COMMITMENT_CHAIN, consensus.root(), 8);
        assert!(
            cursor.advance(&payword.reveal(1).unwrap()).is_err(),
            "a PayWord token verified against a commitment chain"
        );
    }

    #[test]
    fn a_would_advance_probe_leaves_the_cursor_alone() {
        let chain = HashChain::generate(domain::PAYWORD, &seed(8), 4).unwrap();
        let cursor = ChainCursor::new(domain::PAYWORD, chain.root(), 8);
        let before = cursor.clone();
        assert_eq!(cursor.would_advance(&chain.reveal(2).unwrap()).unwrap(), 2);
        assert_eq!(cursor, before);
    }

    #[test]
    fn a_zero_length_chain_is_its_own_root() {
        let chain = HashChain::generate(domain::PAYWORD, &seed(9), 0).unwrap();
        assert_eq!(chain.root(), seed(9));
        assert_eq!(chain.len(), 0);
        assert!(chain.is_empty());
        assert_eq!(chain.reveal(1), None);
    }

    #[test]
    fn reveal_index_zero_is_the_root_and_never_a_valid_reveal() {
        let chain = HashChain::generate(domain::PAYWORD, &seed(10), 3).unwrap();
        assert_eq!(chain.reveal(0), None, "the root is not a reveal of itself");
        assert_eq!(chain.reveal(4), None, "past the end");
    }

    #[test]
    fn generation_refuses_an_unreasonable_length() {
        assert!(HashChain::generate(domain::PAYWORD, &seed(11), MAX_CHAIN_LEN).is_ok());
        assert!(HashChain::generate(domain::PAYWORD, &seed(11), MAX_CHAIN_LEN + 1).is_err());
    }

    #[test]
    fn generation_is_deterministic() {
        let first = HashChain::generate(domain::PAYWORD, &seed(12), 32).unwrap();
        let second = HashChain::generate(domain::PAYWORD, &seed(12), 32).unwrap();
        assert_eq!(first, second);
    }
}
