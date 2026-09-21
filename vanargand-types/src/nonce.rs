// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The two-dimensional nonce: `(lane, sequence)`.
//!
//! R1.3 replaced the ordinary sequential nonce with this one, and the reason is
//! the whole design of Vanargand in miniature.
//!
//! # Why a single counter does not survive a partition
//!
//! A sequential nonce imposes one total order on everything an account does.
//! That is fine when the account is one device with one connection. It is not
//! fine when an account has a phone in a cut-off village and a laptop in the
//! city: both are honest, both sign, both pick the next number, and they
//! collide. The account is punished for being in two places, which is the
//! normal operating condition this protocol is built for.
//!
//! # Why not simply drop ordering
//!
//! Because ordering is what makes fraud self-proving. R2's nomad credit turns a
//! bounced cheque into evidence: spending the same offline credit in two
//! partitions produces **two signatures on the same lane and the same
//! sequence**, a few hundred bytes that anyone can verify and that convict
//! without a court. Remove the counter and that evidence disappears; the
//! offline credit becomes a promise again instead of a bounded, self-policing
//! risk.
//!
//! # The resolution
//!
//! Each device subkey owns a [`Lane`], and each lane is a strictly sequential
//! counter. Within a lane there is a total order, so equivocation is provable.
//! Across lanes there is no order at all, so two honest devices never collide.
//!
//! The correction R2 added is why the lane belongs to the *device* and not to
//! the account: with account-wide lanes, two honest devices of one account, each
//! isolated in its own partition, would produce an innocent equivocation and be
//! slashed for it. Equivocation is provable — and punishable — only within one
//! device subkey.

use core::fmt;

use crate::codec::{CodecError, Decode, Decoder, Encode, Encoder};

/// A nonce lane, owned by exactly one device subkey of an account.
///
/// Lanes are assigned when a device is added and are never reused, even after
/// the device is revoked. Reuse would let a revoked device's old signature and
/// a new device's fresh one share a `(lane, sequence)` and look like
/// equivocation by an account that did nothing wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Lane(u32);

impl Lane {
    /// The lane of an account's first device.
    pub const FIRST: Self = Self(0);

    /// Wraps a lane index.
    #[must_use]
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    /// The lane index.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0
    }

    /// The next lane to allocate after this one, or `None` if exhausted.
    ///
    /// Exhaustion is not reachable in practice — it would take four billion
    /// devices on one account — but it returns an `Option` rather than
    /// wrapping, because a wrapped lane index is a manufactured equivocation
    /// proof against an innocent account.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(index) => Some(Self(index)),
            None => None,
        }
    }
}

impl fmt::Display for Lane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lane {}", self.0)
    }
}

impl Encode for Lane {
    fn encode(&self, out: &mut Encoder) {
        out.write_varint(u64::from(self.0));
    }
}

impl Decode for Lane {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self(input.read_varint_u32()?))
    }
}

/// A two-dimensional nonce.
///
/// Ordering is by lane first, then sequence — which is a total order on the
/// type but **not** a claim that two nonces in different lanes happened in that
/// order. Nothing orders two different lanes; that is the point. The `Ord` impl
/// exists so that nonces can be keys in a `BTreeMap`, and code that reads it as
/// causality is wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Nonce {
    /// Which device's lane.
    pub lane: Lane,
    /// Position within that lane. Strictly sequential, no gaps.
    pub sequence: u64,
}

impl Nonce {
    /// The first nonce of a lane.
    #[must_use]
    pub const fn first(lane: Lane) -> Self {
        Self { lane, sequence: 0 }
    }

    /// Builds a nonce.
    #[must_use]
    pub const fn new(lane: Lane, sequence: u64) -> Self {
        Self { lane, sequence }
    }

    /// The next nonce in the same lane, or `None` if the lane is exhausted.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.sequence.checked_add(1) {
            Some(sequence) => Some(Self { lane: self.lane, sequence }),
            None => None,
        }
    }

    /// Whether `self` and `other` occupy the same slot.
    ///
    /// Two *different* transactions whose nonces collide, signed by the same
    /// device subkey, are an equivocation: the evidence R2 relies on. This
    /// function answers only the nonce half of that question — the other half
    /// is "different transaction, same device", and it belongs to the evidence
    /// type, not here.
    #[must_use]
    pub const fn collides_with(self, other: Self) -> bool {
        self.lane.index() == other.lane.index() && self.sequence == other.sequence
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.lane.index(), self.sequence)
    }
}

impl Encode for Nonce {
    fn encode(&self, out: &mut Encoder) {
        self.lane.encode(out);
        out.write_varint(self.sequence);
    }
}

impl Decode for Nonce {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let lane = Lane::decode(input)?;
        let sequence = input.read_varint()?;
        Ok(Self { lane, sequence })
    }
}

/// The per-account record of how far each lane has advanced.
///
/// A `BTreeMap`, not a `HashMap`: this structure is hashed into the state root,
/// so its iteration order is consensus-critical. `CONTRIBUTING.md` bans the
/// hash-based collections for exactly this reason, and the ban is checked by
/// `clippy.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaneState {
    next: std::collections::BTreeMap<Lane, u64>,
}

impl LaneState {
    /// An account with no lanes yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The sequence number the next transaction in `lane` must carry.
    ///
    /// A lane that has never been used starts at zero, so an unopened lane and
    /// a lane at position zero are the same thing. That is deliberate: it means
    /// adding a device does not have to write to state before the device can
    /// sign.
    #[must_use]
    pub fn next_sequence(&self, lane: Lane) -> u64 {
        self.next.get(&lane).copied().unwrap_or(0)
    }

    /// Whether `nonce` is the one this lane is waiting for.
    ///
    /// Strictly the next one. Not "greater than the last", which would allow
    /// gaps, and a gap is a slot that can never be filled and can therefore
    /// never be proved to have been double-used.
    #[must_use]
    pub fn accepts(&self, nonce: Nonce) -> bool {
        nonce.sequence == self.next_sequence(nonce.lane)
    }

    /// Records that `nonce` has been used, advancing its lane.
    ///
    /// Returns `false` and changes nothing if the nonce was not the expected
    /// one, or if the lane is exhausted.
    pub fn consume(&mut self, nonce: Nonce) -> bool {
        if !self.accepts(nonce) {
            return false;
        }
        let Some(next) = nonce.sequence.checked_add(1) else {
            return false;
        };
        self.next.insert(nonce.lane, next);
        true
    }

    /// The lanes that have been used, in ascending order.
    pub fn lanes(&self) -> impl Iterator<Item = (Lane, u64)> + '_ {
        self.next.iter().map(|(lane, sequence)| (*lane, *sequence))
    }

    /// Sets a lane's counter directly.
    ///
    /// For decoding a stored account and for tests. This is the one way to move
    /// a lane other than by consuming a nonce, and it deliberately bypasses the
    /// strict-sequence rule, so it must never be reachable from transaction
    /// processing: a caller that can set the counter can replay a spend.
    pub fn restore(&mut self, lane: Lane, next_sequence: u64) {
        self.next.insert(lane, next_sequence);
    }
}

#[cfg(test)]
mod tests {
    use super::{Lane, LaneState, Nonce};
    use crate::codec::{Decode, Encode};

    #[test]
    fn nonces_round_trip() {
        for nonce in [
            Nonce::first(Lane::FIRST),
            Nonce::new(Lane::new(1), 0),
            Nonce::new(Lane::new(u32::MAX), u64::MAX),
        ] {
            let bytes = nonce.to_canonical_bytes();
            assert_eq!(Nonce::from_canonical_bytes(&bytes), Ok(nonce));
        }
    }

    #[test]
    fn a_lane_is_strictly_sequential() {
        let mut state = LaneState::new();
        let lane = Lane::FIRST;

        assert!(state.accepts(Nonce::new(lane, 0)));
        assert!(!state.accepts(Nonce::new(lane, 1)), "a gap was accepted");

        assert!(state.consume(Nonce::new(lane, 0)));
        assert!(state.accepts(Nonce::new(lane, 1)));
        assert!(!state.accepts(Nonce::new(lane, 0)), "a replay was accepted");
        assert!(!state.accepts(Nonce::new(lane, 2)), "a gap was accepted");
    }

    #[test]
    fn a_rejected_nonce_does_not_advance_the_lane() {
        let mut state = LaneState::new();
        let lane = Lane::FIRST;
        assert!(!state.consume(Nonce::new(lane, 5)));
        assert_eq!(state.next_sequence(lane), 0);
    }

    #[test]
    fn lanes_advance_independently() {
        // The property that makes a partition survivable: a phone in a cut-off
        // village and a laptop in the city both sign, and neither blocks the
        // other.
        let mut state = LaneState::new();
        let village = Lane::new(0);
        let city = Lane::new(1);

        assert!(state.consume(Nonce::new(village, 0)));
        assert!(state.consume(Nonce::new(village, 1)));
        assert!(state.consume(Nonce::new(city, 0)));

        assert_eq!(state.next_sequence(village), 2);
        assert_eq!(state.next_sequence(city), 1);
        assert_eq!(state.next_sequence(Lane::new(2)), 0, "an unused lane must start at zero");
    }

    #[test]
    fn a_replay_in_one_lane_does_not_disturb_another() {
        let mut state = LaneState::new();
        state.consume(Nonce::new(Lane::new(0), 0));
        state.consume(Nonce::new(Lane::new(1), 0));
        assert!(!state.consume(Nonce::new(Lane::new(0), 0)));
        assert_eq!(state.next_sequence(Lane::new(1)), 1);
    }

    #[test]
    fn collision_is_within_a_lane_only() {
        // The nonce half of the equivocation test.
        assert!(Nonce::new(Lane::new(0), 7).collides_with(Nonce::new(Lane::new(0), 7)));
        assert!(!Nonce::new(Lane::new(0), 7).collides_with(Nonce::new(Lane::new(1), 7)));
        assert!(!Nonce::new(Lane::new(0), 7).collides_with(Nonce::new(Lane::new(0), 8)));
    }

    #[test]
    fn lane_and_sequence_exhaustion_is_none_not_a_wrap() {
        // A wrapped lane index or sequence would manufacture an equivocation
        // proof against an account that did nothing wrong.
        assert_eq!(Lane::new(u32::MAX).next(), None);
        assert_eq!(Lane::new(0).next(), Some(Lane::new(1)));
        assert_eq!(Nonce::new(Lane::FIRST, u64::MAX).next(), None);

        let mut state = LaneState::new();
        state.next.insert(Lane::FIRST, u64::MAX);
        assert!(!state.consume(Nonce::new(Lane::FIRST, u64::MAX)));
    }

    #[test]
    fn lanes_iterate_in_ascending_order() {
        // Consensus-critical: this ordering is hashed into the state root.
        let mut state = LaneState::new();
        for index in [5_u32, 1, 3, 0] {
            state.consume(Nonce::new(Lane::new(index), 0));
        }
        let observed: Vec<u32> = state.lanes().map(|(lane, _)| lane.index()).collect();
        assert_eq!(observed, vec![0, 1, 3, 5]);
    }

    #[test]
    fn display_is_readable() {
        assert_eq!(Nonce::new(Lane::new(2), 9).to_string(), "2/9");
        assert_eq!(Lane::new(2).to_string(), "lane 2");
    }
}
