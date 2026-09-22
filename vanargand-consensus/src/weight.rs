// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Consensus weight, computed in integers.
//!
//! ```text
//! weight = bond × multiplier ÷ 1000
//! ```
//!
//! There is no floating point here or anywhere else in the workspace. A
//! multiplier of "1.8" is the integer 1800, and two nodes computing
//! `10_000 × 1800 ÷ 1000` get the same answer on every platform for ever, which
//! is not true of `10_000.0 × 1.8`.

use core::fmt;

use vanargand_types::codec::{CodecError, Decode, Decoder, Encode, Encoder};
use vanargand_types::Amount;

/// The multiplier value meaning ×1.0.
pub const MULTIPLIER_ONE: u32 = 1_000;

/// The cap, ×2.0.
///
/// `docs/04-proof-of-service.pdf` §2: service amplifies power, it does not
/// replace it — the seizable bond stays the floor of security.
///
/// R2's honest restatement of what the cap buys, which is worth keeping next to
/// the constant: **merit makes domination more expensive, it does not prevent
/// it.** With a ×2 cap, money alone still suffices, with twice as much money.
pub const MULTIPLIER_MAX: u32 = 2_000;

/// The service multiplier, in thousandths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Multiplier(u32);

impl Multiplier {
    /// ×1.0 — the launch value, and the floor.
    pub const ONE: Self = Self(MULTIPLIER_ONE);

    /// ×2.0 — the cap.
    pub const MAX: Self = Self(MULTIPLIER_MAX);

    /// Builds a multiplier, clamped into `[1000, 2000]`.
    ///
    /// Clamping rather than rejecting, and specifically clamping *down* at the
    /// top: R1.1's design rule is that a service metric must fail by
    /// under-estimating the score, never by over-estimating it. A bug that
    /// produces 5000 must yield 2000, not an error a node might handle by
    /// skipping the check.
    #[must_use]
    pub const fn new(thousandths: u32) -> Self {
        if thousandths < MULTIPLIER_ONE {
            Self(MULTIPLIER_ONE)
        } else if thousandths > MULTIPLIER_MAX {
            Self(MULTIPLIER_MAX)
        } else {
            Self(thousandths)
        }
    }

    /// The value in thousandths.
    #[must_use]
    pub const fn thousandths(self) -> u32 {
        self.0
    }
}

impl Default for Multiplier {
    fn default() -> Self {
        Self::ONE
    }
}

impl fmt::Display for Multiplier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Rendered by integer division so that no float appears even in a log
        // line. ×1.8 prints as "x1.800".
        write!(f, "x{}.{:03}", self.0 / MULTIPLIER_ONE, self.0 % MULTIPLIER_ONE)
    }
}

impl Encode for Multiplier {
    fn encode(&self, out: &mut Encoder) {
        out.write_varint(u64::from(self.0));
    }
}

impl Decode for Multiplier {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let raw = input.read_varint_u32()?;
        if !(MULTIPLIER_ONE..=MULTIPLIER_MAX).contains(&raw) {
            // On the wire, out of range is invalid rather than clamped: a
            // decoder never normalises. `Multiplier::new` clamps because it
            // receives a computed score, not an encoding.
            return Err(CodecError::Invalid { reason: "multiplier out of range" });
        }
        Ok(Self(raw))
    }
}

/// Consensus weight.
///
/// Held in 128 bits although a single validator's weight fits in 64: sums over
/// a committee, and over a whole validator set, are the operations that
/// actually happen, and a sum in 64 bits is a sum that can wrap on a chain
/// whose accounting has been corrupted. Costing nothing to widen, it is widened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Weight(u128);

impl Weight {
    /// No weight.
    pub const ZERO: Self = Self(0);

    /// Wraps a raw weight.
    #[must_use]
    pub const fn from_raw(value: u128) -> Self {
        Self(value)
    }

    /// The raw value.
    #[must_use]
    pub const fn raw(self) -> u128 {
        self.0
    }

    /// Whether this weight is zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// `bond × multiplier ÷ 1000`, truncating.
    ///
    /// Truncating down, like every other rounding in this protocol: it can only
    /// under-state a validator's power, which is the safe direction.
    #[must_use]
    pub fn of(bond: Amount, multiplier: Multiplier) -> Self {
        let product = u128::from(bond.as_ulf()).saturating_mul(u128::from(multiplier.thousandths()));
        Self(product / u128::from(MULTIPLIER_ONE))
    }

    /// Addition, or `None` on overflow.
    #[must_use]
    pub const fn checked_add(self, other: Self) -> Option<Self> {
        match self.0.checked_add(other.0) {
            Some(sum) => Some(Self(sum)),
            None => None,
        }
    }

    /// Subtraction, or `None` below zero.
    #[must_use]
    pub const fn checked_sub(self, other: Self) -> Option<Self> {
        match self.0.checked_sub(other.0) {
            Some(difference) => Some(Self(difference)),
            None => None,
        }
    }

    /// Sums an iterator, or `None` on overflow.
    pub fn checked_sum<I: IntoIterator<Item = Self>>(items: I) -> Option<Self> {
        let mut total = Self::ZERO;
        for item in items {
            total = total.checked_add(item)?;
        }
        Some(total)
    }

    /// Scales by `numerator / denominator`, truncating, saturating on overflow.
    ///
    /// Used by the inactivity leak. Saturating rather than wrapping because a
    /// wrapped effective weight would hand a silent validator more power than
    /// it had.
    #[must_use]
    pub fn scaled(self, numerator: u64, denominator: u64) -> Self {
        if denominator == 0 {
            return Self::ZERO;
        }
        let product = self.0.saturating_mul(u128::from(numerator));
        Self(product / u128::from(denominator))
    }

    /// Whether `self` is strictly more than two thirds of `total`.
    ///
    /// `3 × self > 2 × total`, by cross-multiplication — no division, no
    /// rounding, no floating point.
    ///
    /// Strict, and that is the whole point of the function existing rather than
    /// being written inline. The classical BFT bound is strict, and an
    /// implementation that accepts exactly two thirds has a safety bug that
    /// only shows up when the weights happen to divide evenly.
    #[must_use]
    pub fn exceeds_two_thirds_of(self, total: Self) -> bool {
        match (self.0.checked_mul(3), total.0.checked_mul(2)) {
            (Some(left), Some(right)) => left > right,
            // Unreachable for weights within the supply cap. Refusing is the
            // safe direction: a certificate that cannot be evaluated is not a
            // certificate that passed.
            _ => false,
        }
    }
}

impl fmt::Display for Weight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{Multiplier, Weight, MULTIPLIER_MAX, MULTIPLIER_ONE};
    use vanargand_types::codec::{Decode, Encode};
    use vanargand_types::Amount;

    #[test]
    fn the_multiplier_is_clamped_into_range() {
        // R1.1: a service metric must fail by under-estimating, never by
        // over-estimating. A bug producing 5000 must yield the cap.
        assert_eq!(Multiplier::new(0), Multiplier::ONE);
        assert_eq!(Multiplier::new(999), Multiplier::ONE);
        assert_eq!(Multiplier::new(1_000), Multiplier::ONE);
        assert_eq!(Multiplier::new(1_800).thousandths(), 1_800);
        assert_eq!(Multiplier::new(2_000), Multiplier::MAX);
        assert_eq!(Multiplier::new(5_000), Multiplier::MAX);
        assert_eq!(Multiplier::new(u32::MAX), Multiplier::MAX);
    }

    #[test]
    fn the_wire_rejects_what_the_constructor_clamps() {
        // A decoder never normalises; a constructor that receives a computed
        // score does.
        let ok = Multiplier::new(1_500);
        assert_eq!(Multiplier::from_canonical_bytes(&ok.to_canonical_bytes()), Ok(ok));

        let mut encoder = vanargand_types::codec::Encoder::new();
        encoder.write_varint(5_000);
        assert!(Multiplier::from_canonical_bytes(&encoder.finish()).is_err());

        let mut encoder = vanargand_types::codec::Encoder::new();
        encoder.write_varint(0);
        assert!(Multiplier::from_canonical_bytes(&encoder.finish()).is_err());
    }

    #[test]
    fn weight_matches_the_documented_examples() {
        // `docs/04-proof-of-service.pdf` §2: Alice bonds 10 000 with a 1.8
        // multiplier and weighs 18 000; Bob bonds 20 000 with no service and
        // weighs 20 000. Bob outweighs Alice with twice her money — the honest
        // framing R2 insisted on.
        let alice = Weight::of(Amount::from_ulf(10_000), Multiplier::new(1_800));
        let bob = Weight::of(Amount::from_ulf(20_000), Multiplier::ONE);
        assert_eq!(alice.raw(), 18_000);
        assert_eq!(bob.raw(), 20_000);
        assert!(bob > alice);
    }

    #[test]
    fn the_cap_is_really_a_cap() {
        let bond = Amount::from_ulf(1_000);
        assert_eq!(Weight::of(bond, Multiplier::MAX).raw(), 2_000);
        assert_eq!(Weight::of(bond, Multiplier::new(u32::MAX)).raw(), 2_000);
    }

    #[test]
    fn weight_truncates_downwards() {
        // 7 × 1001 / 1000 = 7.007 → 7. Rounding can only under-state power.
        assert_eq!(Weight::of(Amount::from_ulf(7), Multiplier::new(1_001)).raw(), 7);
        assert_eq!(Weight::of(Amount::ZERO, Multiplier::MAX), Weight::ZERO);
    }

    #[test]
    fn weight_of_the_whole_supply_does_not_overflow() {
        let all = Weight::of(Amount::MAX, Multiplier::MAX);
        assert_eq!(all.raw(), u128::from(Amount::MAX.as_ulf()) * 2);
        // And 192 committee members each holding that much still sums.
        assert!(Weight::checked_sum(core::iter::repeat_n(all, 192)).is_some());
    }

    #[test]
    fn the_two_thirds_bound_is_strict() {
        // The bug this function exists to prevent: exactly two thirds must not
        // pass. Only visible when the weights divide evenly, which is exactly
        // when a hand-written comparison gets it wrong.
        let total = Weight::from_raw(300);
        assert!(!Weight::from_raw(200).exceeds_two_thirds_of(total), "exactly 2/3 passed");
        assert!(Weight::from_raw(201).exceeds_two_thirds_of(total));
        assert!(!Weight::from_raw(199).exceeds_two_thirds_of(total));
        assert!(Weight::from_raw(300).exceeds_two_thirds_of(total));
    }

    #[test]
    fn the_two_thirds_bound_handles_the_degenerate_cases() {
        assert!(!Weight::ZERO.exceeds_two_thirds_of(Weight::ZERO), "nothing exceeds nothing");
        assert!(Weight::from_raw(1).exceeds_two_thirds_of(Weight::ZERO));
        assert!(!Weight::ZERO.exceeds_two_thirds_of(Weight::from_raw(1)));
    }

    #[test]
    fn scaling_saturates_rather_than_wrapping() {
        assert_eq!(Weight::from_raw(100).scaled(1, 2).raw(), 50);
        assert_eq!(Weight::from_raw(100).scaled(0, 2), Weight::ZERO);
        assert_eq!(Weight::from_raw(100).scaled(1, 0), Weight::ZERO);
        assert_eq!(Weight::from_raw(u128::MAX).scaled(2, 1).raw(), u128::MAX);
    }

    #[test]
    fn display_shows_no_decimal_point_arithmetic() {
        assert_eq!(Multiplier::ONE.to_string(), "x1.000");
        assert_eq!(Multiplier::new(1_800).to_string(), "x1.800");
        assert_eq!(Multiplier::MAX.to_string(), "x2.000");
        assert_eq!(MULTIPLIER_ONE, 1_000);
        assert_eq!(MULTIPLIER_MAX, 2_000);
    }
}
