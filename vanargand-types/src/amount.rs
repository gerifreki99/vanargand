// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Quantities of value, and the splits the protocol performs on them.
//!
//! # Why this type has no operators
//!
//! [`Amount`] implements no `Add`, `Sub` or `Mul`. That is the enforcement
//! mechanism for the rule in `CONTRIBUTING.md` about unchecked arithmetic: a
//! balance cannot be silently wrapped or overflowed because there is no syntax
//! for doing so. Every operation returns a `Result` or an `Option`, and the
//! caller has to say what happens when it fails. The friction is the feature —
//! `balance - amount` compiling and wrapping is how a chain mints money.
//!
//! # Units
//!
//! The smallest indivisible unit is the **ulf**. One VAN is 10⁹ ulf.
//!
//! Nine decimals rather than eight or eighteen: the micro-payment layer prices
//! a megabyte of gateway traffic, which at any plausible VAN price needs
//! fractions far below a hundredth of a unit, and eighteen decimals would push
//! the supply past `u64` for no benefit. With nine, the entire 100 000 000 VAN
//! cap is 10¹⁷ ulf, which leaves a factor of 184 of headroom in a `u64` — so
//! intermediate sums of every coin in existence still cannot overflow.
//!
//! The unit name is **(open)**: `docs/` never names it.

use core::fmt;

use crate::codec::{CodecError, Decode, Decoder, Encode, Encoder};

/// Decimal places between one VAN and one ulf.
pub const DECIMALS: u32 = 9;

/// Ulf per VAN: 10⁹.
pub const ULF_PER_VAN: u64 = 1_000_000_000;

/// The protocol's hard cap, in ulf: 100 000 000 VAN.
///
/// A point of departure to be tested by simulation, per `docs/05-emission.pdf`,
/// not a frozen constant — but the *existence* of a cap is a principle, since a
/// simple rule is what lets one chain audit another from a few kilobytes.
pub const MAX_SUPPLY: u64 = 100_000_000 * ULF_PER_VAN;

/// A quantity of value, in ulf.
///
/// Values above [`MAX_SUPPLY`] are representable but are rejected by the state
/// layer: the type keeps arithmetic honest, the ledger keeps the cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Amount(u64);

impl Amount {
    /// Zero.
    pub const ZERO: Self = Self(0);

    /// One ulf, the smallest representable quantity.
    pub const ONE_ULF: Self = Self(1);

    /// One VAN.
    pub const ONE_VAN: Self = Self(ULF_PER_VAN);

    /// The hard cap.
    pub const MAX: Self = Self(MAX_SUPPLY);

    /// Builds an amount from a count of ulf.
    #[must_use]
    pub const fn from_ulf(ulf: u64) -> Self {
        Self(ulf)
    }

    /// Builds an amount from whole VAN, or `None` on overflow.
    #[must_use]
    pub const fn from_van(van: u64) -> Option<Self> {
        match van.checked_mul(ULF_PER_VAN) {
            Some(ulf) => Some(Self(ulf)),
            None => None,
        }
    }

    /// The amount in ulf.
    #[must_use]
    pub const fn as_ulf(self) -> u64 {
        self.0
    }

    /// Whether this is zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Whether this is within the protocol cap.
    #[must_use]
    pub const fn within_cap(self) -> bool {
        self.0 <= MAX_SUPPLY
    }

    /// Addition, or `None` on overflow.
    #[must_use]
    pub const fn checked_add(self, other: Self) -> Option<Self> {
        match self.0.checked_add(other.0) {
            Some(sum) => Some(Self(sum)),
            None => None,
        }
    }

    /// Subtraction, or `None` if it would go below zero.
    ///
    /// The single most important function in this module. "Insufficient funds"
    /// and "wrapped around to 18 quintillion" are the same expression in most
    /// languages; here they are `None` and nothing.
    #[must_use]
    pub const fn checked_sub(self, other: Self) -> Option<Self> {
        match self.0.checked_sub(other.0) {
            Some(difference) => Some(Self(difference)),
            None => None,
        }
    }

    /// Multiplication by a plain count, or `None` on overflow.
    #[must_use]
    pub const fn checked_mul(self, factor: u64) -> Option<Self> {
        match self.0.checked_mul(factor) {
            Some(product) => Some(Self(product)),
            None => None,
        }
    }

    /// `self × numerator ÷ denominator`, rounded **down**, computed in 128 bits
    /// so that the intermediate product cannot overflow.
    ///
    /// Rounding down, always, everywhere. Round-half-to-even would be fairer
    /// per operation and is exactly the kind of fairness that is not worth a
    /// consensus rule: "down" is one sentence, has no tie-breaking case, and
    /// can never hand out more than was available. Where the rounding loss has
    /// to go somewhere, the callers in this module send it to the fire.
    ///
    /// Returns `None` if the denominator is zero or the result exceeds `u64`.
    // The narrowing cast is guarded by the bound check immediately above it.
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub const fn mul_div_floor(self, numerator: u64, denominator: u64) -> Option<Self> {
        if denominator == 0 {
            return None;
        }
        let product = (self.0 as u128) * (numerator as u128);
        let quotient = product / (denominator as u128);
        if quotient > u64::MAX as u128 {
            return None;
        }
        Some(Self(quotient as u64))
    }

    /// Sums an iterator, or `None` on overflow.
    pub fn checked_sum<I: IntoIterator<Item = Self>>(items: I) -> Option<Self> {
        let mut total = Self::ZERO;
        for item in items {
            total = total.checked_add(item)?;
        }
        Some(total)
    }
}

impl fmt::Display for Amount {
    /// Renders as VAN with all nine decimals and no separators, e.g.
    /// `1.500000000 VAN`.
    ///
    /// Deliberately not locale-aware and deliberately not trimmed: this is the
    /// representation for logs, errors and test vectors, where an unambiguous
    /// reading matters more than a pretty one. A wallet formats for humans
    /// itself.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.0 / ULF_PER_VAN;
        let fraction = self.0 % ULF_PER_VAN;
        write!(f, "{whole}.{fraction:09} VAN")
    }
}

impl Encode for Amount {
    fn encode(&self, out: &mut Encoder) {
        out.write_varint(self.0);
    }
}

impl Decode for Amount {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self(input.read_varint()?))
    }
}

/// An exact rational, for the health metrics a block header has to publish
/// without floating point.
///
/// `docs/05-emission.pdf` requires every header to carry the ratio of real fees
/// to emission. That is a fraction, and there is no `f64` in this protocol, so
/// it travels as the two integers it was computed from. A verifier recomputes
/// the comparison rather than the division, which is exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ratio {
    /// Top of the fraction.
    pub numerator: u64,
    /// Bottom of the fraction. Zero means "undefined", not "infinite".
    pub denominator: u64,
}

impl Ratio {
    /// A ratio of zero, with denominator one.
    pub const ZERO: Self = Self { numerator: 0, denominator: 1 };

    /// Builds a ratio.
    #[must_use]
    pub const fn new(numerator: u64, denominator: u64) -> Self {
        Self { numerator, denominator }
    }

    /// The value in parts per million, rounded down, or `None` if undefined.
    ///
    /// For display and for threshold comparisons where a fixed grain is wanted.
    /// Comparisons that must be exact should use [`Ratio::cmp_exact`].
    // The narrowing cast is guarded by the bound check immediately above it.
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub const fn to_ppm(self) -> Option<u64> {
        if self.denominator == 0 {
            return None;
        }
        let scaled = (self.numerator as u128) * 1_000_000;
        let quotient = scaled / (self.denominator as u128);
        if quotient > u64::MAX as u128 {
            return None;
        }
        Some(quotient as u64)
    }

    /// Compares two ratios exactly, by cross-multiplication in 128 bits.
    ///
    /// No division, no rounding, no floating point. Both denominators must be
    /// non-zero.
    #[must_use]
    pub const fn cmp_exact(self, other: Self) -> Option<core::cmp::Ordering> {
        if self.denominator == 0 || other.denominator == 0 {
            return None;
        }
        let left = (self.numerator as u128) * (other.denominator as u128);
        let right = (other.numerator as u128) * (self.denominator as u128);
        if left < right {
            Some(core::cmp::Ordering::Less)
        } else if left > right {
            Some(core::cmp::Ordering::Greater)
        } else {
            Some(core::cmp::Ordering::Equal)
        }
    }
}

impl Encode for Ratio {
    fn encode(&self, out: &mut Encoder) {
        out.write_varint(self.numerator);
        out.write_varint(self.denominator);
    }
}

impl Decode for Ratio {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let numerator = input.read_varint()?;
        let denominator = input.read_varint()?;
        Ok(Self { numerator, denominator })
    }
}

/// How a fee is divided. The 70 / 20 / 10 of `docs/05-emission.pdf` §4.
///
/// These are points of departure to be tested by simulation, not frozen
/// constants. What is frozen is the shape: a majority to the worker, a slice to
/// the context pot, and a burn — because the burn is the load-bearing part.
pub mod fee_weights {
    /// To the party that performed the service.
    pub const PROVIDER: u64 = 70;
    /// To the pot of the context: the corridor, the local market.
    pub const POT: u64 = 20;
    /// Destroyed. "La part du feu."
    pub const BURN: u64 = 10;
    /// Sum of the weights.
    pub const TOTAL: u64 = PROVIDER + POT + BURN;
}

/// The three destinations of a fee.
///
/// The invariant, asserted on construction and in the tests: the three parts
/// sum to exactly the fee. Not approximately — a rounding remainder that
/// vanishes is a chain that loses money, and a remainder that is paid twice is
/// a chain that prints it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeSplit {
    /// To the validator, storer, gateway or courier that did the work.
    pub provider: Amount,
    /// To the context pot that funds delivery bounties and finder commissions.
    pub pot: Amount,
    /// Destroyed.
    pub burn: Amount,
}

impl FeeSplit {
    /// Splits a fee.
    ///
    /// Provider and pot are rounded down; **the burn takes the remainder**.
    ///
    /// That choice is not arbitrary. Rounding dust has to go somewhere, and
    /// every other destination is a party with an incentive: a validator that
    /// could choose transaction sizes to collect dust, a pot that could be
    /// farmed. The fire has no incentives. It also means the burn is never
    /// *under*-paid, which keeps C1 sound — the invariant that makes every
    /// closed loop lose money is "a fraction of fees is destroyed", and a
    /// rounding rule that could shave the burn to zero on small fees would
    /// hand an attacker a fee size at which loops are free.
    #[must_use]
    pub fn of(fee: Amount) -> Self {
        let provider =
            fee.mul_div_floor(fee_weights::PROVIDER, fee_weights::TOTAL).unwrap_or(Amount::ZERO);
        let pot = fee.mul_div_floor(fee_weights::POT, fee_weights::TOTAL).unwrap_or(Amount::ZERO);
        // Cannot fail: both parts are floors of fractions summing to less than
        // one, so their sum is at most the fee.
        let paid = provider.checked_add(pot).unwrap_or(Amount::ZERO);
        let burn = fee.checked_sub(paid).unwrap_or(Amount::ZERO);
        Self { provider, pot, burn }
    }

    /// The three parts summed, which must equal the original fee.
    #[must_use]
    pub fn total(self) -> Option<Amount> {
        Amount::checked_sum([self.provider, self.pot, self.burn])
    }
}

/// How an epoch's emission is divided. The 60 / 25 / 15 of
/// `docs/05-emission.pdf` §2.
pub mod emission_weights {
    /// To validators: the wage of security.
    pub const VALIDATORS: u64 = 60;
    /// To the bootstrap fund: missions and usage credits.
    pub const BOOTSTRAP: u64 = 25;
    /// To the protocol treasury: bug bounties, simulation, audits.
    pub const TREASURY: u64 = 15;
    /// Sum of the weights.
    pub const TOTAL: u64 = VALIDATORS + BOOTSTRAP + TREASURY;
}

/// The three envelopes of an epoch's emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmissionSplit {
    /// Paid to validators, by weight and actual participation.
    pub validators: Amount,
    /// The bootstrap fund.
    pub bootstrap: Amount,
    /// The protocol treasury.
    pub treasury: Amount,
}

impl EmissionSplit {
    /// Splits an epoch's emission.
    ///
    /// Every envelope is rounded down and **the remainder is not emitted at
    /// all**, so the three parts may sum to slightly less than the budget.
    ///
    /// This is the opposite convention from [`FeeSplit::of`], and deliberately
    /// so. A fee already exists and must be fully accounted for; emission is
    /// being created, and the rule that governs creation is that a chain may
    /// never mint more than the formula allows. Given a choice between losing a
    /// few ulf per epoch and risking a single ulf over the cap, emission loses
    /// the ulf — a chain one unit over its formula is a chain that fails the
    /// border check of `docs/05-emission.pdf` §5 and is demoted out of the VAN
    /// zone. Two units per hour is not a price worth arguing about.
    #[must_use]
    pub fn of(budget: Amount) -> Self {
        let share = |weight: u64| {
            budget.mul_div_floor(weight, emission_weights::TOTAL).unwrap_or(Amount::ZERO)
        };
        Self {
            validators: share(emission_weights::VALIDATORS),
            bootstrap: share(emission_weights::BOOTSTRAP),
            treasury: share(emission_weights::TREASURY),
        }
    }

    /// The three envelopes summed.
    #[must_use]
    pub fn total(self) -> Option<Amount> {
        Amount::checked_sum([self.validators, self.bootstrap, self.treasury])
    }
}

#[cfg(test)]
mod tests {
    use super::{
        emission_weights, fee_weights, Amount, EmissionSplit, FeeSplit, Ratio, MAX_SUPPLY,
        ULF_PER_VAN,
    };
    use crate::codec::{Decode, Encode};
    use core::cmp::Ordering;

    #[test]
    fn the_cap_leaves_room_for_every_coin_to_be_summed() {
        // The headroom claim in the module documentation, asserted. If someone
        // later changes DECIMALS, this is what tells them what it costs.
        assert!(MAX_SUPPLY < u64::MAX / 100, "less than 100x headroom above the cap");
        assert_eq!(MAX_SUPPLY, 100_000_000 * ULF_PER_VAN);
    }

    #[test]
    fn subtraction_below_zero_is_none_not_a_fortune() {
        assert_eq!(Amount::ZERO.checked_sub(Amount::ONE_ULF), None);
        assert_eq!(
            Amount::from_ulf(5).checked_sub(Amount::from_ulf(6)),
            None,
            "an overdraft wrapped instead of failing"
        );
        assert_eq!(Amount::from_ulf(5).checked_sub(Amount::from_ulf(5)), Some(Amount::ZERO));
    }

    #[test]
    fn addition_overflow_is_none() {
        let huge = Amount::from_ulf(u64::MAX);
        assert_eq!(huge.checked_add(Amount::ONE_ULF), None);
        assert_eq!(huge.checked_add(Amount::ZERO), Some(huge));
    }

    #[test]
    fn from_van_rejects_overflow() {
        assert_eq!(Amount::from_van(1), Some(Amount::ONE_VAN));
        assert_eq!(Amount::from_van(u64::MAX), None);
    }

    #[test]
    fn mul_div_floor_never_overflows_in_the_middle() {
        // The whole supply times 70 exceeds u64; the 128-bit intermediate is
        // what makes this work.
        let whole_supply = Amount::MAX;
        let seventy_percent = whole_supply.mul_div_floor(70, 100).unwrap();
        assert_eq!(seventy_percent.as_ulf(), 70_000_000 * ULF_PER_VAN);
    }

    #[test]
    fn mul_div_floor_rounds_down_and_rejects_zero_denominators() {
        assert_eq!(Amount::from_ulf(10).mul_div_floor(1, 3), Some(Amount::from_ulf(3)));
        assert_eq!(Amount::from_ulf(2).mul_div_floor(1, 3), Some(Amount::ZERO));
        assert_eq!(Amount::from_ulf(10).mul_div_floor(1, 0), None);
    }

    #[test]
    fn a_fee_split_always_sums_to_the_fee() {
        // The invariant, over every fee from nothing to a whole VAN, plus the
        // awkward sizes. Exhaustive at the small end is where rounding lives.
        for ulf in 0_u64..2_000 {
            let fee = Amount::from_ulf(ulf);
            let split = FeeSplit::of(fee);
            assert_eq!(split.total(), Some(fee), "fee split lost or created value at {ulf} ulf");
        }
        for fee in [Amount::ONE_VAN, Amount::MAX, Amount::from_ulf(u64::MAX)] {
            assert_eq!(FeeSplit::of(fee).total(), Some(fee));
        }
    }

    #[test]
    fn a_fee_split_gives_the_remainder_to_the_fire() {
        // 10 ulf splits exactly: 7 / 2 / 1.
        let exact = FeeSplit::of(Amount::from_ulf(10));
        assert_eq!(exact.provider, Amount::from_ulf(7));
        assert_eq!(exact.pot, Amount::from_ulf(2));
        assert_eq!(exact.burn, Amount::from_ulf(1));

        // 11 ulf does not: floors are 7 and 2, and the extra 2 burn.
        let inexact = FeeSplit::of(Amount::from_ulf(11));
        assert_eq!(inexact.provider, Amount::from_ulf(7));
        assert_eq!(inexact.pot, Amount::from_ulf(2));
        assert_eq!(inexact.burn, Amount::from_ulf(2), "remainder did not go to the fire");
    }

    #[test]
    fn every_non_zero_fee_burns_something() {
        // C1 depends on this: the invariant that makes closed loops lose money
        // is "a fraction of every fee is destroyed". A fee size at which the
        // burn rounds to zero would be a fee size at which wash trading is
        // free. The smallest fee that burns nothing is zero itself.
        for ulf in 1_u64..5_000 {
            let split = FeeSplit::of(Amount::from_ulf(ulf));
            assert!(!split.burn.is_zero(), "a fee of {ulf} ulf burned nothing");
        }
    }

    #[test]
    fn fee_weights_sum_to_one_hundred() {
        assert_eq!(fee_weights::TOTAL, 100);
        assert_eq!(emission_weights::TOTAL, 100);
    }

    #[test]
    fn an_emission_split_never_exceeds_its_budget() {
        // The opposite convention from fees, and the one that matters: a chain
        // one ulf over its formula is demoted out of the VAN zone.
        for ulf in 0_u64..2_000 {
            let budget = Amount::from_ulf(ulf);
            let split = EmissionSplit::of(budget);
            let total = split.total().expect("emission split overflowed");
            assert!(total <= budget, "emission split minted {total} from a budget of {budget}");
            // And it never loses more than two ulf, which is the bound implied
            // by three floors.
            assert!(budget.checked_sub(total).unwrap().as_ulf() <= 2);
        }
    }

    #[test]
    fn an_emission_split_of_a_round_budget_is_exact() {
        let budget = Amount::from_ulf(1_000);
        let split = EmissionSplit::of(budget);
        assert_eq!(split.validators, Amount::from_ulf(600));
        assert_eq!(split.bootstrap, Amount::from_ulf(250));
        assert_eq!(split.treasury, Amount::from_ulf(150));
        assert_eq!(split.total(), Some(budget));
    }

    #[test]
    fn amounts_round_trip_through_the_codec() {
        for ulf in [0_u64, 1, 127, 128, ULF_PER_VAN, MAX_SUPPLY, u64::MAX] {
            let amount = Amount::from_ulf(ulf);
            let bytes = amount.to_canonical_bytes();
            assert_eq!(Amount::from_canonical_bytes(&bytes), Ok(amount));
        }
    }

    #[test]
    fn display_shows_all_nine_decimals() {
        assert_eq!(Amount::ZERO.to_string(), "0.000000000 VAN");
        assert_eq!(Amount::ONE_VAN.to_string(), "1.000000000 VAN");
        assert_eq!(Amount::from_ulf(1).to_string(), "0.000000001 VAN");
        assert_eq!(Amount::from_ulf(1_500_000_000).to_string(), "1.500000000 VAN");
    }

    #[test]
    fn ratios_compare_exactly_without_dividing() {
        // 1/3 versus 2/6: equal, which a ppm comparison would also get right,
        // and 333333/1000000 versus 1/3, which it would not.
        assert_eq!(Ratio::new(1, 3).cmp_exact(Ratio::new(2, 6)), Some(Ordering::Equal));
        assert_eq!(
            Ratio::new(333_333, 1_000_000).cmp_exact(Ratio::new(1, 3)),
            Some(Ordering::Less),
            "a ppm-rounded ratio compared equal to the value it was rounded from"
        );
        assert_eq!(Ratio::new(1, 0).cmp_exact(Ratio::new(1, 1)), None);
    }

    #[test]
    fn ratios_convert_to_ppm() {
        assert_eq!(Ratio::new(1, 2).to_ppm(), Some(500_000));
        assert_eq!(Ratio::new(1, 3).to_ppm(), Some(333_333));
        assert_eq!(Ratio::ZERO.to_ppm(), Some(0));
        assert_eq!(Ratio::new(1, 0).to_ppm(), None);
    }

    #[test]
    fn ratios_round_trip_through_the_codec() {
        let ratio = Ratio::new(12_345, 67_890);
        assert_eq!(Ratio::from_canonical_bytes(&ratio.to_canonical_bytes()), Ok(ratio));
    }
}
