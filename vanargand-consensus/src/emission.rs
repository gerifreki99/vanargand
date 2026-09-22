// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The emission formula, and the arithmetic that polices it.
//!
//! `docs/05-emission.pdf`. A cap, a curve, and — the part that matters most for
//! a federation — a rule simple enough that **one chain can audit another from
//! a few kilobytes**:
//!
//! > Chaque en-tête de bloc porte la masse totale de VAN émise par la chaîne
//! > depuis sa naissance […]. Un seul nombre, comparable en un instant à ce que
//! > la formule autorise à cette hauteur de chaîne.
//!
//! That is what [`permitted_through`] computes, and checking a header's counter
//! against it is what makes the VAN zone possible. A conforming chain's VAN are
//! accepted at par; a chain whose counter exceeds its formula is demoted to a
//! local currency by arithmetic rather than by a vote.
//!
//! # Integers, and which way they round
//!
//! Every quantity here is in ulf and every division truncates **down**. The
//! consequence is that the schedule emits slightly *less* than the round
//! figures in the design document — about 5 · 10⁻¹⁵ of the cap over the first
//! period — and that is the safe direction. A chain one ulf over its formula
//! fails the border check and is demoted; a chain one ulf under it is simply a
//! chain.
//!
//! # What is here and what is not
//!
//! Here: the halving schedule, the cumulative ceiling, and the regeneration
//! bound. Those are pure functions of the epoch number, checkable by anyone.
//!
//! Not here: **who receives it**. The 60 / 25 / 15 split lives in
//! `vanargand_types::amount::EmissionSplit`, and the mission proofs and usage
//! credits that the bootstrap envelope pays for are not implemented at all.
//!
//! Also not here: R2's **adoption-gated ramp**, in which each step up is
//! unlocked by a demonstrated fee/emission ratio rather than by the calendar.
//! R2 adopts it *under conditions* — the direction must be "emission unlocked
//! by adoption", never "emission stays high because adoption is missing",
//! since the second recreates the Helium defect while believing it is fleeing
//! it — and requires a manipulation analysis of the trigger (family C8) as a
//! prerequisite. What this module implements is the calendar, which R2 keeps as
//! the floor and the ceiling in either case. **(open)**

use core::fmt;

use vanargand_types::block::params::EPOCH_BLOCKS;
use vanargand_types::Amount;

/// Epochs in a year.
///
/// An epoch is 720 blocks of five seconds, so an hour; 365.25 days is 8766 of
/// them. The quarter-day matters over forty years and costs nothing to include.
pub const EPOCHS_PER_YEAR: u64 = 8_766;

/// Epochs between halvings: four years.
///
/// R2 moved this from two years to four. Two concentrated half the money that
/// will ever exist into the first twenty-four months of a network nobody had
/// heard of, which is a distribution shape rather than a schedule.
pub const EPOCHS_PER_PERIOD: u64 = 4 * EPOCHS_PER_YEAR;

/// What the first four-year period emits in total, in ulf: fifty million VAN.
///
/// Half of everything that will ever exist, deliberately, at the moment the
/// network has to convince its first operators to work for something small.
pub const FIRST_PERIOD_EMISSION: u64 = 50_000_000 * 1_000_000_000;

/// How much of the previous epoch's burn a chain may re-mint.
///
/// Half. `docs/05-emission.pdf` §3: secondary emission is open to every
/// conforming chain and is **always at a loss**. Burn a hundred, re-mint fifty.
/// The arithmetic consequence is that no chain can create more than it
/// destroys, so the total supply can only erode with use — and manufacturing
/// fake traffic to farm regeneration is structurally a machine for losing
/// money.
pub const REGENERATION_NUMERATOR: u64 = 1;
/// Denominator of the regeneration fraction.
pub const REGENERATION_DENOMINATOR: u64 = 2;

/// Why an emission check failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EmissionError {
    /// The chain claims to have emitted more than the formula permits.
    ///
    /// The border check of `docs/05-emission.pdf` §5, and the only one that
    /// needs no cooperation from the chain being audited: a few bytes of header
    /// against a pure function of the height.
    OverFormula {
        /// What the header claims.
        claimed: Amount,
        /// What the formula permits at this epoch.
        permitted: Amount,
    },
    /// The counter went down.
    ///
    /// Emission is cumulative since genesis. A counter that can decrease is a
    /// counter that can be reset, and the audit rests on it never being.
    WentBackwards {
        /// The parent's counter.
        parent: Amount,
        /// This block's.
        claimed: Amount,
    },
    /// The chain claims to have emitted more than the protocol cap.
    OverCap(Amount),
}

impl fmt::Display for EmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OverFormula { claimed, permitted } => {
                write!(f, "emitted {claimed}, formula permits {permitted}")
            }
            Self::WentBackwards { parent, claimed } => {
                write!(f, "emission counter went from {parent} back to {claimed}")
            }
            Self::OverCap(amount) => write!(f, "emitted {amount}, over the protocol cap"),
        }
    }
}

impl std::error::Error for EmissionError {}

/// Which four-year period an epoch falls in. Zero is the first.
#[must_use]
pub const fn period_of(epoch: u64) -> u64 {
    epoch / EPOCHS_PER_PERIOD
}

/// What a whole period emits, in ulf.
///
/// Halves every period, and reaches zero once it has been shifted past the
/// width of the counter. Emission does not taper to a dust: it stops.
#[must_use]
pub const fn period_emission(period: u64) -> u64 {
    if period >= 64 {
        return 0;
    }
    FIRST_PERIOD_EMISSION >> period
}

/// What one epoch of a period emits, in ulf.
///
/// Truncated down, so a period emits marginally less than its nominal total.
#[must_use]
pub fn emission_for_epoch(epoch: u64) -> Amount {
    Amount::from_ulf(period_emission(period_of(epoch)) / EPOCHS_PER_PERIOD)
}

/// Everything the formula permits from genesis through `epoch`, inclusive.
///
/// The number a header's `emitted_supply` is measured against. Computed rather
/// than accumulated, so that an auditor needs only the height — not the history.
#[must_use]
pub fn permitted_through(epoch: u64) -> Amount {
    let period = period_of(epoch);
    let mut total: u64 = 0;

    // Complete periods.
    let mut index = 0;
    while index < period && index < 64 {
        let per_epoch = period_emission(index) / EPOCHS_PER_PERIOD;
        total = total.saturating_add(per_epoch.saturating_mul(EPOCHS_PER_PERIOD));
        index = index.saturating_add(1);
    }

    // The epochs elapsed in the current one, this epoch included.
    let elapsed = epoch
        .checked_rem(EPOCHS_PER_PERIOD)
        .unwrap_or(0)
        .saturating_add(1);
    let per_epoch = period_emission(period) / EPOCHS_PER_PERIOD;
    total = total.saturating_add(per_epoch.saturating_mul(elapsed));

    Amount::from_ulf(total.min(Amount::MAX.as_ulf()))
}

/// The most a chain may re-mint after destroying `burned` in the previous
/// epoch.
///
/// Half, rounded down. No chain can create more than it destroys.
#[must_use]
pub fn max_regeneration(burned: Amount) -> Amount {
    burned
        .mul_div_floor(REGENERATION_NUMERATOR, REGENERATION_DENOMINATOR)
        .unwrap_or(Amount::ZERO)
}

/// Checks a block's emission counter against its parent's and the formula.
///
/// Two questions, and both are answerable by a phone: has the counter moved
/// backwards, and does it exceed what the formula allows at this height?
pub fn check_counter(
    parent_emitted: Amount,
    claimed: Amount,
    epoch: u64,
) -> Result<(), EmissionError> {
    if claimed < parent_emitted {
        return Err(EmissionError::WentBackwards { parent: parent_emitted, claimed });
    }
    if !claimed.within_cap() {
        return Err(EmissionError::OverCap(claimed));
    }
    let permitted = permitted_through(epoch);
    if claimed > permitted {
        return Err(EmissionError::OverFormula { claimed, permitted });
    }
    Ok(())
}

/// The epoch a block height falls in.
///
/// Here rather than only on the header, because an auditor checking another
/// chain's milestone has a height and no header type.
#[must_use]
pub const fn epoch_of_height(height: u64) -> u64 {
    height / EPOCH_BLOCKS
}

#[cfg(test)]
mod tests {
    use super::{
        check_counter, emission_for_epoch, epoch_of_height, max_regeneration, period_emission,
        period_of, permitted_through, EmissionError, EPOCHS_PER_PERIOD, EPOCHS_PER_YEAR,
        FIRST_PERIOD_EMISSION,
    };
    use vanargand_types::Amount;

    #[test]
    fn an_epoch_is_an_hour_and_a_period_is_four_years() {
        assert_eq!(EPOCHS_PER_YEAR, 8_766, "365.25 days of hourly epochs");
        assert_eq!(EPOCHS_PER_PERIOD, 35_064);
        assert_eq!(epoch_of_height(0), 0);
        assert_eq!(epoch_of_height(719), 0);
        assert_eq!(epoch_of_height(720), 1);
    }

    #[test]
    fn the_first_epochs_emit_what_the_design_document_says() {
        // `docs/05-emission.pdf` §1: "Années 1–4 … ~1 425 VAN" per epoch.
        let per_epoch = emission_for_epoch(0);
        assert_eq!(per_epoch, emission_for_epoch(EPOCHS_PER_PERIOD - 1));
        let van = per_epoch.as_ulf() / 1_000_000_000;
        assert_eq!(van, 1_425, "per-epoch emission drifted from the published figure");
    }

    #[test]
    fn emission_halves_every_period() {
        assert_eq!(period_emission(0), FIRST_PERIOD_EMISSION);
        assert_eq!(period_emission(1), FIRST_PERIOD_EMISSION / 2);
        assert_eq!(period_emission(2), FIRST_PERIOD_EMISSION / 4);
        assert_eq!(period_of(0), 0);
        assert_eq!(period_of(EPOCHS_PER_PERIOD - 1), 0);
        assert_eq!(period_of(EPOCHS_PER_PERIOD), 1);
    }

    #[test]
    fn emission_stops_rather_than_tapering_for_ever() {
        // Once the halving has shifted the period's total past the width of the
        // counter there is nothing left to divide.
        assert_eq!(period_emission(64), 0);
        assert_eq!(period_emission(u64::MAX), 0);
        assert_eq!(emission_for_epoch(EPOCHS_PER_PERIOD * 64), Amount::ZERO);
    }

    #[test]
    fn the_first_period_emits_about_half_of_everything() {
        let after_four_years = permitted_through(EPOCHS_PER_PERIOD - 1);
        let half = Amount::MAX.as_ulf() / 2;
        assert!(after_four_years.as_ulf() <= half, "the first period overshot fifty million");
        // Truncation loses less than one epoch's worth.
        let shortfall = half.saturating_sub(after_four_years.as_ulf());
        assert!(
            shortfall < emission_for_epoch(0).as_ulf(),
            "truncation lost {shortfall} ulf, more than a single epoch"
        );
    }

    #[test]
    fn the_cumulative_ceiling_never_exceeds_the_cap() {
        // The property the whole federation rests on: a chain that respects the
        // formula cannot mint past a hundred million, whatever its age.
        for epoch in [0_u64, 1, EPOCHS_PER_PERIOD, EPOCHS_PER_PERIOD * 10, EPOCHS_PER_PERIOD * 100]
        {
            let permitted = permitted_through(epoch);
            assert!(
                permitted.within_cap(),
                "at epoch {epoch} the formula permits {permitted}, over the cap"
            );
        }
        assert!(permitted_through(u64::MAX).within_cap());
    }

    #[test]
    fn the_ceiling_only_ever_rises() {
        let mut previous = Amount::ZERO;
        for epoch in 0..200_u64 {
            let permitted = permitted_through(epoch);
            assert!(permitted >= previous, "the ceiling fell at epoch {epoch}");
            previous = permitted;
        }
        // And across a halving boundary.
        let before = permitted_through(EPOCHS_PER_PERIOD - 1);
        let after = permitted_through(EPOCHS_PER_PERIOD);
        assert!(after > before);
        // But more slowly: the step after the halving is half the step before.
        let step_before =
            permitted_through(EPOCHS_PER_PERIOD - 1).as_ulf()
                - permitted_through(EPOCHS_PER_PERIOD - 2).as_ulf();
        let step_after = after.as_ulf() - before.as_ulf();
        assert_eq!(step_after, step_before / 2);
    }

    #[test]
    fn the_border_check_catches_a_counterfeiter() {
        // A chain whose counter exceeds its formula is demoted by arithmetic,
        // not by a vote. This is that arithmetic.
        let permitted = permitted_through(10);
        assert_eq!(check_counter(Amount::ZERO, permitted, 10), Ok(()));

        let one_too_many = Amount::from_ulf(permitted.as_ulf().saturating_add(1));
        assert_eq!(
            check_counter(Amount::ZERO, one_too_many, 10),
            Err(EmissionError::OverFormula { claimed: one_too_many, permitted })
        );
    }

    #[test]
    fn the_counter_may_never_go_backwards() {
        // A counter that can decrease is a counter that can be reset, and the
        // whole audit rests on it never being.
        assert_eq!(
            check_counter(Amount::from_ulf(1_000), Amount::from_ulf(999), 10),
            Err(EmissionError::WentBackwards {
                parent: Amount::from_ulf(1_000),
                claimed: Amount::from_ulf(999)
            })
        );
        assert_eq!(
            check_counter(Amount::from_ulf(1_000), Amount::from_ulf(1_000), 10),
            Ok(()),
            "standing still is legitimate: an epoch may emit nothing"
        );
    }

    #[test]
    fn a_counter_over_the_cap_is_refused_whatever_the_epoch() {
        let over = Amount::from_ulf(Amount::MAX.as_ulf().saturating_add(1));
        assert_eq!(check_counter(Amount::ZERO, over, u64::MAX), Err(EmissionError::OverCap(over)));
    }

    #[test]
    fn regeneration_is_always_at_a_loss() {
        // Burn a hundred, re-mint fifty. No chain can create more than it
        // destroys, so the supply erodes with use — and farming fake traffic is
        // a machine for losing money.
        assert_eq!(max_regeneration(Amount::from_ulf(100)), Amount::from_ulf(50));
        assert_eq!(max_regeneration(Amount::from_ulf(101)), Amount::from_ulf(50));
        assert_eq!(max_regeneration(Amount::from_ulf(1)), Amount::ZERO);
        assert_eq!(max_regeneration(Amount::ZERO), Amount::ZERO);

        for burned in 0..500_u64 {
            let minted = max_regeneration(Amount::from_ulf(burned));
            assert!(
                minted.as_ulf().saturating_mul(2) <= burned,
                "re-minted {minted} against a burn of {burned}"
            );
        }
    }
}
