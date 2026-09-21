// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Proof of Service: epochs, committee sampling, the randomness beacon, the
//! finality ladder and the inactivity leak.
//!
//! **Not implemented.** The objects this crate will operate on exist:
//! `vanargand_types::block` has the header, the three rungs, the contestation
//! window and validator equivocation, all with their tests.
//!
//! What belongs here and nowhere else:
//!
//! - the validator set and its service weight (bond × multiplier, capped at ×2);
//! - committee sampling from the epoch seed — 64 active drawn from 192, on a
//!   schedule known an hour in advance, per R2's honesty correction;
//! - the commitment chain plus VDF that makes the seed unchooseable (A4), which
//!   R2 puts on the critical launch path as its only unproven component;
//! - the two-thirds certificate, and the inactivity leak that lets a partition
//!   recover finality without anyone intervening;
//! - the unbonding delay, which is the only place in the workspace that needs
//!   to know what an epoch is.
//!
//! Slashing is for **attributable** faults only — equivocation, which carries
//! its own proof. Never for silence: R2 withdrew that penalty because a crash
//! and a deliberate withholding are the same observable.
//!
//! Tier 1 of the roadmap in `docs/02-scope.pdf`.
