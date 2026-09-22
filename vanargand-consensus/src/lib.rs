// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Proof of Service: weight, the epoch seed, committee sampling, certificates
//! and the inactivity leak.
//!
//! Implements `spec/draft/07-consensus.md`. Tier 1 of the roadmap in
//! `docs/02-scope.pdf`.
//!
//! # In one sentence
//!
//! You do not earn the right to keep the ledger by being rich or by burning
//! electricity: you earn it by posting a seizable bond and rendering real
//! service — and chance picks who validates, every hour, among those who
//! qualify.
//!
//! # What is here
//!
//! - [`weight`] — `bond × multiplier ÷ 1000`, in integers, and the strict
//!   two-thirds comparison.
//! - [`validator`] — candidates and the set of them.
//! - [`seed`] — mixing the commitment-chain reveals into an epoch seed.
//! - [`committee`] — the weighted draw without replacement, and the duty roster.
//! - [`certificate`] — votes, and what makes a block final at rung 2.
//! - [`leak`] — how a partitioned chain recovers finality with nobody
//!   intervening.
//!
//! - [`vdf`] — the sequential delay function, and a checkpointed proof of
//!   sequential work with its soundness written out.
//! - [`emission`] — the halving schedule and the ceiling a header's emission
//!   counter is audited against. One pure function of the height, which is what
//!   lets one chain audit another from a few kilobytes.
//!
//! # What is deliberately not here
//!
//! **The succinct proof.** [`vdf`] performs the delay and can prove it was
//! performed, but only probabilistically: a verifier samples segments, and a
//! prover that skipped a fraction *f* of the work escapes with probability
//! `(1 − f)^samples`. R2 requires a STARK, which catches any deviation and
//! verifies in constant time; that is not implemented, and it is the difference
//! between "every node samples ten segments" and "every node either trusts the
//! sampling or pays the whole delay itself".
//!
//! [`seed::EpochSeed`] records which grade of seed it holds, so a node can
//! refuse a test-network shortcut on a production chain.
//!
//! **The service score.** How storage challenges and consensus participation
//! accumulate into a multiplier, and how it erodes, is unspecified. Only its
//! effect on weight is here, and at launch the multiplier is frozen at ×1.0
//! anyway (`docs/04-proof-of-service.pdf` §8).
//!
//! **Proposer selection and block production.** Who proposes within the active
//! set, and the mechanics of gossiping proposals and collecting votes, belong
//! to `vanargand-node`.
//!
//! # Two rules that run through all of it
//!
//! **Only attributable faults are slashed.** Equivocation carries its own proof
//! and is seized; absence is not attributable and is never seized. R2's first
//! acknowledged error was a penalty for non-revelation, withdrawn because a
//! crash and a deliberate withholding produce the same silence — and because it
//! contradicted C9's own principle that silence under partition is not guilt.
//!
//! **The two-thirds bound is strict.** `3 × signed > 2 × total`, by
//! cross-multiplication, never by division. An implementation that accepts
//! exactly two thirds has a safety bug that only appears when the weights
//! happen to divide evenly, which is exactly when a hand-written comparison
//! gets it wrong.

pub mod certificate;
pub mod committee;
pub mod emission;
pub mod leak;
pub mod seed;
pub mod validator;
pub mod vdf;
pub mod weight;

pub use certificate::{Certificate, CertificateError, Vote};
pub use committee::{Committee, CommitteeMember, ACTIVE, SAMPLED};
pub use emission::{permitted_through, EmissionError};
pub use leak::LeakState;
pub use seed::{mix_reveals, EpochSeed};
pub use validator::{ValidatorRecord, ValidatorSet};
pub use vdf::{DelayError, DelayParameters, DelayProof};
pub use weight::{Multiplier, Weight};
