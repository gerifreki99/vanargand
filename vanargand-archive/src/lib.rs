// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The archive-delivery market: timed-response challenges, latency
//! triangulation, and serving the chain's public history rather than sealing
//! it.
//!
//! **Not implemented.**
//!
//! R2 changed this market's objective, and the change is the interesting part.
//! The chain's history is public, so the goal is not a vault but a CDN: it
//! should be served fast, everywhere, forever. Nobody proves they *hold* the
//! data; they prove they *serve* it — challenges answered against the clock,
//! triangulated by watchtowers drawn at random, plus a mystery shopper that
//! actually downloads and files a signed receipt.
//!
//! Two consequences worth stating. The generation attack (E2) becomes a
//! non-problem: a "cheat" who serves public data quickly has performed exactly
//! the service being paid for. And this market escapes C7 entirely, because its
//! diversity is measured in milliseconds rather than in identities — the speed
//! of light is an incorruptible oracle.
//!
//! The honest limit, in R2's words: triangulation proves a diversity of points
//! of presence, not of owners. Enough for public data, not enough for
//! private.
//!
//! Tier 1 of the roadmap in `docs/02-scope.pdf`.
