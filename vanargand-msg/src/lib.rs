// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end encrypted messaging: session establishment, double ratchet, MLS
//! for groups, and store-and-forward relays for absent recipients.
//!
//! **Not implemented.** The key encapsulation interface it needs is in
//! `vanargand_crypto::kem`, with no backend wired yet.
//!
//! Post-quantum encapsulation from v1, not later. G1's "harvest now, decrypt
//! later" attack means a signature can in principle be upgraded afterwards
//! while an encrypted message cannot: everything sent before the switch stays
//! readable forever. R2 adds a post-quantum pre-shared key injected into MLS
//! each epoch, hardening groups without leaving RFC 9420.
//!
//! B4 — traffic correlation — is open, and honestly so. Padding, random delays
//! and optional onion routing raise the cost; no system in the world solves
//! it.
//!
//! Tier 1 of the roadmap in `docs/02-scope.pdf`.
