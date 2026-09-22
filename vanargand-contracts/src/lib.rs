// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The WASM virtual machine and open contracts.
//!
//! **Not implemented, and absent from Tier 1 by choice**, so that F1 — the long
//! history of drained contracts — is not exposed before audits have run. It
//! lives on the test network in the meantime.
//!
//! The rule that survives whatever the VM turns out to be: **the protocol's
//! vital functions stay native and outside the VM.** Bridges, freezes, storage
//! proofs and channels are not contracts. A bug in a user's contract must never
//! be able to touch the core.
//!
//! Tier 2 of the roadmap in `docs/02-scope.pdf`.
