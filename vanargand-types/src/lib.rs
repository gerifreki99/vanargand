// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The canonical objects of the Vanargand protocol.
//!
//! This crate holds everything whose **bytes are consensus**: the encoding,
//! identifiers, addresses, amounts, nonces, transactions and block headers.
//! Nothing here executes anything or talks to anything. If two implementations
//! of Vanargand agree about this crate, they agree about what a transaction
//! *is*; whether they agree about what it *does* is `vanargand-state`'s
//! problem.
//!
//! # Reading order
//!
//! 1. [`codec`] — the canonical encoding. Everything else depends on it.
//! 2. [`amount`] — value, and the splits performed on it.
//! 3. [`id`] — the protocol's identifiers, each its own type.
//! 4. [`bech32`] / [`address`] — the text form a human reads and retypes.
//! 5. [`nonce`] — the two-dimensional nonce that survives a partition.
//! 6. [`name`] — names and tickers, and the homograph problem.
//! 7. [`tx`] — transactions and the partition grammar.
//! 8. [`block`] — headers, the finality ladder, contestation clocks.
//!
//! # Three rules that run through all of it
//!
//! **A decoder never normalises.** It accepts the one canonical encoding or it
//! errors. Normalising would let two byte strings mean one object, which in a
//! protocol whose fraud proofs are "two signatures over the same thing" is not
//! a cosmetic problem.
//!
//! **There is no clock.** No type here has a timestamp field, and the deadline
//! types take *finalised* height rather than height. That is the C9 parade made
//! structural: a contestation window that could run out inside a partition is a
//! window that protects nobody.
//!
//! **Arithmetic on value cannot wrap.** [`amount::Amount`] implements no
//! operators at all; every operation returns an `Option` or a `Result` and the
//! caller has to say what failure means.

pub mod address;
pub mod amount;
pub mod bech32;
pub mod block;
pub mod codec;
pub mod crypto_codec;
pub mod id;
pub mod merkle;
pub mod name;
pub mod nonce;
pub mod tx;

pub use address::{Address, Network};
pub use amount::{Amount, EmissionSplit, FeeSplit, Ratio};
pub use codec::{CodecError, Decode, Decoder, Encode, Encoder};
pub use id::{AccountId, AssetId, BlockId, ChainId, DeviceId, TxId};
pub use name::Name;
pub use nonce::{Lane, LaneState, Nonce};

// Re-exported so that a downstream crate can work with the protocol's objects
// without naming the primitive layer, while `vanargand-crypto` stays the only
// place that names a cryptographic library.
pub use vanargand_crypto::hash::Hash;
pub use vanargand_crypto::AlgorithmId;
