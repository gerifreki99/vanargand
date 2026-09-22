// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The project's bare name: a façade that re-exports the crates a consumer
//! actually wants.
//!
//! Empty until there is a stable surface worth re-exporting. Publishing a
//! façade before the crates behind it have settled means every one of their
//! breaking changes becomes a breaking change here too, which is the opposite
//! of what a façade is for.
//!
//! Use [`vanargand_types`] and [`vanargand_crypto`] directly in the meantime.
