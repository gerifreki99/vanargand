// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Local assets: the issuance rules, separate from the balances.
//!
//! R2's **monetary inversion** brings these forward from Tier 3 to Tier 1, and
//! it is a regulatory design rather than a feature request:
//!
//! > Le VAN est la monnaie des machines ; les humains gardent la leur.
//!
//! At the pilot festival the attendee pays in the organiser's closed token —
//! the one it already issues legally through its cashless partner — running on
//! Vanargand's rails. The VAN circulates only between machines: terminals,
//! relays, gateways, archives, validators. The consumer-facing regulatory
//! surface stays exactly where it already was (G7), the organiser keeps the
//! float economy that is its actual business, and the monetary federation of
//! Tier 3 gets tested in miniature from the first day.
//!
//! # What lives here and what does not
//!
//! This module owns **issuance**: who may mint, whether they may mint again,
//! and what the supply is. It never touches a balance. The ledger moves the
//! money, because an issuance bug and an accounting bug should not be able to
//! hide in the same function.

use std::collections::BTreeMap;

use core::fmt;

use vanargand_crypto::hash::{domain, Hash, Hasher};
use vanargand_types::codec::{CodecError, Decode, Decoder, Encode, Encoder};
use vanargand_types::id::{AccountId, AssetId};
use vanargand_types::name::Name;
use vanargand_types::Amount;

/// An asset's registry record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetRecord {
    /// The account that created it, and the only one that may mint.
    pub issuer: AccountId,
    /// The ticker, unique across the chain.
    pub ticker: Name,
    /// Decimal places, for display only.
    ///
    /// The ledger counts indivisible units and never divides by this. It exists
    /// so that a wallet can render "12.50 tokens" instead of "1250", and a
    /// transition that read it would be a transition that could round.
    pub decimals: u8,
    /// Whether the issuer may mint after creation.
    ///
    /// A festival that mints its whole float once and then sets this to false
    /// has told every holder something the ledger will enforce.
    pub reissuable: bool,
    /// Units in existence.
    pub supply: Amount,
}

impl AssetRecord {
    /// The digest stored in the state tree.
    #[must_use]
    pub fn value_hash(&self) -> Hash {
        Hasher::new(domain::STATE_VALUE).update(&self.to_canonical_bytes()).finalize()
    }
}

impl Encode for AssetRecord {
    fn encode(&self, out: &mut Encoder) {
        self.issuer.encode(out);
        self.ticker.encode(out);
        out.write_varint(u64::from(self.decimals));
        out.write_bool(self.reissuable);
        self.supply.encode(out);
    }
}

impl Decode for AssetRecord {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            issuer: AccountId::decode(input)?,
            ticker: Name::decode(input)?,
            decimals: input.read_varint_u8()?,
            reissuable: input.read_bool()?,
            supply: Amount::decode(input)?,
        })
    }
}

/// Why an issuance operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssetError {
    /// No such asset.
    NoSuchAsset(AssetId),
    /// The ticker is already taken.
    TickerTaken {
        /// Which ticker.
        ticker: Name,
        /// The asset that holds it.
        held_by: AssetId,
    },
    /// The asset identifier is already in use.
    ///
    /// Unreachable while identifiers are derived from a transaction id, which
    /// is unique by the nonce rules. Checked anyway, because the alternative is
    /// silently replacing an existing asset's issuer.
    AssetExists(AssetId),
    /// Only the issuer may mint.
    NotTheIssuer {
        /// Who tried.
        caller: AccountId,
        /// Who may.
        issuer: AccountId,
    },
    /// The asset was created with issuance closed.
    NotReissuable(AssetId),
    /// A mint or burn of nothing.
    ZeroAmount,
    /// Burning more than exists.
    SupplyUnderflow {
        /// What was burned.
        amount: Amount,
        /// What existed.
        supply: Amount,
    },
    /// Supply arithmetic overflowed.
    Overflow,
}

impl fmt::Display for AssetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSuchAsset(id) => write!(f, "no such asset {id}"),
            Self::TickerTaken { ticker, held_by } => {
                write!(f, "ticker '{ticker}' is held by {held_by}")
            }
            Self::AssetExists(id) => write!(f, "asset {id} already exists"),
            Self::NotTheIssuer { caller, issuer } => {
                write!(f, "{caller} is not the issuer; {issuer} is")
            }
            Self::NotReissuable(id) => write!(f, "asset {id} was created with issuance closed"),
            Self::ZeroAmount => write!(f, "a mint or burn of nothing"),
            Self::SupplyUnderflow { amount, supply } => {
                write!(f, "burning {amount} of a supply of {supply}")
            }
            Self::Overflow => write!(f, "supply arithmetic overflowed"),
        }
    }
}

impl std::error::Error for AssetError {}

/// Every asset on the chain, and the tickers they hold.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssetRegistry {
    assets: BTreeMap<AssetId, AssetRecord>,
    tickers: BTreeMap<Name, AssetId>,
}

impl AssetRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An asset's record.
    #[must_use]
    pub fn get(&self, id: &AssetId) -> Option<&AssetRecord> {
        self.assets.get(id)
    }

    /// The asset holding a ticker, if any.
    #[must_use]
    pub fn by_ticker(&self, ticker: &Name) -> Option<AssetId> {
        self.tickers.get(ticker).copied()
    }

    /// How many assets exist.
    #[must_use]
    pub fn len(&self) -> usize {
        self.assets.len()
    }

    /// Whether no asset exists.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.assets.is_empty()
    }

    /// Every asset, in ascending identifier order.
    pub fn iter(&self) -> impl Iterator<Item = (&AssetId, &AssetRecord)> {
        self.assets.iter()
    }

    /// Every ticker reservation, in ascending name order.
    pub fn tickers(&self) -> impl Iterator<Item = (&Name, &AssetId)> {
        self.tickers.iter()
    }

    /// Creates an asset with no supply.
    ///
    /// Supply starts at zero even when the issuer intends to mint immediately:
    /// creation and issuance are separate acts, so that a chain reading its own
    /// history can say when each happened.
    pub fn create(
        &mut self,
        id: AssetId,
        issuer: AccountId,
        ticker: Name,
        decimals: u8,
        reissuable: bool,
    ) -> Result<(), AssetError> {
        if self.assets.contains_key(&id) {
            return Err(AssetError::AssetExists(id));
        }
        if let Some(held_by) = self.by_ticker(&ticker) {
            return Err(AssetError::TickerTaken { ticker, held_by });
        }
        self.tickers.insert(ticker.clone(), id);
        self.assets.insert(
            id,
            AssetRecord { issuer, ticker, decimals, reissuable, supply: Amount::ZERO },
        );
        Ok(())
    }

    /// Authorises a mint and records the new supply.
    ///
    /// Returns without moving any balance: the ledger credits the recipient.
    pub fn authorise_mint(
        &mut self,
        id: &AssetId,
        caller: AccountId,
        amount: Amount,
    ) -> Result<(), AssetError> {
        if amount.is_zero() {
            return Err(AssetError::ZeroAmount);
        }
        let record = self.assets.get_mut(id).ok_or(AssetError::NoSuchAsset(*id))?;
        if record.issuer != caller {
            return Err(AssetError::NotTheIssuer { caller, issuer: record.issuer });
        }
        if !record.reissuable && !record.supply.is_zero() {
            return Err(AssetError::NotReissuable(*id));
        }
        record.supply = record.supply.checked_add(amount).ok_or(AssetError::Overflow)?;
        Ok(())
    }

    /// Records a burn against the supply.
    ///
    /// Anyone holding units may burn their own; the ledger has already checked
    /// that they hold them.
    pub fn record_burn(&mut self, id: &AssetId, amount: Amount) -> Result<(), AssetError> {
        if amount.is_zero() {
            return Err(AssetError::ZeroAmount);
        }
        let record = self.assets.get_mut(id).ok_or(AssetError::NoSuchAsset(*id))?;
        record.supply = record.supply.checked_sub(amount).ok_or(AssetError::SupplyUnderflow {
            amount,
            supply: record.supply,
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{AssetError, AssetRegistry};
    use vanargand_crypto::hash::Hash;
    use vanargand_types::codec::{Decode, Encode};
    use vanargand_types::id::{AccountId, AssetId};
    use vanargand_types::name::Name;
    use vanargand_types::Amount;

    fn account(byte: u8) -> AccountId {
        AccountId::from_hash(Hash::from_bytes([byte; 32]))
    }

    fn asset(byte: u8) -> AssetId {
        AssetId::from_hash(Hash::from_bytes([byte; 32]))
    }

    fn name(text: &str) -> Name {
        Name::new(text).expect("a valid ticker")
    }

    /// The pilot's shape: an organiser issues a closed festival token.
    fn festival() -> (AssetRegistry, AssetId, AccountId) {
        let mut registry = AssetRegistry::new();
        let organiser = account(1);
        registry
            .create(asset(10), organiser, name("festi"), 2, true)
            .expect("a fresh ticker");
        (registry, asset(10), organiser)
    }

    #[test]
    fn creation_starts_with_no_supply() {
        // Creation and issuance are separate acts, so that a chain reading its
        // own history can say when each happened.
        let (registry, id, organiser) = festival();
        let record = registry.get(&id).expect("just created");
        assert_eq!(record.supply, Amount::ZERO);
        assert_eq!(record.issuer, organiser);
        assert_eq!(record.decimals, 2);
        assert!(record.reissuable);
    }

    #[test]
    fn a_ticker_is_unique_across_the_chain() {
        // Which is why `asset_create` is grammatically illegal in a provisional
        // block: uniqueness is global and one side of a partition cannot decide
        // it.
        let (mut registry, id, _) = festival();
        assert_eq!(
            registry.create(asset(11), account(2), name("festi"), 0, true),
            Err(AssetError::TickerTaken { ticker: name("festi"), held_by: id })
        );
        assert!(registry.create(asset(11), account(2), name("festo"), 0, true).is_ok());
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn an_identifier_is_never_silently_reused() {
        // Unreachable while identifiers come from transaction ids, which the
        // nonce rules make unique. Checked anyway: the alternative is quietly
        // replacing an asset's issuer.
        let (mut registry, id, _) = festival();
        assert_eq!(
            registry.create(id, account(2), name("other"), 0, true),
            Err(AssetError::AssetExists(id))
        );
    }

    #[test]
    fn only_the_issuer_may_mint() {
        let (mut registry, id, organiser) = festival();
        assert_eq!(
            registry.authorise_mint(&id, account(9), Amount::from_ulf(100)),
            Err(AssetError::NotTheIssuer { caller: account(9), issuer: organiser })
        );
        assert!(registry.authorise_mint(&id, organiser, Amount::from_ulf(100)).is_ok());
        assert_eq!(registry.get(&id).expect("exists").supply, Amount::from_ulf(100));
    }

    #[test]
    fn a_closed_issuance_mints_once_and_no_more() {
        // A festival that mints its float once and closes issuance has told
        // every holder something the ledger will enforce.
        let mut registry = AssetRegistry::new();
        registry.create(asset(20), account(1), name("closed"), 0, false).expect("fresh");

        assert!(registry.authorise_mint(&asset(20), account(1), Amount::from_ulf(1_000)).is_ok());
        assert_eq!(
            registry.authorise_mint(&asset(20), account(1), Amount::from_ulf(1)),
            Err(AssetError::NotReissuable(asset(20)))
        );
        assert_eq!(registry.get(&asset(20)).expect("exists").supply, Amount::from_ulf(1_000));
    }

    #[test]
    fn burning_reduces_the_supply_and_cannot_go_below_zero() {
        let (mut registry, id, organiser) = festival();
        registry.authorise_mint(&id, organiser, Amount::from_ulf(100)).expect("issuer");

        registry.record_burn(&id, Amount::from_ulf(40)).expect("enough supply");
        assert_eq!(registry.get(&id).expect("exists").supply, Amount::from_ulf(60));

        assert_eq!(
            registry.record_burn(&id, Amount::from_ulf(61)),
            Err(AssetError::SupplyUnderflow {
                amount: Amount::from_ulf(61),
                supply: Amount::from_ulf(60)
            })
        );
        assert_eq!(
            registry.get(&id).expect("exists").supply,
            Amount::from_ulf(60),
            "a refused burn moved the supply"
        );
    }

    #[test]
    fn a_burn_can_reopen_a_closed_issuance_only_to_zero() {
        // A subtlety worth pinning: `reissuable = false` is implemented as "no
        // minting once supply is non-zero". Burning the entire supply therefore
        // lets the issuer mint again. That is a consequence of the rule as
        // written, not a decision — and it is the behaviour an implementation
        // has to agree on, so it is asserted rather than left to be
        // rediscovered.
        let mut registry = AssetRegistry::new();
        registry.create(asset(30), account(1), name("once"), 0, false).expect("fresh");
        registry.authorise_mint(&asset(30), account(1), Amount::from_ulf(10)).expect("first");
        assert!(registry.authorise_mint(&asset(30), account(1), Amount::ONE_ULF).is_err());

        registry.record_burn(&asset(30), Amount::from_ulf(10)).expect("burn it all");
        assert!(
            registry.authorise_mint(&asset(30), account(1), Amount::from_ulf(5)).is_ok(),
            "burning to zero did not reopen issuance; the rule changed"
        );
    }

    #[test]
    fn zero_is_not_an_amount() {
        let (mut registry, id, organiser) = festival();
        assert_eq!(
            registry.authorise_mint(&id, organiser, Amount::ZERO),
            Err(AssetError::ZeroAmount)
        );
        assert_eq!(registry.record_burn(&id, Amount::ZERO), Err(AssetError::ZeroAmount));
    }

    #[test]
    fn an_unknown_asset_is_rejected() {
        let mut registry = AssetRegistry::new();
        assert_eq!(
            registry.authorise_mint(&asset(99), account(1), Amount::ONE_ULF),
            Err(AssetError::NoSuchAsset(asset(99)))
        );
        assert_eq!(
            registry.record_burn(&asset(99), Amount::ONE_ULF),
            Err(AssetError::NoSuchAsset(asset(99)))
        );
    }

    #[test]
    fn records_round_trip() {
        let (mut registry, id, organiser) = festival();
        registry.authorise_mint(&id, organiser, Amount::from_ulf(12_345)).expect("issuer");
        let record = registry.get(&id).expect("exists").clone();
        let bytes = record.to_canonical_bytes();
        assert_eq!(super::AssetRecord::from_canonical_bytes(&bytes), Ok(record));
    }

    #[test]
    fn the_registry_iterates_in_identifier_order() {
        // Consensus-critical: these entries are hashed into the state root.
        let mut registry = AssetRegistry::new();
        for byte in [7_u8, 1, 5, 3] {
            registry
                .create(asset(byte), account(1), name(&format!("t{byte}")), 0, true)
                .expect("fresh");
        }
        let observed: Vec<AssetId> = registry.iter().map(|(id, _)| *id).collect();
        let mut expected = observed.clone();
        expected.sort_unstable();
        assert_eq!(observed, expected);
    }
}
