// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ledger, and the deterministic application of transactions to it.
//!
//! # What this module does not do
//!
//! It does not verify signatures. The caller does that, because the caller is
//! the one that knows which key belongs to which device and whether that key is
//! acceptable on this network. A function that both looked up authority and
//! applied an effect would be a function where an authority bug and an
//! accounting bug live in the same place.
//!
//! # Determinism
//!
//! Every rule below is a pure function of the transaction bytes and the state
//! it names. No clock, no randomness, no iteration over an unordered
//! collection, no floating point. This is what R2 means by specifying every
//! transaction kind as "provable": a full node must be able to produce a
//! compact refutation of a bad transition (A7), and a refutation is only
//! compact if the transition touched a knowable set of Merkle branches.
//!
//! # Completeness, honestly
//!
//! Six transaction kinds are implemented. The rest return
//! [`StateError::NotImplemented`], which is a loud placeholder and not a
//! design: a chain must not be run until every kind either applies or is
//! removed from [`vanargand_types::tx::TxKind`]. The list is in the module
//! documentation of the tests at the bottom.

use std::collections::BTreeMap;

use vanargand_bourse::payword::{PayWordToken, MAX_TRANCHES};
use vanargand_bourse::purse::{Purse, PurseId, DISPUTE_WINDOW_FINALIZED_BLOCKS};
use vanargand_types::amount::{FeeSplit, Ratio};
use vanargand_types::block::{ContestationWindow, FinalityRung};
use vanargand_types::id::{AccountId, AssetId, ChainId, DeviceId};
use vanargand_types::name::Name;
use vanargand_types::nonce::Lane;
use vanargand_types::tx::{asset_id_of, TxBody, TxError, TxKind, TX_VERSION};
use vanargand_types::{Amount, Hash};

use crate::account::{Account, Device};
use crate::asset::{AssetError, AssetRegistry};
use crate::keys;
use crate::name_book::{NameBook, NameError};
use crate::purse_book::{Payout, PurseBook, PurseBookError};
use crate::recovery::{RecoveryBook, RecoveryError, RECOVERY_WINDOW_FINALIZED_BLOCKS};
use crate::slashing::{AccountOffence, Penalty, SlashingBook, SlashingError, ValidatorOffence};
use crate::smt::SparseMerkleTree;

/// What a block says about itself while its transactions are applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockContext {
    /// Which chain.
    pub chain: ChainId,
    /// This block's height.
    pub height: u64,
    /// The most recent rung-2 height this block builds on.
    ///
    /// Every deadline is measured against this and never against `height`. A
    /// partition raises `height` freely and cannot move this number at all,
    /// which is what freezes every contestation clock (C9).
    pub finalized_height: u64,
    /// Whether this block claims provisional or chain finality.
    pub rung: FinalityRung,
    /// The proposer, who receives the provider share of every fee.
    pub proposer: AccountId,
}

/// What applying a transaction did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    /// How the fee was divided.
    pub fee: FeeSplit,
    /// How much of the account's offline credit this consumed.
    ///
    /// Zero outside a provisional block: the credit only exists while the chain
    /// cannot finalise.
    pub nomad_consumed: Amount,
}

/// Why a transaction could not be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StateError {
    /// The transaction names a different chain.
    WrongChain,
    /// Unsupported transaction version.
    UnsupportedVersion(u16),
    /// The validity window has closed, in finalised height.
    Expired {
        /// The window's end.
        valid_until: u64,
        /// The current finalised height.
        finalized_height: u64,
    },
    /// This kind is grammatically illegal in a provisional block (C9).
    ForbiddenInProvisional {
        /// Which kind.
        kind: &'static str,
    },
    /// No such account.
    NoSuchAccount(AccountId),
    /// The account has no such device.
    NoSuchDevice(DeviceId),
    /// The device has been revoked.
    DeviceRevoked(DeviceId),
    /// The transaction used a lane that is not this device's.
    WrongLane {
        /// The lane the device owns.
        expected: Lane,
        /// The lane the transaction used.
        got: Lane,
    },
    /// The nonce is not the next one this lane expects.
    BadNonce {
        /// What the lane expects.
        expected: u64,
        /// What the transaction carried.
        got: u64,
    },
    /// Not enough of an asset.
    InsufficientBalance {
        /// Which asset, `None` for VAN.
        asset: Option<AssetId>,
        /// What was needed.
        needed: Amount,
        /// What was there.
        available: Amount,
    },
    /// The offline credit for this device is exhausted.
    ///
    /// The merchant-facing guarantee, enforced. An account cut off from the
    /// world can spend exactly what it declared in advance and not one ulf
    /// more.
    NomadCreditExhausted {
        /// The device.
        device: DeviceId,
        /// What the transaction would have spent.
        needed: Amount,
        /// What remained of the device's share.
        remaining: Amount,
    },
    /// The per-device shares would exceed the account's declared credit.
    NomadOverAllocated {
        /// The sum of the shares.
        allocated: Amount,
        /// The declared credit.
        credit: Amount,
    },
    /// A lane index was reused.
    LaneAlreadyUsed(Lane),
    /// A device identifier that was revoked cannot be added again.
    DeviceWasRevoked(DeviceId),
    /// The device is already registered.
    DeviceAlreadyExists(DeviceId),
    /// A channel's tranche value was zero.
    ///
    /// The channel's capacity is derived as `deposit ÷ tranche_value`, so a
    /// tranche worth nothing would be a channel of infinite length.
    ZeroTrancheValue,
    /// Evidence that does not show what it claims to show.
    BadEvidence(TxError),
    /// The accused account has no device matching the evidence.
    ///
    /// Either the account never held that key, or it has been revoked and its
    /// key forgotten. Evidence about a key the ledger cannot identify is
    /// evidence nobody can check.
    UnknownAccusedDevice(DeviceId),
    /// No device of the accused validator signed both blocks.
    NotTheValidator(AccountId),
    /// The asset registry refused.
    Asset(AssetError),
    /// The channel book refused.
    Purse(PurseBookError),
    /// The name registry refused.
    Name(NameError),
    /// The recovery machinery refused.
    Recovery(RecoveryError),
    /// This equivocation has already been punished.
    Slashing(SlashingError),
    /// Arithmetic overflowed. Never silently wrapped.
    Overflow,
    /// This transaction kind has no implementation yet.
    ///
    /// A placeholder, not a design. A chain must not be run while any kind can
    /// return this.
    NotImplemented {
        /// Which kind.
        kind: &'static str,
    },
}

impl core::fmt::Display for StateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongChain => write!(f, "the transaction is for another chain"),
            Self::UnsupportedVersion(version) => write!(f, "unsupported version {version}"),
            Self::Expired { valid_until, finalized_height } => write!(
                f,
                "expired: valid until finalised height {valid_until}, now {finalized_height}"
            ),
            Self::ForbiddenInProvisional { kind } => {
                write!(f, "{kind} is not permitted in a provisional block")
            }
            Self::NoSuchAccount(id) => write!(f, "no such account {id}"),
            Self::NoSuchDevice(id) => write!(f, "no such device {id}"),
            Self::DeviceRevoked(id) => write!(f, "device {id} is revoked"),
            Self::WrongLane { expected, got } => {
                write!(f, "device owns {expected}, transaction used {got}")
            }
            Self::BadNonce { expected, got } => {
                write!(f, "lane expects sequence {expected}, got {got}")
            }
            Self::InsufficientBalance { needed, available, .. } => {
                write!(f, "needed {needed}, available {available}")
            }
            Self::NomadCreditExhausted { device, needed, remaining } => write!(
                f,
                "device {device} would spend {needed} offline with {remaining} of its credit left"
            ),
            Self::NomadOverAllocated { allocated, credit } => {
                write!(f, "device shares total {allocated}, declared credit is {credit}")
            }
            Self::LaneAlreadyUsed(lane) => write!(f, "{lane} is already allocated"),
            Self::DeviceWasRevoked(id) => write!(f, "device {id} was revoked and cannot return"),
            Self::DeviceAlreadyExists(id) => write!(f, "device {id} already exists"),
            Self::ZeroTrancheValue => write!(f, "a channel tranche cannot be worth nothing"),
            Self::BadEvidence(error) => write!(f, "{error}"),
            Self::UnknownAccusedDevice(id) => write!(f, "the accused holds no device {id}"),
            Self::NotTheValidator(id) => write!(f, "no device of {id} signed both blocks"),
            Self::Asset(error) => write!(f, "{error}"),
            Self::Purse(error) => write!(f, "{error}"),
            Self::Name(error) => write!(f, "{error}"),
            Self::Recovery(error) => write!(f, "{error}"),
            Self::Slashing(error) => write!(f, "{error}"),
            Self::Overflow => write!(f, "arithmetic overflow"),
            Self::NotImplemented { kind } => write!(f, "{kind} is not implemented yet"),
        }
    }
}

impl std::error::Error for StateError {}

impl From<AssetError> for StateError {
    fn from(error: AssetError) -> Self {
        Self::Asset(error)
    }
}

impl From<PurseBookError> for StateError {
    fn from(error: PurseBookError) -> Self {
        Self::Purse(error)
    }
}

impl From<NameError> for StateError {
    fn from(error: NameError) -> Self {
        Self::Name(error)
    }
}

impl From<RecoveryError> for StateError {
    fn from(error: RecoveryError) -> Self {
        Self::Recovery(error)
    }
}

impl From<SlashingError> for StateError {
    fn from(error: SlashingError) -> Self {
        Self::Slashing(error)
    }
}

/// The ledger.
///
/// # On recomputing the root
///
/// [`Ledger::state_root`] rebuilds the sparse Merkle tree from scratch. That is
/// correct and it is not what a production node should do — it needs an
/// incremental tree so that a block touching ten accounts costs ten paths. The
/// interface is the one such a tree would expose; the cost is the placeholder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ledger {
    accounts: BTreeMap<AccountId, Account>,
    /// Open micro-payment channels.
    purses: PurseBook,
    /// Local assets and their issuance rules.
    assets: AssetRegistry,
    /// Registered names and pending commitments.
    names: NameBook,
    /// Recoveries in progress.
    recoveries: RecoveryBook,
    /// Equivocations already punished.
    offences: SlashingBook,
    /// Total VAN destroyed. "La part du feu."
    burned: Amount,
    /// The context pot that funds delivery bounties and finder commissions.
    context_pot: Amount,
    /// Every fee ever paid, before it was split.
    ///
    /// Cumulative since genesis, like the emission counter it is compared
    /// against. `docs/05-emission.pdf` §4 requires every header to publish the
    /// ratio of real fees to emission — "la part du réseau qui vit de son usage
    /// plutôt que de la subvention" — and R1.5 makes it a go/no-go criterion
    /// for opening Tier 2. It is tracked here because it is the only place that
    /// sees a fee before it becomes three other numbers.
    fees_collected: Amount,
}

impl Ledger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An account, if it exists.
    #[must_use]
    pub fn account(&self, id: &AccountId) -> Option<&Account> {
        self.accounts.get(id)
    }

    /// Inserts or replaces an account. For genesis construction and tests.
    pub fn put_account(&mut self, id: AccountId, account: Account) {
        self.accounts.insert(id, account);
    }

    /// The open channels.
    #[must_use]
    pub fn purses(&self) -> &PurseBook {
        &self.purses
    }

    /// The asset registry.
    #[must_use]
    pub fn assets(&self) -> &AssetRegistry {
        &self.assets
    }

    /// Registered names and pending commitments.
    #[must_use]
    pub fn names(&self) -> &NameBook {
        &self.names
    }

    /// Recoveries in progress.
    #[must_use]
    pub fn recoveries(&self) -> &RecoveryBook {
        &self.recoveries
    }

    /// Equivocations already punished.
    #[must_use]
    pub fn offences(&self) -> &SlashingBook {
        &self.offences
    }

    /// How much VAN has been destroyed.
    #[must_use]
    pub fn burned(&self) -> Amount {
        self.burned
    }

    /// The context pot's balance.
    #[must_use]
    pub fn context_pot(&self) -> Amount {
        self.context_pot
    }

    /// Every fee ever paid, before splitting.
    #[must_use]
    pub fn total_fees(&self) -> Amount {
        self.fees_collected
    }

    /// The health metric a header publishes: fees over emission.
    ///
    /// Returned as the two integers it was computed from rather than as a
    /// number, because there is no floating point in this protocol and because
    /// a reader learns more from the pair than from the quotient.
    ///
    /// **Cumulative, not per-epoch.** The design document does not say which,
    /// and cumulative is the choice here: it is stable against a quiet hour,
    /// and an auditor holding two headers can derive the interval between them
    /// by subtraction, which is not true the other way round.
    #[must_use]
    pub fn fee_emission_ratio(&self, emitted_supply: Amount) -> Ratio {
        Ratio::new(self.fees_collected.as_ulf(), emitted_supply.as_ulf())
    }

    /// Every VAN the ledger holds: in balances, in bonds, and locked in
    /// channels.
    ///
    /// Used by the conservation test — no transition may create or destroy
    /// value except through the fee burn, which is accounted separately — so it
    /// has to count the money that is *not* in an account. A deposit sitting in
    /// an open channel has left its owner's balance and has not been paid to
    /// anybody; forgetting it would make every channel look like a burn.
    #[must_use]
    pub fn total_native_balance(&self) -> Option<Amount> {
        let in_accounts = Amount::checked_sum(
            self.accounts.values().flat_map(|account| [account.balance(None), account.bonded]),
        )?;
        let in_channels = Amount::checked_sum(
            self.purses
                .iter()
                .filter(|(_, purse)| purse.asset.is_none())
                .map(|(_, purse)| purse.deposit),
        )?;
        in_accounts.checked_add(in_channels)
    }

    /// Builds the state tree.
    ///
    /// Every key goes through [`crate::keys`], so that accounts, channels,
    /// assets and ticker reservations occupy separate namespaces and a proof
    /// carries a statement about *what kind of thing* lives at a key rather
    /// than leaving a verifier to guess from the value's shape.
    fn tree(&self) -> SparseMerkleTree {
        let mut tree = SparseMerkleTree::new();
        for (id, account) in &self.accounts {
            tree.insert(keys::account(id), account.value_hash());
        }
        for (id, purse) in self.purses.iter() {
            tree.insert(keys::purse(id), PurseBook::value_hash(purse));
        }
        for (id, record) in self.assets.iter() {
            tree.insert(keys::asset(id), record.value_hash());
        }
        for (name, id) in self.assets.tickers() {
            tree.insert(keys::ticker(name), *id.as_hash());
        }
        for (name, owner) in self.names.iter() {
            tree.insert(keys::name(name), *owner.as_hash());
        }
        for (digest, record) in self.names.commitments() {
            tree.insert(keys::commitment(digest), record.value_hash());
        }
        for (target, pending) in self.recoveries.iter() {
            tree.insert(keys::recovery(target), pending.value_hash());
        }
        for offence in self.offences.account_offences() {
            let digest = SlashingBook::digest(offence);
            tree.insert(keys::offence(&digest), digest);
        }
        for offence in self.offences.validator_offences() {
            let digest = SlashingBook::digest(offence);
            tree.insert(keys::offence(&digest), digest);
        }
        tree.insert(
            Self::burn_key(),
            reserved_value(self.burned, self.context_pot, self.fees_collected),
        );
        tree
    }

    /// The state root.
    #[must_use]
    pub fn state_root(&self) -> Hash {
        self.tree().root()
    }

    /// A proof about one account, against [`Ledger::state_root`].
    #[must_use]
    pub fn prove_account(&self, id: &AccountId) -> crate::smt::SmtProof {
        self.tree().prove(&keys::account(id))
    }

    /// A proof about one channel.
    #[must_use]
    pub fn prove_purse(&self, id: &PurseId) -> crate::smt::SmtProof {
        self.tree().prove(&keys::purse(id))
    }

    /// A proof that a ticker is taken, or that it is free.
    ///
    /// The non-inclusion half is the interesting one: it is how a wallet checks
    /// that a name is available without trusting the node that told it so.
    #[must_use]
    pub fn prove_ticker(&self, name: &Name) -> crate::smt::SmtProof {
        self.tree().prove(&keys::ticker(name))
    }

    /// The reserved key under which the burn and pot counters live.
    ///
    /// A fixed key rather than a side channel, so that the state root commits
    /// to them and a light client can prove how much has been destroyed. It
    /// sits in its own namespace, so no identifier of any other kind can reach
    /// it even in principle.
    #[must_use]
    pub fn burn_key() -> Hash {
        keys::reserved(b"burn and context pot")
    }

    /// Applies one transaction, entirely or not at all.
    ///
    /// The signature is assumed already verified; see the module documentation.
    ///
    /// # All or nothing
    ///
    /// A transaction that fails leaves the ledger byte-for-byte as it was —
    /// including the fee, including the nonce. There is no "the fee was taken
    /// but the transfer bounced" state, because a protocol with two kinds of
    /// failure has two kinds of bug and a state root that depends on which one
    /// happened.
    ///
    /// This is achieved by working on a copy and committing on success, which
    /// is correct and expensive. A production ledger wants a journalled overlay
    /// that records the touched keys and rolls them back; the property it has
    /// to preserve is exactly the one asserted by
    /// `a_failed_transaction_changes_nothing` below.
    pub fn apply(&mut self, ctx: &BlockContext, body: &TxBody) -> Result<Applied, StateError> {
        let mut working = self.clone();
        let applied = working.apply_in_place(ctx, body)?;
        *self = working;
        Ok(applied)
    }

    fn apply_in_place(
        &mut self,
        ctx: &BlockContext,
        body: &TxBody,
    ) -> Result<Applied, StateError> {
        self.check_envelope(ctx, body)?;
        let (lane, device_id) = self.check_authority(body)?;

        // What this transaction takes out of the account in VAN. The fee always
        // counts; a VAN transfer counts on top of it. This is the number the
        // offline credit is measured against, and it deliberately includes the
        // fee: an attacker who could pay unlimited fees offline would drain the
        // account past its declared ceiling by a route the merchant never saw.
        let native_outflow = self.native_outflow(body)?;

        let nomad_consumed = if ctx.rung == FinalityRung::Provisional {
            self.check_nomad(body, device_id, native_outflow)?;
            native_outflow
        } else {
            Amount::ZERO
        };

        let fee = FeeSplit::of(body.fee);
        self.charge_fee(ctx, body, fee)?;
        self.apply_kind(ctx, body)?;

        // Consume the nonce last, so that a rejected transaction leaves the
        // lane exactly where it was and can be retried.
        let account = self.accounts.get_mut(&body.account).ok_or(
            StateError::NoSuchAccount(body.account),
        )?;
        if !account.lanes.consume(body.nonce) {
            return Err(StateError::BadNonce {
                expected: account.lanes.next_sequence(lane),
                got: body.nonce.sequence,
            });
        }
        if !nomad_consumed.is_zero() {
            if let Some(device) = account.devices.get_mut(&device_id) {
                device.nomad_spent =
                    device.nomad_spent.checked_add(nomad_consumed).ok_or(StateError::Overflow)?;
            }
        }

        Ok(Applied { fee, nomad_consumed })
    }

    /// Clears every device's offline spending counter.
    ///
    /// Called when the chain regains rung-2 finality: the offline credit is a
    /// per-outage allowance, not a lifetime one. Doing this on reconnection
    /// rather than continuously is what makes the merchant's guarantee
    /// meaningful — the ceiling applies to the partition the merchant is
    /// standing in.
    pub fn settle_nomad_counters(&mut self) {
        for account in self.accounts.values_mut() {
            for device in account.devices.values_mut() {
                device.nomad_spent = Amount::ZERO;
            }
        }
    }

    // --- internals --------------------------------------------------------

    fn check_envelope(&self, ctx: &BlockContext, body: &TxBody) -> Result<(), StateError> {
        if body.version != TX_VERSION {
            return Err(StateError::UnsupportedVersion(body.version));
        }
        if body.chain != ctx.chain {
            return Err(StateError::WrongChain);
        }
        if let Some(valid_until) = body.valid_until_finalized {
            if ctx.finalized_height > valid_until {
                return Err(StateError::Expired {
                    valid_until,
                    finalized_height: ctx.finalized_height,
                });
            }
        }
        if ctx.rung == FinalityRung::Provisional && !body.kind.allowed_in_provisional() {
            return Err(StateError::ForbiddenInProvisional { kind: body.kind.name() });
        }
        Ok(())
    }

    fn check_authority(&self, body: &TxBody) -> Result<(Lane, DeviceId), StateError> {
        let account =
            self.accounts.get(&body.account).ok_or(StateError::NoSuchAccount(body.account))?;
        if account.revoked_devices.contains(&body.device) {
            return Err(StateError::DeviceRevoked(body.device));
        }
        let device =
            account.devices.get(&body.device).ok_or(StateError::NoSuchDevice(body.device))?;
        if device.lane != body.nonce.lane {
            return Err(StateError::WrongLane { expected: device.lane, got: body.nonce.lane });
        }
        if !account.lanes.accepts(body.nonce) {
            return Err(StateError::BadNonce {
                expected: account.lanes.next_sequence(body.nonce.lane),
                got: body.nonce.sequence,
            });
        }
        Ok((device.lane, body.device))
    }

    fn native_outflow(&self, body: &TxBody) -> Result<Amount, StateError> {
        let extra = match &body.kind {
            TxKind::Transfer { asset: None, amount, .. } => *amount,
            TxKind::PurseOpen { asset: None, deposit, .. } => *deposit,
            TxKind::Bond { amount, .. } => *amount,
            _ => Amount::ZERO,
        };
        body.fee.checked_add(extra).ok_or(StateError::Overflow)
    }

    fn check_nomad(
        &self,
        body: &TxBody,
        device_id: DeviceId,
        outflow: Amount,
    ) -> Result<(), StateError> {
        let Some(account) = self.accounts.get(&body.account) else {
            return Err(StateError::NoSuchAccount(body.account));
        };
        let Some(device) = account.devices.get(&device_id) else {
            return Err(StateError::NoSuchDevice(device_id));
        };
        let remaining = device.nomad_remaining();
        if outflow > remaining {
            return Err(StateError::NomadCreditExhausted {
                device: device_id,
                needed: outflow,
                remaining,
            });
        }
        Ok(())
    }

    fn charge_fee(
        &mut self,
        ctx: &BlockContext,
        body: &TxBody,
        fee: FeeSplit,
    ) -> Result<(), StateError> {
        let payer =
            self.accounts.get_mut(&body.account).ok_or(StateError::NoSuchAccount(body.account))?;
        let available = payer.balance(None);
        payer.debit(None, body.fee).ok_or(StateError::InsufficientBalance {
            asset: None,
            needed: body.fee,
            available,
        })?;

        self.burned = self.burned.checked_add(fee.burn).ok_or(StateError::Overflow)?;
        self.context_pot =
            self.context_pot.checked_add(fee.pot).ok_or(StateError::Overflow)?;
        self.fees_collected =
            self.fees_collected.checked_add(body.fee).ok_or(StateError::Overflow)?;

        let proposer = self.accounts.entry(ctx.proposer).or_default();
        proposer.credit(None, fee.provider).ok_or(StateError::Overflow)?;
        Ok(())
    }

    fn apply_kind(&mut self, ctx: &BlockContext, body: &TxBody) -> Result<(), StateError> {
        match &body.kind {
            TxKind::Transfer { to, asset, amount } => {
                self.transfer(body.account, *to, *asset, *amount)
            }
            TxKind::NomadSet { credit, margin } => self.nomad_set(body.account, *credit, *margin),
            TxKind::DeviceAdd { key, lane, nomad_share } => {
                self.device_add(body.account, key, *lane, *nomad_share)
            }
            TxKind::DeviceRevoke { device } => self.device_revoke(body.account, *device),
            TxKind::Bond { amount, .. } => self.bond(body.account, *amount),
            TxKind::Unbond { amount } => self.unbond(body.account, *amount),

            TxKind::PurseOpen {
                counterparty,
                asset,
                deposit,
                payword_root,
                tranche_value,
                expiry_finalized_height,
            } => self.purse_open(
                body.id(),
                body.account,
                *counterparty,
                *asset,
                *deposit,
                *payword_root,
                *tranche_value,
                *expiry_finalized_height,
            ),
            TxKind::PurseCloseCooperative { purse, payer_balance, payee_balance, .. } => {
                self.purse_close_cooperative(purse, body.account, *payer_balance, *payee_balance)
            }
            TxKind::PurseCloseUnilateral { purse, tranches_claimed, payword_token } => self
                .purse_close_unilateral(
                    ctx,
                    purse,
                    body.account,
                    *tranches_claimed,
                    *payword_token,
                ),
            TxKind::PurseDispute { purse, tranches_claimed, payword_token } => {
                let token = PayWordToken { index: *tranches_claimed, link: *payword_token };
                self.purses.dispute(purse, *tranches_claimed, &token)?;
                Ok(())
            }

            TxKind::AssetCreate { ticker, decimals, reissuable } => {
                let id = asset_id_of(body.account, body.id());
                self.assets.create(id, body.account, ticker.clone(), *decimals, *reissuable)?;
                Ok(())
            }
            TxKind::AssetMint { asset, to, amount } => {
                self.asset_mint(body.account, *asset, *to, *amount)
            }
            TxKind::AssetBurn { asset, amount } => self.asset_burn(body.account, *asset, *amount),

            TxKind::NameCommit { commitment } => {
                self.names.commit(*commitment, body.account, ctx.finalized_height)?;
                Ok(())
            }
            TxKind::NameReveal { name, salt } => {
                self.names.reveal(name, salt, body.account, ctx.finalized_height)?;
                Ok(())
            }

            TxKind::GuardianSet { guardians, threshold } => {
                let account =
                    self.accounts.get_mut(&body.account).ok_or(StateError::NoSuchAccount(body.account))?;
                account.guardians = guardians.clone();
                account.guardian_threshold = *threshold;
                Ok(())
            }
            TxKind::RecoveryStart { account, new_root_key } => {
                self.recovery_approve(ctx, *account, new_root_key, body.account)
            }
            TxKind::RecoveryCancel { account } => {
                // Only the account itself may cancel, and "itself" means a
                // device that still works — which is precisely the owner the
                // window exists to protect.
                if *account != body.account {
                    return Err(StateError::Recovery(RecoveryError::NotRecovering));
                }
                self.recoveries.cancel(account)?;
                Ok(())
            }
            TxKind::RecoveryFinalise { account } => self.recovery_finalise(ctx, *account),

            TxKind::AccountEquivocation(evidence) => {
                self.punish_account_equivocation(evidence, body.account)
            }
            TxKind::ValidatorEquivocation(evidence) => {
                self.punish_validator_equivocation(evidence, body.account)
            }

            other => Err(StateError::NotImplemented { kind: other.name() }),
        }
    }

    fn recovery_approve(
        &mut self,
        ctx: &BlockContext,
        target: AccountId,
        new_root_key: &vanargand_crypto::sign::VerifyingKey,
        guardian: AccountId,
    ) -> Result<(), StateError> {
        let account = self.accounts.get(&target).ok_or(StateError::NoSuchAccount(target))?;
        let guardians = account.guardians.clone();
        let window = ContestationWindow {
            opened_at_finalized: ctx.finalized_height,
            duration: RECOVERY_WINDOW_FINALIZED_BLOCKS,
        };
        self.recoveries.approve(target, new_root_key, guardian, &guardians, window)?;
        Ok(())
    }

    /// Completes a recovery: the new root key replaces the account's devices.
    ///
    /// Every existing device is **revoked**, not merely displaced. A recovery
    /// happens because the old devices are gone or compromised; leaving one of
    /// them able to sign would make the recovery pointless in the first case
    /// and dangerous in the second. Revoked identifiers are remembered for
    /// ever, so none of them can be added back.
    fn recovery_finalise(
        &mut self,
        ctx: &BlockContext,
        target: AccountId,
    ) -> Result<(), StateError> {
        let threshold = self
            .accounts
            .get(&target)
            .ok_or(StateError::NoSuchAccount(target))?
            .guardian_threshold;
        let new_root_key = self.recoveries.finalise(&target, threshold, ctx.finalized_height)?;

        let account = self.accounts.get_mut(&target).ok_or(StateError::NoSuchAccount(target))?;
        let displaced: Vec<DeviceId> = account.devices.keys().copied().collect();
        for device in displaced {
            account.devices.remove(&device);
            account.revoked_devices.insert(device);
        }

        let device_id = DeviceId::of_device_key(&new_root_key);
        let lane = account.next_lane;
        account.devices.insert(
            device_id,
            Device {
                key: new_root_key,
                lane,
                nomad_share: Amount::ZERO,
                nomad_spent: Amount::ZERO,
            },
        );
        account.next_lane = lane.next().ok_or(StateError::Overflow)?;
        // A recovered account starts with no offline credit. It has just proved
        // it lost control of its devices, and the nomad credit is a promise
        // made to strangers about what they can safely accept from it.
        account.nomad_credit = Amount::ZERO;
        Ok(())
    }

    /// Punishes an account equivocation — R2's self-proving fraud.
    ///
    /// Because a nomad spend travels on one device's sequenced lane, spending
    /// the same offline credit in two partitions *necessarily* produces this
    /// object. It is not detected; the act manufactures it.
    ///
    /// The bonded margin is seized and split: half to whoever published the
    /// proof, half to the fire. An account that never bonded a margin is still
    /// convicted, and there is simply nothing to take — R2 makes bonding
    /// optional, and the deterrent in that case is the cascade invalidation of
    /// the losing spend rather than a seizure.
    fn punish_account_equivocation(
        &mut self,
        evidence: &vanargand_types::tx::AccountEquivocation,
        denouncer: AccountId,
    ) -> Result<(), StateError> {
        let accused = evidence.first.body.account;
        let account = self.accounts.get(&accused).ok_or(StateError::NoSuchAccount(accused))?;
        let device = account
            .devices
            .get(&evidence.device)
            .ok_or(StateError::UnknownAccusedDevice(evidence.device))?;

        evidence.check(&device.key).map_err(StateError::BadEvidence)?;

        self.offences.record_account(AccountOffence {
            account: accused,
            device: evidence.device,
            lane: evidence.first.body.nonce.lane,
            sequence: evidence.first.body.nonce.sequence,
        })?;

        let account =
            self.accounts.get_mut(&accused).ok_or(StateError::NoSuchAccount(accused))?;
        let penalty = Penalty::split(account.nomad_margin);
        account.nomad_margin = Amount::ZERO;
        self.pay_penalty(penalty, denouncer)
    }

    /// Punishes a validator equivocation (A2): bond destroyed, exclusion.
    ///
    /// The evidence names an account but not which of its device keys signed
    /// the blocks, so every device is tried. That is correct — any device of
    /// the account signing two blocks at one height is the account
    /// equivocating — and it is also a sign that a validator ought to register
    /// a dedicated block-signing key when it bonds. `vanargand-consensus`
    /// already models one; `TxKind::Bond` does not carry it. **(open)**
    fn punish_validator_equivocation(
        &mut self,
        evidence: &vanargand_types::block::ValidatorEquivocation,
        denouncer: AccountId,
    ) -> Result<(), StateError> {
        let accused = evidence.validator;
        let account = self.accounts.get(&accused).ok_or(StateError::NoSuchAccount(accused))?;

        let signed_by_the_accused =
            account.devices.values().any(|device| evidence.check(&device.key).is_ok());
        if !signed_by_the_accused {
            return Err(StateError::NotTheValidator(accused));
        }

        self.offences.record_validator(ValidatorOffence {
            validator: accused,
            height: evidence.first.header.height,
        })?;

        let account =
            self.accounts.get_mut(&accused).ok_or(StateError::NoSuchAccount(accused))?;
        let penalty = Penalty::split(account.bonded);
        account.bonded = Amount::ZERO;
        self.pay_penalty(penalty, denouncer)
    }

    /// Pays a seizure out: half to the denouncer, half destroyed.
    fn pay_penalty(&mut self, penalty: Penalty, denouncer: AccountId) -> Result<(), StateError> {
        if penalty.is_empty() {
            return Ok(());
        }
        self.burned = self.burned.checked_add(penalty.burned).ok_or(StateError::Overflow)?;
        self.accounts
            .entry(denouncer)
            .or_default()
            .credit(None, penalty.to_denouncer)
            .ok_or(StateError::Overflow)?;
        Ok(())
    }

    /// Opens a channel, locking the deposit.
    ///
    /// The channel's capacity — how many tranches its PayWord chain may pay
    /// for — is **derived**, not declared: `deposit ÷ tranche_value`. There is
    /// no field for it in the transaction and there should not be, because a
    /// declared capacity is a number that can disagree with the money. A payer
    /// cannot spend more than it locked, so the longest useful chain is exactly
    /// the one the deposit pays for.
    #[allow(clippy::too_many_arguments)]
    fn purse_open(
        &mut self,
        id: PurseId,
        payer: AccountId,
        payee: AccountId,
        asset: Option<AssetId>,
        deposit: Amount,
        payword_root: Hash,
        tranche_value: Amount,
        expiry_finalized_height: u64,
    ) -> Result<(), StateError> {
        if tranche_value.is_zero() {
            return Err(StateError::ZeroTrancheValue);
        }
        let tranches = deposit.as_ulf() / tranche_value.as_ulf();
        let capacity = u32::try_from(tranches).unwrap_or(MAX_TRANCHES).min(MAX_TRANCHES);

        let funder = self.accounts.get_mut(&payer).ok_or(StateError::NoSuchAccount(payer))?;
        let available = funder.balance(asset);
        funder.debit(asset, deposit).ok_or(StateError::InsufficientBalance {
            asset,
            needed: deposit,
            available,
        })?;

        let purse = Purse::open(
            payer,
            payee,
            asset,
            deposit,
            payword_root,
            tranche_value,
            capacity,
            expiry_finalized_height,
        )
        .map_err(PurseBookError::Purse)?;
        self.purses.open(id, purse)?;
        Ok(())
    }

    fn purse_close_cooperative(
        &mut self,
        id: &PurseId,
        caller: AccountId,
        to_payer: Amount,
        to_payee: Amount,
    ) -> Result<(), StateError> {
        let payout = self.purses.close_cooperative(id, caller, to_payer, to_payee)?;
        self.credit_payout(&payout)
    }

    fn purse_close_unilateral(
        &mut self,
        ctx: &BlockContext,
        id: &PurseId,
        caller: AccountId,
        tranches_claimed: u32,
        payword_token: Hash,
    ) -> Result<(), StateError> {
        let token = (tranches_claimed > 0)
            .then_some(PayWordToken { index: tranches_claimed, link: payword_token });
        // Anchored to the **finalised** height, never the block's own. A
        // partition raises one freely and cannot move the other, which is the
        // whole of the C9 parade.
        let window = ContestationWindow {
            opened_at_finalized: ctx.finalized_height,
            duration: DISPUTE_WINDOW_FINALIZED_BLOCKS,
        };
        self.purses.begin_unilateral(id, caller, tranches_claimed, token.as_ref(), window)?;
        Ok(())
    }

    fn asset_mint(
        &mut self,
        caller: AccountId,
        asset: AssetId,
        to: AccountId,
        amount: Amount,
    ) -> Result<(), StateError> {
        self.assets.authorise_mint(&asset, caller, amount)?;
        let recipient = self.accounts.entry(to).or_default();
        recipient.credit(Some(asset), amount).ok_or(StateError::Overflow)?;
        Ok(())
    }

    fn asset_burn(
        &mut self,
        caller: AccountId,
        asset: AssetId,
        amount: Amount,
    ) -> Result<(), StateError> {
        let holder = self.accounts.get_mut(&caller).ok_or(StateError::NoSuchAccount(caller))?;
        let available = holder.balance(Some(asset));
        holder.debit(Some(asset), amount).ok_or(StateError::InsufficientBalance {
            asset: Some(asset),
            needed: amount,
            available,
        })?;
        self.assets.record_burn(&asset, amount)?;
        Ok(())
    }

    /// Credits both sides of a settled channel.
    fn credit_payout(&mut self, payout: &Payout) -> Result<(), StateError> {
        if !payout.settlement.to_payer.is_zero() {
            self.accounts
                .entry(payout.payer)
                .or_default()
                .credit(payout.asset, payout.settlement.to_payer)
                .ok_or(StateError::Overflow)?;
        }
        if !payout.settlement.to_payee.is_zero() {
            self.accounts
                .entry(payout.payee)
                .or_default()
                .credit(payout.asset, payout.settlement.to_payee)
                .ok_or(StateError::Overflow)?;
        }
        Ok(())
    }

    /// Settles every channel whose contestation window has elapsed.
    ///
    /// Called once per block by the block processor, **not** by a transaction.
    /// A party owed money should not have to be online and hold a fee to
    /// collect it — and the party most likely to be neither is the one that was
    /// cheated and is waiting for a window to close.
    ///
    /// Takes a **finalised** height, like every other deadline in the protocol.
    pub fn settle_elapsed_purses(
        &mut self,
        current_finalized_height: u64,
    ) -> Result<Vec<Payout>, StateError> {
        let payouts = self.purses.settle_elapsed(current_finalized_height);
        for payout in &payouts {
            self.credit_payout(payout)?;
        }
        Ok(payouts)
    }

    /// Drops name commitments that expired unopened, returning how many.
    ///
    /// The second half of a block's housekeeping, alongside
    /// [`Ledger::settle_elapsed_purses`]. A commitment is opaque, so an
    /// abandoned one is a row nobody can ever interpret — the worst kind to
    /// leave in a state that is meant to stay small for ever.
    pub fn prune_expired_commitments(&mut self, current_finalized_height: u64) -> usize {
        self.names.prune_expired(current_finalized_height)
    }

    fn transfer(
        &mut self,
        from: AccountId,
        to: AccountId,
        asset: Option<AssetId>,
        amount: Amount,
    ) -> Result<(), StateError> {
        let sender = self.accounts.get_mut(&from).ok_or(StateError::NoSuchAccount(from))?;
        let available = sender.balance(asset);
        sender.debit(asset, amount).ok_or(StateError::InsufficientBalance {
            asset,
            needed: amount,
            available,
        })?;
        let recipient = self.accounts.entry(to).or_default();
        recipient.credit(asset, amount).ok_or(StateError::Overflow)?;
        Ok(())
    }

    fn nomad_set(
        &mut self,
        id: AccountId,
        credit: Amount,
        margin: Amount,
    ) -> Result<(), StateError> {
        let account = self.accounts.get_mut(&id).ok_or(StateError::NoSuchAccount(id))?;
        let allocated = account.allocated_nomad().ok_or(StateError::Overflow)?;
        if allocated > credit {
            return Err(StateError::NomadOverAllocated { allocated, credit });
        }
        account.nomad_credit = credit;
        account.nomad_margin = margin;
        Ok(())
    }

    fn device_add(
        &mut self,
        id: AccountId,
        key: &vanargand_crypto::sign::VerifyingKey,
        lane: Lane,
        nomad_share: Amount,
    ) -> Result<(), StateError> {
        let device_id = DeviceId::of_device_key(key);
        let account = self.accounts.get_mut(&id).ok_or(StateError::NoSuchAccount(id))?;

        if account.revoked_devices.contains(&device_id) {
            return Err(StateError::DeviceWasRevoked(device_id));
        }
        if account.devices.contains_key(&device_id) {
            return Err(StateError::DeviceAlreadyExists(device_id));
        }
        if account.devices.values().any(|existing| existing.lane == lane) {
            return Err(StateError::LaneAlreadyUsed(lane));
        }
        // A lane below the high-water mark may have belonged to a revoked
        // device. Reusing it would let an old signature and a new one share a
        // slot and look like equivocation by an account that did nothing.
        if lane < account.next_lane {
            return Err(StateError::LaneAlreadyUsed(lane));
        }

        let allocated = account
            .allocated_nomad()
            .and_then(|total| total.checked_add(nomad_share))
            .ok_or(StateError::Overflow)?;
        if allocated > account.nomad_credit {
            return Err(StateError::NomadOverAllocated {
                allocated,
                credit: account.nomad_credit,
            });
        }

        account.devices.insert(
            device_id,
            Device { key: key.clone(), lane, nomad_share, nomad_spent: Amount::ZERO },
        );
        account.next_lane = lane.next().ok_or(StateError::Overflow)?;
        Ok(())
    }

    fn device_revoke(&mut self, id: AccountId, device: DeviceId) -> Result<(), StateError> {
        let account = self.accounts.get_mut(&id).ok_or(StateError::NoSuchAccount(id))?;
        if account.devices.remove(&device).is_none() {
            return Err(StateError::NoSuchDevice(device));
        }
        account.revoked_devices.insert(device);
        Ok(())
    }

    fn bond(&mut self, id: AccountId, amount: Amount) -> Result<(), StateError> {
        let account = self.accounts.get_mut(&id).ok_or(StateError::NoSuchAccount(id))?;
        let available = account.balance(None);
        account.debit(None, amount).ok_or(StateError::InsufficientBalance {
            asset: None,
            needed: amount,
            available,
        })?;
        account.bonded = account.bonded.checked_add(amount).ok_or(StateError::Overflow)?;
        Ok(())
    }

    fn unbond(&mut self, id: AccountId, amount: Amount) -> Result<(), StateError> {
        // The unbonding delay is a consensus concern and is enforced by
        // `vanargand-consensus`, which knows the epoch. This function performs
        // the accounting only. Splitting it this way is what keeps the ledger
        // free of a clock.
        let account = self.accounts.get_mut(&id).ok_or(StateError::NoSuchAccount(id))?;
        account.bonded = account.bonded.checked_sub(amount).ok_or(
            StateError::InsufficientBalance {
                asset: None,
                needed: amount,
                available: account.bonded,
            },
        )?;
        account.credit(None, amount).ok_or(StateError::Overflow)?;
        Ok(())
    }
}

/// The digest stored under the reserved key: the burn, the pot, and the fees.
///
/// All three are committed to the state root so that a light client can prove
/// how much has been destroyed and how much of the network's income is real —
/// which is what makes "toute prime provient de frais déjà payés" checkable
/// rather than asserted.
fn reserved_value(burned: Amount, pot: Amount, fees: Amount) -> Hash {
    let mut encoder = vanargand_types::codec::Encoder::new();
    vanargand_types::codec::Encode::encode(&burned, &mut encoder);
    vanargand_types::codec::Encode::encode(&pot, &mut encoder);
    vanargand_types::codec::Encode::encode(&fees, &mut encoder);
    vanargand_crypto::hash::hash(vanargand_crypto::hash::domain::STATE_VALUE, &encoder.finish())
}
