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

use vanargand_types::amount::FeeSplit;
use vanargand_types::block::FinalityRung;
use vanargand_types::id::{AccountId, AssetId, ChainId, DeviceId};
use vanargand_types::nonce::Lane;
use vanargand_types::tx::{TxBody, TxKind, TX_VERSION};
use vanargand_types::{Amount, Hash};

use crate::account::{Account, Device};
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
            Self::Overflow => write!(f, "arithmetic overflow"),
            Self::NotImplemented { kind } => write!(f, "{kind} is not implemented yet"),
        }
    }
}

impl std::error::Error for StateError {}

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
    /// Total VAN destroyed. "La part du feu."
    burned: Amount,
    /// The context pot that funds delivery bounties and finder commissions.
    context_pot: Amount,
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

    /// Every VAN held by an account, summed.
    ///
    /// Used by the conservation test: no transition may create or destroy value
    /// except through the fee burn, which is accounted separately.
    #[must_use]
    pub fn total_native_balance(&self) -> Option<Amount> {
        Amount::checked_sum(self.accounts.values().flat_map(|account| {
            [account.balance(None), account.bonded]
        }))
    }

    /// The state root.
    #[must_use]
    pub fn state_root(&self) -> Hash {
        let mut tree = SparseMerkleTree::new();
        for (id, account) in &self.accounts {
            tree.insert(*id.as_hash(), account.value_hash());
        }
        tree.insert(Self::burn_key(), burn_value(self.burned, self.context_pot));
        tree.root()
    }

    /// A proof about one account, against [`Ledger::state_root`].
    #[must_use]
    pub fn prove_account(&self, id: &AccountId) -> crate::smt::SmtProof {
        let mut tree = SparseMerkleTree::new();
        for (key, account) in &self.accounts {
            tree.insert(*key.as_hash(), account.value_hash());
        }
        tree.insert(Self::burn_key(), burn_value(self.burned, self.context_pot));
        tree.prove(id.as_hash())
    }

    /// The reserved key under which the burn and pot counters live.
    ///
    /// A fixed key rather than a side channel, so that the state root commits
    /// to them and a light client can prove how much has been destroyed. The
    /// key is the digest of a fixed string, so no account can ever derive it:
    /// an account identifier is the hash of a public key, and hitting this
    /// value would need a preimage.
    #[must_use]
    pub fn burn_key() -> Hash {
        vanargand_crypto::hash::hash(
            vanargand_crypto::hash::domain::STATE_VALUE,
            b"vanargand reserved: burn and context pot",
        )
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
        self.apply_kind(body)?;

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

        let proposer = self.accounts.entry(ctx.proposer).or_default();
        proposer.credit(None, fee.provider).ok_or(StateError::Overflow)?;
        Ok(())
    }

    fn apply_kind(&mut self, body: &TxBody) -> Result<(), StateError> {
        match &body.kind {
            TxKind::Transfer { to, asset, amount } => self.transfer(body.account, *to, *asset, *amount),
            TxKind::NomadSet { credit, margin } => self.nomad_set(body.account, *credit, *margin),
            TxKind::DeviceAdd { key, lane, nomad_share } => {
                self.device_add(body.account, key, *lane, *nomad_share)
            }
            TxKind::DeviceRevoke { device } => self.device_revoke(body.account, *device),
            TxKind::Bond { amount, .. } => self.bond(body.account, *amount),
            TxKind::Unbond { amount } => self.unbond(body.account, *amount),
            other => Err(StateError::NotImplemented { kind: other.name() }),
        }
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

/// The digest stored under the reserved burn key.
fn burn_value(burned: Amount, pot: Amount) -> Hash {
    let mut encoder = vanargand_types::codec::Encoder::new();
    vanargand_types::codec::Encode::encode(&burned, &mut encoder);
    vanargand_types::codec::Encode::encode(&pot, &mut encoder);
    vanargand_crypto::hash::hash(vanargand_crypto::hash::domain::STATE_VALUE, &encoder.finish())
}
