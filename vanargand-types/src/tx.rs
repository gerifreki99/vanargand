// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transactions: the envelope, the kinds, and the partition grammar.
//!
//! See `spec/draft/04-transactions.md`.
//!
//! # Every kind is "provable"
//!
//! R2's answer to A7 — a two-thirds-corrupt committee finalising an invalid
//! state that no light client can detect — is a fraud proof over state
//! transitions, and that only works if the transitions are few, fixed and
//! strictly deterministic. The constraint lands here: a transaction kind may
//! not depend on anything outside its own bytes and the state it names. No
//! clock, no randomness the protocol did not derive, no iteration over an
//! unordered collection, no virtual machine.
//!
//! # The partition grammar
//!
//! [`TxKind::allowed_in_provisional`] is the C9 parade. Some transactions are
//! **grammatically illegal** in a provisional block rather than merely
//! discouraged, because the party they could harm may be on the other side of
//! the partition and unable to object. The function is written as an exhaustive
//! match with no wildcard, so adding a kind does not compile until somebody has
//! answered the question "what happens if this is published while half the
//! network cannot see it?".

use core::fmt;

use vanargand_crypto::hash::{domain, Hash, Hasher};
use vanargand_crypto::sign::{Signature, VerifyingKey};

use crate::amount::Amount;
use crate::block::ValidatorEquivocation;
use crate::codec::{CodecError, Decode, Decoder, Encode, Encoder};
use crate::id::{AccountId, AssetId, ChainId, DeviceId, TxId};
use crate::name::Name;
use crate::nonce::{Lane, Nonce};

/// The transaction format version this build writes.
pub const TX_VERSION: u16 = 1;

/// What a transaction does.
///
/// Discriminants are **frozen**. A removed variant keeps its number reserved
/// forever: reusing it would let a transaction written under the old rules be
/// reinterpreted under the new ones. Zero is reserved and always invalid, so
/// that a zeroed buffer fails rather than selecting something.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TxKind {
    /// Move value. The ledger's principal operation.
    Transfer {
        /// Recipient.
        to: AccountId,
        /// Which asset, or `None` for VAN itself.
        ///
        /// The native asset is absence rather than a reserved identifier, so
        /// that the common case is also the smallest encoding and there is no
        /// "the VAN asset id" to forge.
        asset: Option<AssetId>,
        /// How much.
        amount: Amount,
    },

    /// Declare the offline credit, and optionally bond a margin behind it.
    ///
    /// R1.3's central design change. The account publishes, in advance and to
    /// everyone, the fraction of its balance it may spend while cut off. A
    /// merchant then knows what it risks *ex ante* rather than repairing it
    /// *ex post*: at worst the declared credit, never a fortune from nowhere.
    ///
    /// The optional `margin` is R2's bonded version: prove the equivocation,
    /// seize the margin, compensate the victims, burn a share. A bounced
    /// cheque that denounces itself.
    NomadSet {
        /// The offline credit.
        credit: Amount,
        /// Bonded margin behind it. Zero for the unbonded form.
        margin: Amount,
    },

    /// Add a device subkey, with its own nonce lane and its own share of the
    /// nomad credit.
    ///
    /// The per-device split is R2's correction and it is not an optimisation:
    /// with an account-wide credit, two honest devices of one account, each
    /// isolated in its own partition, would produce an equivocation and be
    /// punished for it.
    DeviceAdd {
        /// The device's public key.
        key: VerifyingKey,
        /// The lane this device will use. Never reused, even after revocation.
        lane: Lane,
        /// This device's share of the account's nomad credit.
        nomad_share: Amount,
    },

    /// Revoke a device subkey.
    DeviceRevoke {
        /// Which device.
        device: DeviceId,
    },

    /// First half of a name registration: publish a sealed commitment.
    ///
    /// Commit-and-reveal, applied per R1.7 after the omission was recognised.
    /// Without it, a validator that sees a `NameReveal` in the mempool can
    /// register the name first — F4, front-running, against exactly the kind of
    /// object where being first is the whole value.
    NameCommit {
        /// `H[name commitment](canonical(name) ‖ salt ‖ account_id)`.
        commitment: Hash,
    },

    /// Second half: open the commitment.
    NameReveal {
        /// The name.
        name: Name,
        /// The salt used in the commitment.
        salt: [u8; 32],
    },

    /// Set the guardians and threshold for social recovery.
    GuardianSet {
        /// The guardians.
        ///
        /// A `BTreeSet` rather than a `Vec`, so that the canonical encoding is
        /// a property of the type rather than a rule someone has to remember.
        /// A duplicate guardian would count twice towards the threshold,
        /// quietly turning a three-of-five recovery into a two-of-five one,
        /// and the type makes that unrepresentable rather than merely invalid.
        guardians: std::collections::BTreeSet<AccountId>,
        /// How many must co-sign.
        threshold: u32,
    },

    /// Begin recovery of an account onto a new root key.
    ///
    /// Opens a contestation window during which the old device can cancel.
    /// G4 — collusion or phishing of the guardians — is not solved by this and
    /// is not claimed to be; it is an attack on people, and the window,
    /// the threshold and the notifications are mitigations, not a proof.
    RecoveryStart {
        /// The account being recovered.
        account: AccountId,
        /// Its proposed new root key.
        new_root_key: VerifyingKey,
    },

    /// Cancel a recovery in progress. Signed by a still-live device.
    RecoveryCancel {
        /// The account.
        account: AccountId,
    },

    /// Complete a recovery whose window has elapsed **in finalised height**.
    RecoveryFinalise {
        /// The account.
        account: AccountId,
    },

    /// Become a validator candidate: lock a bond and seal a commitment chain.
    ///
    /// Sealing the chain root at bond time is what makes the epoch randomness
    /// unchooseable (A4): proposing a block reveals the next link, which the
    /// proposer cannot pick because the chain was fixed before it knew
    /// anything, and cannot withhold without missing its turn.
    Bond {
        /// How much to lock.
        amount: Amount,
        /// Root of the sealed commitment chain.
        commitment_root: Hash,
    },

    /// Begin withdrawing a bond. Matures after the unbonding delay, counted in
    /// finalised height.
    Unbond {
        /// How much to withdraw.
        amount: Amount,
    },

    /// Open a two-party micro-payment channel — a *bourse*.
    ///
    /// Strictly two parties (R1.6): multi-party channels are a research topic,
    /// and groups go through a hub or through unanimous locking.
    PurseOpen {
        /// The other party.
        counterparty: AccountId,
        /// Which asset, or `None` for VAN.
        asset: Option<AssetId>,
        /// Amount locked by the opener.
        deposit: Amount,
        /// Root of the payer's PayWord chain.
        payword_root: Hash,
        /// What one PayWord token is worth.
        tranche_value: Amount,
        /// Expiry, in **finalised** height.
        expiry_finalized_height: u64,
    },

    /// Close a channel with both parties' agreement.
    ///
    /// Whitelisted in provisional blocks by R2: a closure both parties signed
    /// cannot defraud either of them, so there is no absent victim and no
    /// reason to forbid it offline. The application prompts the user to close
    /// their channels before a planned outage for exactly this reason.
    PurseCloseCooperative {
        /// The channel, identified by the transaction that opened it.
        purse: TxId,
        /// Final balance to the opener.
        payer_balance: Amount,
        /// Final balance to the counterparty.
        payee_balance: Amount,
        /// The counterparty's signature over the same final state.
        counterparty_signature: Signature,
    },

    /// Close a channel unilaterally, claiming a number of spent tranches.
    ///
    /// **Grammatically forbidden in provisional blocks.** This is C9 itself:
    /// publish a stale unilateral closure while the counterparty and its
    /// watchtower are on the far side of a partition, and the contestation
    /// window runs out in a world where the objector cannot exist. Forbidding
    /// the transaction offline, and counting the window only in finalised
    /// height, closes it from both directions.
    PurseCloseUnilateral {
        /// The channel.
        purse: TxId,
        /// How many tranches the closer admits receiving.
        tranches_claimed: u32,
        /// The PayWord token proving it.
        payword_token: Hash,
    },

    /// Contest a unilateral closure with a later PayWord token.
    ///
    /// C5: the other party, or a paid watchtower acting for them while they
    /// sleep, publishes the more recent signed balance and the cheat loses
    /// its stake. Every device of an owner is automatically a watchtower for
    /// that owner's channels (R1.6).
    PurseDispute {
        /// The channel.
        purse: TxId,
        /// The larger number of tranches actually spent.
        tranches_claimed: u32,
        /// The later PayWord token.
        payword_token: Hash,
    },

    /// Create a local asset: a festival's closed token, a neighbourhood
    /// currency.
    ///
    /// R2's monetary inversion brings this to Tier 1. Humans pay in the
    /// issuer's existing token; the VAN circulates between machines. The
    /// consumer-facing regulatory surface stays where it already was (G7), and
    /// the organiser keeps the float economy that is its actual business.
    AssetCreate {
        /// The ticker, unique in state.
        ticker: Name,
        /// Decimal places.
        decimals: u8,
        /// Whether the issuer may mint again after creation.
        reissuable: bool,
    },

    /// Mint units of an asset. Only its issuer may.
    AssetMint {
        /// Which asset.
        asset: AssetId,
        /// Recipient.
        to: AccountId,
        /// How much.
        amount: Amount,
    },

    /// Destroy units of an asset held by the signer.
    AssetBurn {
        /// Which asset.
        asset: AssetId,
        /// How much.
        amount: Amount,
    },

    /// Publish proof that one device subkey signed two transactions on the same
    /// lane and sequence.
    ///
    /// R2 extends "fraud produces its own evidence" from validators to
    /// accounts. Spending the same offline credit in two partitions
    /// *necessarily* produces this, because a nomad spend goes on a single
    /// sequenced lane. A few hundred bytes convict; the margin is seized,
    /// victims are compensated, a share burns.
    AccountEquivocation(Box<AccountEquivocation>),

    /// Publish proof that a validator signed two blocks at one height (A2).
    ValidatorEquivocation(Box<ValidatorEquivocation>),
}

impl TxKind {
    /// The frozen wire discriminant.
    #[must_use]
    pub const fn discriminant(&self) -> u64 {
        match self {
            Self::Transfer { .. } => 1,
            Self::NomadSet { .. } => 2,
            Self::DeviceAdd { .. } => 3,
            Self::DeviceRevoke { .. } => 4,
            Self::NameCommit { .. } => 5,
            Self::NameReveal { .. } => 6,
            Self::GuardianSet { .. } => 7,
            Self::RecoveryStart { .. } => 8,
            Self::RecoveryCancel { .. } => 9,
            Self::RecoveryFinalise { .. } => 10,
            Self::Bond { .. } => 11,
            Self::Unbond { .. } => 12,
            Self::PurseOpen { .. } => 13,
            Self::PurseCloseCooperative { .. } => 14,
            Self::PurseCloseUnilateral { .. } => 15,
            Self::PurseDispute { .. } => 16,
            Self::AssetCreate { .. } => 17,
            Self::AssetMint { .. } => 18,
            Self::AssetBurn { .. } => 19,
            Self::AccountEquivocation(_) => 20,
            Self::ValidatorEquivocation(_) => 21,
        }
    }

    /// A short name, for logs, errors and the provisional-grammar test.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Transfer { .. } => "transfer",
            Self::NomadSet { .. } => "nomad_set",
            Self::DeviceAdd { .. } => "device_add",
            Self::DeviceRevoke { .. } => "device_revoke",
            Self::NameCommit { .. } => "name_commit",
            Self::NameReveal { .. } => "name_reveal",
            Self::GuardianSet { .. } => "guardian_set",
            Self::RecoveryStart { .. } => "recovery_start",
            Self::RecoveryCancel { .. } => "recovery_cancel",
            Self::RecoveryFinalise { .. } => "recovery_finalise",
            Self::Bond { .. } => "bond",
            Self::Unbond { .. } => "unbond",
            Self::PurseOpen { .. } => "purse_open",
            Self::PurseCloseCooperative { .. } => "purse_close_cooperative",
            Self::PurseCloseUnilateral { .. } => "purse_close_unilateral",
            Self::PurseDispute { .. } => "purse_dispute",
            Self::AssetCreate { .. } => "asset_create",
            Self::AssetMint { .. } => "asset_mint",
            Self::AssetBurn { .. } => "asset_burn",
            Self::AccountEquivocation(_) => "account_equivocation",
            Self::ValidatorEquivocation(_) => "validator_equivocation",
        }
    }

    /// Whether this kind may appear in a provisional (rung 1) block.
    ///
    /// **The C9 parade.** Written as an exhaustive match with no wildcard on
    /// purpose: a new transaction kind will not compile until someone has
    /// answered "what happens if this is published while the party it could
    /// harm cannot see it?".
    ///
    /// The whitelist is short, and `docs/02-scope.pdf` says why it can afford
    /// to be: messaging and channels already cover most of offline life, so the
    /// grammar can be conservative without making a cut-off village useless.
    #[must_use]
    pub const fn allowed_in_provisional(&self) -> bool {
        match self {
            // Bounded by the nomad credit, which was declared before the
            // partition and is known to everyone. This is the whole point.
            Self::Transfer { .. } => true,
            // Locking funds is bounded by the same credit, and a channel is how
            // a festival or a train actually pays for things offline.
            Self::PurseOpen { .. } => true,
            // Both parties signed, so there is no absent victim (R2).
            Self::PurseCloseCooperative { .. } => true,

            // The stale-closure attack itself.
            Self::PurseCloseUnilateral { .. } => false,
            // A dispute is meaningless while the window it belongs to is
            // frozen, and admitting it offline would invite races on
            // reconnection.
            Self::PurseDispute { .. } => false,

            // Raising the offline credit *inside* a partition would destroy the
            // property that makes the credit worth anything: that the merchant
            // knew the ceiling in advance.
            Self::NomadSet { .. } => false,
            // A new device brings a new lane and a new share of the credit —
            // the same problem, wearing a different hat.
            Self::DeviceAdd { .. } => false,
            Self::DeviceRevoke { .. } => false,

            // Identity changes need a window, and a window cannot run here.
            Self::GuardianSet { .. } => false,
            Self::RecoveryStart { .. } => false,
            Self::RecoveryCancel { .. } => false,
            Self::RecoveryFinalise { .. } => false,

            // Consensus membership is a global fact; a partition must not
            // change it. `unbond` is named explicitly in R1.3.
            Self::Bond { .. } => false,
            Self::Unbond { .. } => false,

            // Uniqueness of a name or a ticker is global and cannot be decided
            // by one side of a split.
            Self::NameCommit { .. } => false,
            Self::NameReveal { .. } => false,
            Self::AssetCreate { .. } => false,
            // Issuance changes a supply that both sides will have to agree on.
            // The festival case is transfers of already-minted tokens, which
            // are allowed above.
            Self::AssetMint { .. } => false,
            Self::AssetBurn { .. } => false,

            // Evidence triggers seizure, and seizure is irreversible while a
            // provisional block is not. Evidence keeps: it is replayed on
            // reconnection, and the contestation clocks it feeds were frozen
            // the whole time anyway.
            Self::AccountEquivocation(_) => false,
            Self::ValidatorEquivocation(_) => false,
        }
    }

    /// Whether this kind carries nested evidence.
    #[must_use]
    pub const fn is_evidence(&self) -> bool {
        matches!(self, Self::AccountEquivocation(_) | Self::ValidatorEquivocation(_))
    }
}

impl Encode for TxKind {
    fn encode(&self, out: &mut Encoder) {
        out.write_varint(self.discriminant());
        match self {
            Self::Transfer { to, asset, amount } => {
                to.encode(out);
                out.write_option(asset.as_ref());
                amount.encode(out);
            }
            Self::NomadSet { credit, margin } => {
                credit.encode(out);
                margin.encode(out);
            }
            Self::DeviceAdd { key, lane, nomad_share } => {
                key.encode(out);
                lane.encode(out);
                nomad_share.encode(out);
            }
            Self::DeviceRevoke { device } => device.encode(out),
            Self::NameCommit { commitment } => commitment.encode(out),
            Self::NameReveal { name, salt } => {
                name.encode(out);
                out.write_raw(salt);
            }
            Self::GuardianSet { guardians, threshold } => {
                out.write_ordered_set(guardians);
                out.write_varint(u64::from(*threshold));
            }
            Self::RecoveryStart { account, new_root_key } => {
                account.encode(out);
                new_root_key.encode(out);
            }
            Self::RecoveryCancel { account } | Self::RecoveryFinalise { account } => {
                account.encode(out);
            }
            Self::Bond { amount, commitment_root } => {
                amount.encode(out);
                commitment_root.encode(out);
            }
            Self::Unbond { amount } => amount.encode(out),
            Self::PurseOpen {
                counterparty,
                asset,
                deposit,
                payword_root,
                tranche_value,
                expiry_finalized_height,
            } => {
                counterparty.encode(out);
                out.write_option(asset.as_ref());
                deposit.encode(out);
                payword_root.encode(out);
                tranche_value.encode(out);
                out.write_varint(*expiry_finalized_height);
            }
            Self::PurseCloseCooperative {
                purse,
                payer_balance,
                payee_balance,
                counterparty_signature,
            } => {
                purse.encode(out);
                payer_balance.encode(out);
                payee_balance.encode(out);
                counterparty_signature.encode(out);
            }
            Self::PurseCloseUnilateral { purse, tranches_claimed, payword_token }
            | Self::PurseDispute { purse, tranches_claimed, payword_token } => {
                purse.encode(out);
                out.write_varint(u64::from(*tranches_claimed));
                payword_token.encode(out);
            }
            Self::AssetCreate { ticker, decimals, reissuable } => {
                ticker.encode(out);
                out.write_varint(u64::from(*decimals));
                out.write_bool(*reissuable);
            }
            Self::AssetMint { asset, to, amount } => {
                asset.encode(out);
                to.encode(out);
                amount.encode(out);
            }
            Self::AssetBurn { asset, amount } => {
                asset.encode(out);
                amount.encode(out);
            }
            Self::AccountEquivocation(evidence) => evidence.encode(out),
            Self::ValidatorEquivocation(evidence) => evidence.encode(out),
        }
    }
}

impl Decode for TxKind {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let discriminant = input.read_varint()?;
        match discriminant {
            1 => Ok(Self::Transfer {
                to: AccountId::decode(input)?,
                asset: input.read_option::<AssetId>()?,
                amount: Amount::decode(input)?,
            }),
            2 => Ok(Self::NomadSet {
                credit: Amount::decode(input)?,
                margin: Amount::decode(input)?,
            }),
            3 => Ok(Self::DeviceAdd {
                key: VerifyingKey::decode(input)?,
                lane: Lane::decode(input)?,
                nomad_share: Amount::decode(input)?,
            }),
            4 => Ok(Self::DeviceRevoke { device: DeviceId::decode(input)? }),
            5 => Ok(Self::NameCommit { commitment: Hash::decode(input)? }),
            6 => Ok(Self::NameReveal {
                name: Name::decode(input)?,
                salt: input.read_array::<32>()?,
            }),
            7 => Ok(Self::GuardianSet {
                // `read_set` has already rejected duplicates and disorder, so
                // collecting into a `BTreeSet` cannot lose an element. The
                // decoder, not the collection, is what rejects a hostile list.
                guardians: input.read_set::<AccountId>()?.into_iter().collect(),
                threshold: input.read_varint_u32()?,
            }),
            8 => Ok(Self::RecoveryStart {
                account: AccountId::decode(input)?,
                new_root_key: VerifyingKey::decode(input)?,
            }),
            9 => Ok(Self::RecoveryCancel { account: AccountId::decode(input)? }),
            10 => Ok(Self::RecoveryFinalise { account: AccountId::decode(input)? }),
            11 => Ok(Self::Bond {
                amount: Amount::decode(input)?,
                commitment_root: Hash::decode(input)?,
            }),
            12 => Ok(Self::Unbond { amount: Amount::decode(input)? }),
            13 => Ok(Self::PurseOpen {
                counterparty: AccountId::decode(input)?,
                asset: input.read_option::<AssetId>()?,
                deposit: Amount::decode(input)?,
                payword_root: Hash::decode(input)?,
                tranche_value: Amount::decode(input)?,
                expiry_finalized_height: input.read_varint()?,
            }),
            14 => Ok(Self::PurseCloseCooperative {
                purse: TxId::decode(input)?,
                payer_balance: Amount::decode(input)?,
                payee_balance: Amount::decode(input)?,
                counterparty_signature: Signature::decode(input)?,
            }),
            15 => Ok(Self::PurseCloseUnilateral {
                purse: TxId::decode(input)?,
                tranches_claimed: input.read_varint_u32()?,
                payword_token: Hash::decode(input)?,
            }),
            16 => Ok(Self::PurseDispute {
                purse: TxId::decode(input)?,
                tranches_claimed: input.read_varint_u32()?,
                payword_token: Hash::decode(input)?,
            }),
            17 => Ok(Self::AssetCreate {
                ticker: Name::decode(input)?,
                decimals: input.read_varint_u8()?,
                reissuable: input.read_bool()?,
            }),
            18 => Ok(Self::AssetMint {
                asset: AssetId::decode(input)?,
                to: AccountId::decode(input)?,
                amount: Amount::decode(input)?,
            }),
            19 => Ok(Self::AssetBurn {
                asset: AssetId::decode(input)?,
                amount: Amount::decode(input)?,
            }),
            // Evidence contains whole transactions, which contain kinds, which
            // could contain evidence. `nested` bounds the recursion at
            // MAX_NESTING so that a hostile 1 MiB message cannot walk the stack
            // off the end (A6); `AccountEquivocation::check` then rejects
            // evidence about evidence outright.
            20 => Ok(Self::AccountEquivocation(Box::new(
                input.nested(AccountEquivocation::decode)?,
            ))),
            21 => Ok(Self::ValidatorEquivocation(Box::new(
                input.nested(ValidatorEquivocation::decode)?,
            ))),
            other => {
                Err(CodecError::UnknownVariant { enum_name: "TxKind", discriminant: other })
            }
        }
    }
}

/// The signed part of a transaction.
///
/// The identifier is computed over this, not over the envelope, so it does not
/// depend on the signature — which keeps it stable while a transaction is being
/// assembled and stops a third party changing it by re-wrapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxBody {
    /// Format version.
    pub version: u16,
    /// Which chain. Redundant with the signing domain, which also binds the
    /// chain — thirty-two bytes beside a 2420-byte signature buys a globally
    /// meaningful transaction identifier and a second lock on D4.
    pub chain: ChainId,
    /// The account this transaction acts for.
    pub account: AccountId,
    /// The device subkey that signs it.
    pub device: DeviceId,
    /// Lane and sequence.
    pub nonce: Nonce,
    /// Fee offered, split 70 / 20 / 10 by [`crate::amount::FeeSplit`].
    pub fee: Amount,
    /// Latest **finalised** height at which this remains valid.
    ///
    /// Finalised height, like every other deadline in the protocol. A validity
    /// window that ran on ordinary height would expire inside a partition, and
    /// a transaction that expires while nobody can include it is a transaction
    /// the partition has silently cancelled.
    pub valid_until_finalized: Option<u64>,
    /// What it does.
    pub kind: TxKind,
}

impl TxBody {
    /// This transaction's identifier.
    #[must_use]
    pub fn id(&self) -> TxId {
        TxId::from_hash(Hasher::new(domain::TXID).update(&self.to_canonical_bytes()).finalize())
    }

    /// The digest the device signs: `H[tx signing](chain_id ‖ txid)`.
    #[must_use]
    pub fn signing_digest(&self) -> Hash {
        Hasher::new(domain::TX_SIGNING)
            .update(self.chain.as_bytes())
            .update(self.id().as_bytes())
            .finalize()
    }

    /// Structural checks that need no chain state.
    pub fn check_self_consistent(&self) -> Result<(), TxError> {
        if self.version != TX_VERSION {
            return Err(TxError::UnsupportedVersion(self.version));
        }
        match &self.kind {
            TxKind::GuardianSet { guardians, threshold } => {
                if *threshold == 0 {
                    return Err(TxError::ZeroThreshold);
                }
                let count = u32::try_from(guardians.len()).unwrap_or(u32::MAX);
                if *threshold > count {
                    return Err(TxError::ThresholdAboveGuardians {
                        threshold: *threshold,
                        guardians: count,
                    });
                }
            }
            TxKind::PurseOpen { counterparty, .. } => {
                if *counterparty == self.account {
                    return Err(TxError::SelfCounterparty);
                }
            }
            TxKind::Transfer { to, amount, .. } => {
                if *to == self.account {
                    return Err(TxError::SelfCounterparty);
                }
                if amount.is_zero() {
                    return Err(TxError::ZeroAmount);
                }
            }
            TxKind::AccountEquivocation(evidence) => {
                if evidence.first.body.kind.is_evidence() || evidence.second.body.kind.is_evidence()
                {
                    return Err(TxError::EvidenceAboutEvidence);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl Encode for TxBody {
    fn encode(&self, out: &mut Encoder) {
        out.write_u16(self.version);
        self.chain.encode(out);
        self.account.encode(out);
        self.device.encode(out);
        self.nonce.encode(out);
        self.fee.encode(out);
        match self.valid_until_finalized {
            None => {
                out.write_u8(0);
            }
            Some(height) => {
                out.write_u8(1);
                out.write_varint(height);
            }
        }
        self.kind.encode(out);
    }
}

impl Decode for TxBody {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let version = input.read_u16()?;
        let chain = ChainId::decode(input)?;
        let account = AccountId::decode(input)?;
        let device = DeviceId::decode(input)?;
        let nonce = Nonce::decode(input)?;
        let fee = Amount::decode(input)?;
        let valid_until_finalized = match input.read_u8()? {
            0 => None,
            1 => Some(input.read_varint()?),
            other => return Err(CodecError::BadOptionTag(other)),
        };
        let kind = TxKind::decode(input)?;
        Ok(Self { version, chain, account, device, nonce, fee, valid_until_finalized, kind })
    }
}

/// A transaction: a body and the signature of the device that authorised it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// What is signed.
    pub body: TxBody,
    /// The device subkey's signature over [`TxBody::signing_digest`].
    pub signature: Signature,
}

impl Transaction {
    /// This transaction's identifier.
    #[must_use]
    pub fn id(&self) -> TxId {
        self.body.id()
    }

    /// Verifies the signature against the device key it names.
    ///
    /// Checks that the key really is the one the body names, by re-deriving the
    /// device identifier. Without that check, a valid signature by *some* key
    /// would be accepted for a body naming *another* device — and every nonce
    /// lane, every nomad share and every equivocation proof in the protocol
    /// hangs off which device signed.
    ///
    /// Rejects the test algorithms. Use
    /// [`Transaction::verify_allowing_test_algorithms`] on a test network.
    pub fn verify(&self, device_key: &VerifyingKey) -> Result<(), TxError> {
        if !device_key.algorithm().valid_on_live_chain() {
            return Err(TxError::TestAlgorithmOnLiveChain);
        }
        self.verify_allowing_test_algorithms(device_key)
    }

    /// As [`Transaction::verify`], without the production algorithm check.
    pub fn verify_allowing_test_algorithms(
        &self,
        device_key: &VerifyingKey,
    ) -> Result<(), TxError> {
        if DeviceId::of_device_key(device_key) != self.body.device {
            return Err(TxError::WrongDeviceKey);
        }
        vanargand_crypto::sign::verify(
            device_key,
            self.body.signing_digest().as_bytes(),
            &self.signature,
        )
        .map_err(|_| TxError::BadSignature)
    }
}

impl Encode for Transaction {
    fn encode(&self, out: &mut Encoder) {
        self.body.encode(out);
        self.signature.encode(out);
    }
}

impl Decode for Transaction {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self { body: TxBody::decode(input)?, signature: Signature::decode(input)? })
    }
}

/// Proof that one device signed two different transactions in the same slot.
///
/// R2's extension of "fraud produces its own evidence" from validators to
/// ordinary accounts. Because a nomad spend travels on a single sequenced lane
/// belonging to one device, spending the same offline credit in two partitions
/// *necessarily* produces this object. It is not detected; it is manufactured
/// by the act.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountEquivocation {
    /// The accused device subkey.
    pub device: DeviceId,
    /// One transaction.
    pub first: Transaction,
    /// The other.
    pub second: Transaction,
}

impl AccountEquivocation {
    /// Checks that this really is equivocation, given the device's key.
    pub fn check(&self, device_key: &VerifyingKey) -> Result<(), TxError> {
        let (first, second) = (&self.first.body, &self.second.body);

        if first.kind.is_evidence() || second.kind.is_evidence() {
            // Evidence about evidence is a recursion bomb dressed as a
            // denunciation, and it proves nothing that the inner evidence does
            // not already prove on its own.
            return Err(TxError::EvidenceAboutEvidence);
        }
        if first.chain != second.chain {
            return Err(TxError::NotEquivocation { why: "different chains" });
        }
        if first.account != second.account {
            return Err(TxError::NotEquivocation { why: "different accounts" });
        }
        if first.device != self.device || second.device != self.device {
            return Err(TxError::NotEquivocation { why: "not both by the accused device" });
        }
        if !first.nonce.collides_with(second.nonce) {
            // Different lanes are the honest multi-device case, and different
            // sequences are simply two payments. Neither is a crime.
            return Err(TxError::NotEquivocation { why: "nonces do not collide" });
        }
        if self.first.id() == self.second.id() {
            return Err(TxError::NotEquivocation { why: "the same transaction twice" });
        }

        self.first.verify_allowing_test_algorithms(device_key)?;
        self.second.verify_allowing_test_algorithms(device_key)?;
        Ok(())
    }
}

impl Encode for AccountEquivocation {
    fn encode(&self, out: &mut Encoder) {
        self.device.encode(out);
        self.first.encode(out);
        self.second.encode(out);
    }
}

impl Decode for AccountEquivocation {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            device: DeviceId::decode(input)?,
            first: Transaction::decode(input)?,
            second: Transaction::decode(input)?,
        })
    }
}

/// Derives an asset identifier from its creating transaction.
#[must_use]
pub fn asset_id_of(creator: AccountId, creating_tx: TxId) -> AssetId {
    AssetId::from_hash(
        Hasher::new(domain::ASSET_ID)
            .update(creator.as_bytes())
            .update(creating_tx.as_bytes())
            .finalize(),
    )
}

/// Computes a name registration commitment.
#[must_use]
pub fn name_commitment(name: &Name, salt: &[u8; 32], account: AccountId) -> Hash {
    Hasher::new(domain::NAME_COMMITMENT)
        .update(&name.to_canonical_bytes())
        .update(salt)
        .update(account.as_bytes())
        .finalize()
}

/// Why a transaction or a piece of transaction evidence was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TxError {
    /// The transaction format version is not one this build understands.
    UnsupportedVersion(u16),
    /// The signature did not verify.
    BadSignature,
    /// The supplied key is not the device the body names.
    WrongDeviceKey,
    /// A test algorithm was used on a production chain.
    TestAlgorithmOnLiveChain,
    /// A guardian threshold of zero.
    ZeroThreshold,
    /// A threshold larger than the guardian list.
    ThresholdAboveGuardians {
        /// The threshold asked for.
        threshold: u32,
        /// How many guardians there are.
        guardians: u32,
    },
    /// An account named itself as counterparty or recipient.
    SelfCounterparty,
    /// A transfer of nothing.
    ZeroAmount,
    /// Evidence whose subject is itself evidence.
    EvidenceAboutEvidence,
    /// This kind is grammatically illegal in a provisional block.
    ForbiddenInProvisional {
        /// Which kind.
        kind: &'static str,
    },
    /// Evidence that does not show what it claims to show.
    NotEquivocation {
        /// Which requirement failed.
        why: &'static str,
    },
}

impl fmt::Display for TxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported transaction version {version}")
            }
            Self::BadSignature => write!(f, "signature verification failed"),
            Self::WrongDeviceKey => write!(f, "the key is not the device this transaction names"),
            Self::TestAlgorithmOnLiveChain => {
                write!(f, "a test algorithm was used on a production chain")
            }
            Self::ZeroThreshold => write!(f, "a guardian threshold of zero recovers nothing"),
            Self::ThresholdAboveGuardians { threshold, guardians } => {
                write!(f, "threshold {threshold} exceeds {guardians} guardians")
            }
            Self::SelfCounterparty => write!(f, "an account cannot transact with itself"),
            Self::ZeroAmount => write!(f, "a transfer of zero"),
            Self::EvidenceAboutEvidence => write!(f, "evidence about evidence"),
            Self::ForbiddenInProvisional { kind } => {
                write!(f, "{kind} is not permitted in a provisional block")
            }
            Self::NotEquivocation { why } => write!(f, "not equivocation: {why}"),
        }
    }
}

impl std::error::Error for TxError {}

/// Checks a whole provisional block's transactions against the partition
/// grammar.
///
/// Returns the first offender. A block containing one forbidden transaction is
/// invalid in its entirety: the alternative, dropping the offender and keeping
/// the rest, would make two honest nodes disagree about what the block was.
pub fn check_provisional_grammar<'a, I>(transactions: I) -> Result<(), TxError>
where
    I: IntoIterator<Item = &'a TxBody>,
{
    for body in transactions {
        if !body.kind.allowed_in_provisional() {
            return Err(TxError::ForbiddenInProvisional { kind: body.kind.name() });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        asset_id_of, check_provisional_grammar, name_commitment, AccountEquivocation,
        Transaction, TxBody, TxError, TxKind, TX_VERSION,
    };
    use crate::amount::Amount;
    use crate::codec::{CodecError, Decode, Encode, Encoder};
    use crate::id::{AccountId, AssetId, ChainId, DeviceId, TxId};
    use crate::name::Name;
    use crate::nonce::{Lane, Nonce};
    use std::collections::BTreeSet;
    use vanargand_crypto::algorithm::AlgorithmId;
    use vanargand_crypto::hash::Hash;
    use vanargand_crypto::sign::{self, Keypair, VerifyingKey};

    fn keypair(byte: u8) -> Keypair {
        sign::keypair_from_seed(AlgorithmId::InsecureTest, &Hash::from_bytes([byte; 32])).unwrap()
    }

    fn account(byte: u8) -> AccountId {
        AccountId::from_hash(Hash::from_bytes([byte; 32]))
    }

    fn body(kind: TxKind) -> TxBody {
        TxBody {
            version: TX_VERSION,
            chain: ChainId::from_hash(Hash::from_bytes([0x11; 32])),
            account: account(0x21),
            device: DeviceId::from_hash(Hash::from_bytes([0x31; 32])),
            nonce: Nonce::new(Lane::FIRST, 3),
            fee: Amount::from_ulf(1_000),
            valid_until_finalized: Some(5_000),
            kind,
        }
    }

    fn transfer() -> TxKind {
        TxKind::Transfer { to: account(0x41), asset: None, amount: Amount::from_ulf(10) }
    }

    /// One of every variant, for the round-trip and discriminant tests.
    fn every_kind() -> Vec<TxKind> {
        let key = keypair(1).verifying;
        vec![
            transfer(),
            TxKind::Transfer {
                to: account(0x41),
                asset: Some(AssetId::from_hash(Hash::from_bytes([0x51; 32]))),
                amount: Amount::from_ulf(10),
            },
            TxKind::NomadSet { credit: Amount::from_ulf(500), margin: Amount::from_ulf(50) },
            TxKind::DeviceAdd {
                key: key.clone(),
                lane: Lane::new(2),
                nomad_share: Amount::from_ulf(100),
            },
            TxKind::DeviceRevoke { device: DeviceId::from_hash(Hash::from_bytes([0x61; 32])) },
            TxKind::NameCommit { commitment: Hash::from_bytes([0x71; 32]) },
            TxKind::NameReveal { name: Name::new("cafe-du-port").unwrap(), salt: [0x81; 32] },
            TxKind::GuardianSet {
                guardians: [account(0x01), account(0x02), account(0x03)].into_iter().collect(),
                threshold: 2,
            },
            TxKind::RecoveryStart { account: account(0x91), new_root_key: key },
            TxKind::RecoveryCancel { account: account(0x92) },
            TxKind::RecoveryFinalise { account: account(0x93) },
            TxKind::Bond {
                amount: Amount::from_ulf(10_000),
                commitment_root: Hash::from_bytes([0xa1; 32]),
            },
            TxKind::Unbond { amount: Amount::from_ulf(10_000) },
            TxKind::PurseOpen {
                counterparty: account(0xb1),
                asset: None,
                deposit: Amount::from_ulf(250),
                payword_root: Hash::from_bytes([0xc1; 32]),
                tranche_value: Amount::from_ulf(1),
                expiry_finalized_height: 9_000,
            },
            TxKind::PurseCloseCooperative {
                purse: TxId::from_hash(Hash::from_bytes([0xd1; 32])),
                payer_balance: Amount::from_ulf(150),
                payee_balance: Amount::from_ulf(100),
                counterparty_signature: sign::sign(
                    &keypair(2).signing,
                    b"final state",
                )
                .unwrap(),
            },
            TxKind::PurseCloseUnilateral {
                purse: TxId::from_hash(Hash::from_bytes([0xd2; 32])),
                tranches_claimed: 40,
                payword_token: Hash::from_bytes([0xe1; 32]),
            },
            TxKind::PurseDispute {
                purse: TxId::from_hash(Hash::from_bytes([0xd3; 32])),
                tranches_claimed: 75,
                payword_token: Hash::from_bytes([0xe2; 32]),
            },
            TxKind::AssetCreate {
                ticker: Name::new("festi").unwrap(),
                decimals: 2,
                reissuable: true,
            },
            TxKind::AssetMint {
                asset: AssetId::from_hash(Hash::from_bytes([0xf1; 32])),
                to: account(0xf2),
                amount: Amount::from_ulf(1_000),
            },
            TxKind::AssetBurn {
                asset: AssetId::from_hash(Hash::from_bytes([0xf3; 32])),
                amount: Amount::from_ulf(10),
            },
        ]
    }

    /// Builds a signed transaction for `kind` under `pair`, at `nonce`.
    fn signed(pair: &Keypair, kind: TxKind, nonce: Nonce) -> Transaction {
        let mut inner = body(kind);
        inner.device = DeviceId::of_device_key(&pair.verifying);
        inner.nonce = nonce;
        let signature = sign::sign(&pair.signing, inner.signing_digest().as_bytes()).unwrap();
        Transaction { body: inner, signature }
    }

    #[test]
    fn every_kind_round_trips() {
        for kind in every_kind() {
            let original = body(kind);
            let bytes = original.to_canonical_bytes();
            assert_eq!(
                TxBody::from_canonical_bytes(&bytes),
                Ok(original.clone()),
                "round trip failed for {}",
                original.kind.name()
            );
        }
    }

    #[test]
    fn discriminants_are_unique_and_never_zero() {
        // Zero is reserved so that a zeroed buffer fails rather than selecting
        // something, exactly as for algorithm identifiers.
        //
        // `every_kind()` holds two `Transfer` entries on purpose (native and
        // local-asset, to exercise the `Option<AssetId>` round trip), so this
        // checks one discriminant per *name*, not per fixture entry — a real
        // collision between two different variants still fails the assertion.
        let mut seen_names = BTreeSet::new();
        let mut seen_discriminants = BTreeSet::new();
        for kind in every_kind() {
            if !seen_names.insert(kind.name()) {
                continue;
            }
            let discriminant = kind.discriminant();
            assert_ne!(discriminant, 0, "{} took the reserved zero", kind.name());
            assert!(
                seen_discriminants.insert(discriminant),
                "{} reuses discriminant {discriminant}",
                kind.name()
            );
        }
    }

    #[test]
    fn names_are_unique() {
        let names: BTreeSet<&str> = every_kind().iter().map(|kind| kind.name()).collect();
        // Two Transfer variants in the fixture share a name, hence the -1.
        assert_eq!(names.len(), every_kind().len() - 1);
    }

    #[test]
    fn an_unknown_discriminant_is_rejected() {
        let mut encoder = Encoder::new();
        encoder.write_varint(200);
        assert_eq!(
            TxKind::from_canonical_bytes(&encoder.finish()),
            Err(CodecError::UnknownVariant { enum_name: "TxKind", discriminant: 200 })
        );
    }

    #[test]
    fn the_reserved_zero_discriminant_is_rejected() {
        assert_eq!(
            TxKind::from_canonical_bytes(&[0x00]),
            Err(CodecError::UnknownVariant { enum_name: "TxKind", discriminant: 0 })
        );
    }

    // --- the partition grammar (C9) ---------------------------------------

    #[test]
    fn the_provisional_whitelist_is_exactly_what_r2_decided() {
        // Pinned deliberately. Widening this list is a change to the C9 parade
        // and must be a decision somebody made, not a diff nobody noticed.
        // `transfer` appears twice because the fixture holds both the native
        // and the local-asset form.
        let allowed: Vec<&str> = every_kind()
            .iter()
            .filter(|kind| kind.allowed_in_provisional())
            .map(TxKind::name)
            .collect();
        assert_eq!(
            allowed,
            vec!["transfer", "transfer", "purse_open", "purse_close_cooperative"],
            "the provisional grammar changed"
        );
    }

    #[test]
    fn evidence_kinds_sit_at_the_end_of_the_discriminant_space() {
        let pair = keypair(40);
        let nonce = Nonce::new(Lane::FIRST, 0);
        let account_evidence = TxKind::AccountEquivocation(Box::new(AccountEquivocation {
            device: DeviceId::of_device_key(&pair.verifying),
            first: signed(&pair, transfer(), nonce),
            second: signed(&pair, TxKind::Unbond { amount: Amount::from_ulf(1) }, nonce),
        }));
        assert_eq!(account_evidence.discriminant(), 20);
        assert_eq!(account_evidence.name(), "account_equivocation");
        assert!(account_evidence.is_evidence());
        assert!(
            !account_evidence.allowed_in_provisional(),
            "evidence triggers irreversible seizure and a provisional block is reversible"
        );
    }

    #[test]
    fn unilateral_closure_is_grammatically_illegal_offline() {
        // C9 itself: publish a stale closure into provisional blocks while the
        // counterparty and its watchtower are on the far side of the split.
        let stale = body(TxKind::PurseCloseUnilateral {
            purse: TxId::ZERO,
            tranches_claimed: 0,
            payword_token: Hash::ZERO,
        });
        assert_eq!(
            check_provisional_grammar([&stale]),
            Err(TxError::ForbiddenInProvisional { kind: "purse_close_unilateral" })
        );
    }

    #[test]
    fn raising_the_nomad_credit_offline_is_illegal() {
        // The credit is worth something only because the merchant knew the
        // ceiling before the outage.
        let raise = body(TxKind::NomadSet {
            credit: Amount::from_van(1_000_000).unwrap(),
            margin: Amount::ZERO,
        });
        assert_eq!(
            check_provisional_grammar([&raise]),
            Err(TxError::ForbiddenInProvisional { kind: "nomad_set" })
        );
    }

    #[test]
    fn recovery_and_unbonding_are_illegal_offline() {
        for kind in [
            TxKind::RecoveryStart { account: account(1), new_root_key: keypair(3).verifying },
            TxKind::RecoveryCancel { account: account(1) },
            TxKind::RecoveryFinalise { account: account(1) },
            TxKind::Unbond { amount: Amount::from_ulf(1) },
        ] {
            let name = kind.name();
            assert_eq!(
                check_provisional_grammar([&body(kind)]),
                Err(TxError::ForbiddenInProvisional { kind: name }),
                "{name} was allowed in a provisional block"
            );
        }
    }

    #[test]
    fn a_whitelisted_block_passes() {
        let bodies = vec![
            body(transfer()),
            body(TxKind::PurseOpen {
                counterparty: account(0xb1),
                asset: None,
                deposit: Amount::from_ulf(250),
                payword_root: Hash::ZERO,
                tranche_value: Amount::from_ulf(1),
                expiry_finalized_height: 9_000,
            }),
        ];
        assert_eq!(check_provisional_grammar(bodies.iter()), Ok(()));
    }

    // --- signing ----------------------------------------------------------

    #[test]
    fn a_transaction_verifies_and_a_tampered_one_does_not() {
        let pair = keypair(10);
        let transaction = signed(&pair, transfer(), Nonce::new(Lane::FIRST, 0));
        assert_eq!(transaction.verify_allowing_test_algorithms(&pair.verifying), Ok(()));

        let mut tampered = transaction.clone();
        tampered.body.fee = Amount::from_ulf(1);
        assert_eq!(
            tampered.verify_allowing_test_algorithms(&pair.verifying),
            Err(TxError::BadSignature)
        );
    }

    #[test]
    fn the_key_must_be_the_device_the_body_names() {
        // Without this check, a valid signature by some key would be accepted
        // for a body naming another device — and every lane, nomad share and
        // equivocation proof hangs off which device signed.
        let pair = keypair(11);
        let other = keypair(12);
        let transaction = signed(&pair, transfer(), Nonce::new(Lane::FIRST, 0));
        assert_eq!(
            transaction.verify_allowing_test_algorithms(&other.verifying),
            Err(TxError::WrongDeviceKey)
        );
    }

    #[test]
    fn the_production_path_refuses_a_test_algorithm() {
        let pair = keypair(13);
        let transaction = signed(&pair, transfer(), Nonce::new(Lane::FIRST, 0));
        assert_eq!(
            transaction.verify(&pair.verifying),
            Err(TxError::TestAlgorithmOnLiveChain)
        );
    }

    #[test]
    fn the_signature_is_bound_to_the_chain() {
        let pair = keypair(14);
        let transaction = signed(&pair, transfer(), Nonce::new(Lane::FIRST, 0));
        let mut elsewhere = transaction.clone();
        elsewhere.body.chain = ChainId::from_hash(Hash::from_bytes([0x99; 32]));
        assert_eq!(
            elsewhere.verify_allowing_test_algorithms(&pair.verifying),
            Err(TxError::BadSignature),
            "a transaction replayed onto another chain verified"
        );
    }

    #[test]
    fn the_identifier_does_not_depend_on_the_signature() {
        let pair = keypair(15);
        let transaction = signed(&pair, transfer(), Nonce::new(Lane::FIRST, 0));
        let mut rewrapped = transaction.clone();
        rewrapped.signature = sign::sign(&keypair(16).signing, b"anything").unwrap();
        assert_eq!(rewrapped.id(), transaction.id());
    }

    // --- account equivocation (R2) ----------------------------------------

    #[test]
    fn spending_the_same_slot_twice_produces_its_own_proof() {
        // The property R2 relies on: this object is not detected, it is
        // manufactured by the act of double-spending an offline credit.
        let pair = keypair(20);
        let nonce = Nonce::new(Lane::new(1), 7);
        let village = signed(&pair, transfer(), nonce);
        let mut town_kind = transfer();
        if let TxKind::Transfer { ref mut amount, .. } = town_kind {
            *amount = Amount::from_ulf(11);
        }
        let town = signed(&pair, town_kind, nonce);

        assert_ne!(village.id(), town.id());
        let evidence = AccountEquivocation {
            device: DeviceId::of_device_key(&pair.verifying),
            first: village,
            second: town,
        };
        assert_eq!(evidence.check(&pair.verifying), Ok(()));
    }

    #[test]
    fn two_honest_devices_in_two_partitions_are_not_equivocation() {
        // R2's correction, asserted. This is the scenario the correction was
        // written for: one account, a phone in a cut-off village and a laptop
        // in the city, both spending honestly at the same moment. With an
        // account-wide lane the two would collide and the account would be
        // slashed for being in two places — which is the normal operating
        // condition of this protocol.
        let phone_key = keypair(21);
        let laptop_key = keypair(22);

        // Each device has its own lane, so the sequence numbers are free to
        // coincide without meaning anything.
        let phone = signed(&phone_key, transfer(), Nonce::new(Lane::new(0), 4));
        let laptop = signed(&laptop_key, transfer(), Nonce::new(Lane::new(1), 4));

        // No accusation can be framed: the two transactions do not even name
        // the same device.
        assert_ne!(phone.body.device, laptop.body.device);
        let accusing_the_phone = AccountEquivocation {
            device: DeviceId::of_device_key(&phone_key.verifying),
            first: phone.clone(),
            second: laptop,
        };
        assert_eq!(
            accusing_the_phone.check(&phone_key.verifying),
            Err(TxError::NotEquivocation { why: "not both by the accused device" })
        );

        // And even within one device, two different lanes never collide.
        let same_device_other_lane =
            signed(&phone_key, transfer(), Nonce::new(Lane::new(1), 4));
        let across_lanes = AccountEquivocation {
            device: DeviceId::of_device_key(&phone_key.verifying),
            first: phone,
            second: same_device_other_lane,
        };
        assert_eq!(
            across_lanes.check(&phone_key.verifying),
            Err(TxError::NotEquivocation { why: "nonces do not collide" })
        );
    }

    #[test]
    fn the_same_transaction_twice_is_not_equivocation() {
        let pair = keypair(22);
        let once = signed(&pair, transfer(), Nonce::new(Lane::FIRST, 1));
        let evidence = AccountEquivocation {
            device: DeviceId::of_device_key(&pair.verifying),
            first: once.clone(),
            second: once,
        };
        assert_eq!(
            evidence.check(&pair.verifying),
            Err(TxError::NotEquivocation { why: "the same transaction twice" })
        );
    }

    #[test]
    fn evidence_across_two_chains_is_not_equivocation() {
        // Two chains are two worlds. The same lane and sequence on each is the
        // documented, intended behaviour of a universal identity.
        let pair = keypair(23);
        let nonce = Nonce::new(Lane::FIRST, 2);
        let here = signed(&pair, transfer(), nonce);
        let mut there = signed(&pair, transfer(), nonce);
        there.body.chain = ChainId::from_hash(Hash::from_bytes([0x77; 32]));
        there.signature =
            sign::sign(&pair.signing, there.body.signing_digest().as_bytes()).unwrap();

        let evidence = AccountEquivocation {
            device: DeviceId::of_device_key(&pair.verifying),
            first: here,
            second: there,
        };
        assert_eq!(
            evidence.check(&pair.verifying),
            Err(TxError::NotEquivocation { why: "different chains" })
        );
    }

    #[test]
    fn unsigned_evidence_is_rejected() {
        let pair = keypair(24);
        let nonce = Nonce::new(Lane::FIRST, 0);
        let genuine = signed(&pair, transfer(), nonce);
        let mut forged = genuine.clone();
        forged.body.fee = Amount::from_ulf(2);
        // Signature no longer matches the tampered body.
        let evidence = AccountEquivocation {
            device: DeviceId::of_device_key(&pair.verifying),
            first: genuine,
            second: forged,
        };
        assert_eq!(evidence.check(&pair.verifying), Err(TxError::BadSignature));
    }

    #[test]
    fn evidence_about_evidence_is_refused() {
        // A recursion bomb dressed as a denunciation. It also proves nothing
        // the inner evidence does not already prove on its own.
        let pair = keypair(25);
        let nonce = Nonce::new(Lane::FIRST, 0);
        let inner = AccountEquivocation {
            device: DeviceId::of_device_key(&pair.verifying),
            first: signed(&pair, transfer(), nonce),
            second: signed(&pair, TxKind::Unbond { amount: Amount::from_ulf(1) }, nonce),
        };
        let wrapper = signed(
            &pair,
            TxKind::AccountEquivocation(Box::new(inner)),
            Nonce::new(Lane::FIRST, 1),
        );
        assert_eq!(wrapper.body.check_self_consistent(), Ok(()));

        let outer = AccountEquivocation {
            device: DeviceId::of_device_key(&pair.verifying),
            first: wrapper.clone(),
            second: wrapper,
        };
        assert_eq!(outer.check(&pair.verifying), Err(TxError::EvidenceAboutEvidence));
    }

    #[test]
    fn evidence_round_trips_through_the_codec() {
        let pair = keypair(26);
        let nonce = Nonce::new(Lane::FIRST, 9);
        let evidence = AccountEquivocation {
            device: DeviceId::of_device_key(&pair.verifying),
            first: signed(&pair, transfer(), nonce),
            second: signed(&pair, TxKind::Unbond { amount: Amount::from_ulf(3) }, nonce),
        };
        let kind = TxKind::AccountEquivocation(Box::new(evidence));
        let bytes = kind.to_canonical_bytes();
        assert_eq!(TxKind::from_canonical_bytes(&bytes), Ok(kind));
    }

    // --- structural checks ------------------------------------------------

    #[test]
    fn self_consistency_catches_the_structural_mistakes() {
        assert_eq!(body(transfer()).check_self_consistent(), Ok(()));

        let mut wrong_version = body(transfer());
        wrong_version.version = TX_VERSION + 1;
        assert_eq!(
            wrong_version.check_self_consistent(),
            Err(TxError::UnsupportedVersion(TX_VERSION + 1))
        );

        let zero = body(TxKind::Transfer {
            to: account(0x41),
            asset: None,
            amount: Amount::ZERO,
        });
        assert_eq!(zero.check_self_consistent(), Err(TxError::ZeroAmount));

        let mut to_self = body(transfer());
        if let TxKind::Transfer { ref mut to, .. } = to_self.kind {
            *to = to_self.account;
        }
        assert_eq!(to_self.check_self_consistent(), Err(TxError::SelfCounterparty));

        let two_guardians = || -> BTreeSet<AccountId> {
            [account(1), account(2)].into_iter().collect()
        };
        let no_threshold =
            body(TxKind::GuardianSet { guardians: two_guardians(), threshold: 0 });
        assert_eq!(no_threshold.check_self_consistent(), Err(TxError::ZeroThreshold));

        let impossible =
            body(TxKind::GuardianSet { guardians: two_guardians(), threshold: 3 });
        assert_eq!(
            impossible.check_self_consistent(),
            Err(TxError::ThresholdAboveGuardians { threshold: 3, guardians: 2 })
        );
    }

    #[test]
    fn a_duplicated_guardian_is_rejected_on_the_wire() {
        // A duplicate would count twice towards the threshold, which turns a
        // "three of five" recovery into a "two of five" one.
        let mut encoder = Encoder::new();
        encoder.write_varint(7); // GuardianSet
        encoder.write_seq(&[account(1), account(1)]);
        encoder.write_varint(2);
        assert_eq!(
            TxKind::from_canonical_bytes(&encoder.finish()),
            Err(CodecError::UnorderedSet { index: 1 })
        );
    }

    #[test]
    fn an_unsorted_guardian_list_is_rejected_on_the_wire() {
        let mut encoder = Encoder::new();
        encoder.write_varint(7);
        encoder.write_seq(&[account(3), account(1), account(2)]);
        encoder.write_varint(2);
        assert_eq!(
            TxKind::from_canonical_bytes(&encoder.finish()),
            Err(CodecError::UnorderedSet { index: 1 })
        );
    }

    // --- derived identifiers ----------------------------------------------

    #[test]
    fn asset_identifiers_are_unique_per_creating_transaction() {
        let creator = account(1);
        let first = asset_id_of(creator, TxId::from_hash(Hash::from_bytes([1; 32])));
        let second = asset_id_of(creator, TxId::from_hash(Hash::from_bytes([2; 32])));
        let elsewhere = asset_id_of(account(2), TxId::from_hash(Hash::from_bytes([1; 32])));
        assert_ne!(first, second);
        assert_ne!(first, elsewhere);
    }

    #[test]
    fn a_name_commitment_binds_the_name_the_salt_and_the_account() {
        let name = Name::new("marie").unwrap();
        let other = Name::new("marie-b").unwrap();
        let base = name_commitment(&name, &[0; 32], account(1));
        assert_ne!(base, name_commitment(&other, &[0; 32], account(1)));
        assert_ne!(base, name_commitment(&name, &[1; 32], account(1)));
        assert_ne!(base, name_commitment(&name, &[0; 32], account(2)));
        assert_eq!(base, name_commitment(&name, &[0; 32], account(1)));
    }

    #[test]
    fn a_length_prefixed_name_makes_the_commitment_unambiguous() {
        // Without the length prefix, ("ab", salt) and ("a", "b"++salt) could
        // collide. The canonical encoding of the name closes that by
        // construction.
        let short = Name::new("ab").unwrap();
        let long = Name::new("abc").unwrap();
        assert_ne!(
            name_commitment(&short, &[0; 32], account(1)),
            name_commitment(&long, &[0; 32], account(1))
        );
    }

    #[test]
    fn a_verifying_key_survives_a_transaction_round_trip() {
        let key: VerifyingKey = keypair(30).verifying;
        let original = body(TxKind::DeviceAdd {
            key: key.clone(),
            lane: Lane::new(5),
            nomad_share: Amount::from_ulf(42),
        });
        let decoded = TxBody::from_canonical_bytes(&original.to_canonical_bytes()).unwrap();
        match decoded.kind {
            TxKind::DeviceAdd { key: decoded_key, .. } => assert_eq!(decoded_key, key),
            other => panic!("decoded as {}", other.name()),
        }
    }
}
