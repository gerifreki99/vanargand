// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the ledger knows about an account.
//!
//! Every collection here is ordered. A `BTreeMap` or a `BTreeSet`, never a
//! hash-based one — this structure is encoded and hashed into the state root,
//! so its iteration order is consensus, and a randomised order would make two
//! honest nodes compute different roots from identical data.

use std::collections::{BTreeMap, BTreeSet};

use vanargand_types::codec::{CodecError, Decode, Decoder, Encode, Encoder};
use vanargand_types::id::{AccountId, AssetId, DeviceId};
use vanargand_types::name::Name;
use vanargand_types::nonce::{Lane, LaneState};
use vanargand_types::Amount;
use vanargand_crypto::sign::VerifyingKey;
use vanargand_crypto::hash::{domain, Hash, Hasher};

/// One device subkey of an account.
///
/// The per-device nomad share is R2's correction and the reason this type
/// exists separately from the account: with an account-wide offline credit, two
/// honest devices isolated in two partitions would each spend "the" credit and
/// produce an equivocation between them. Splitting the credit per device means
/// each one can only overspend against itself, which is exactly the case that
/// deserves punishing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The device's public key.
    pub key: VerifyingKey,
    /// Its nonce lane. Unique within the account, never reused.
    pub lane: Lane,
    /// Its share of the account's offline credit.
    pub nomad_share: Amount,
    /// How much of that share has been spent since the last finalised
    /// settlement.
    pub nomad_spent: Amount,
}

impl Device {
    /// How much this device may still spend while the chain is partitioned.
    #[must_use]
    pub fn nomad_remaining(&self) -> Amount {
        self.nomad_share.checked_sub(self.nomad_spent).unwrap_or(Amount::ZERO)
    }
}

impl Encode for Device {
    fn encode(&self, out: &mut Encoder) {
        self.key.encode(out);
        self.lane.encode(out);
        self.nomad_share.encode(out);
        self.nomad_spent.encode(out);
    }
}

impl Decode for Device {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            key: VerifyingKey::decode(input)?,
            lane: Lane::decode(input)?,
            nomad_share: Amount::decode(input)?,
            nomad_spent: Amount::decode(input)?,
        })
    }
}

/// An account record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Account {
    /// Balances by asset. The key `None` is VAN itself.
    ///
    /// `Option<AssetId>` as a map key sorts `None` first and is therefore
    /// deterministic, and it keeps the native asset from needing a reserved
    /// identifier that could be forged.
    pub balances: BTreeMap<Option<AssetId>, Amount>,

    /// Total offline credit declared by this account, in VAN.
    ///
    /// Published on the ledger in advance so that a merchant knows what it
    /// risks before accepting an offline payment rather than discovering it
    /// afterwards. The sum of the per-device shares may not exceed it.
    pub nomad_credit: Amount,

    /// Optional bonded margin behind the credit (R2).
    ///
    /// With a margin, a proved equivocation seizes it: victims are compensated
    /// and a share burns. Without one, the credit still bounds the exposure but
    /// there is nothing to seize.
    pub nomad_margin: Amount,

    /// The account's devices.
    pub devices: BTreeMap<DeviceId, Device>,

    /// Devices that have been revoked, kept forever.
    ///
    /// Never emptied and never reused. An attacker who once held a device key
    /// could otherwise wait out the contestation window and have the device
    /// added back.
    pub revoked_devices: BTreeSet<DeviceId>,

    /// The next lane index to hand out.
    pub next_lane: Lane,

    /// Per-lane sequence counters.
    pub lanes: LaneState,

    /// Guardians for social recovery.
    pub guardians: BTreeSet<AccountId>,

    /// How many guardians must co-sign a recovery.
    pub guardian_threshold: u32,

    /// Stake bonded as a validator candidate.
    pub bonded: Amount,

    /// The registered human-readable name, if any.
    pub name: Option<Name>,
}

impl Account {
    /// An account with nothing in it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The balance of `asset`, or zero.
    #[must_use]
    pub fn balance(&self, asset: Option<AssetId>) -> Amount {
        self.balances.get(&asset).copied().unwrap_or(Amount::ZERO)
    }

    /// Adds to a balance, or returns `None` on overflow.
    #[must_use]
    pub fn credit(&mut self, asset: Option<AssetId>, amount: Amount) -> Option<()> {
        let updated = self.balance(asset).checked_add(amount)?;
        self.balances.insert(asset, updated);
        Some(())
    }

    /// Subtracts from a balance, or returns `None` if there is not enough.
    ///
    /// A balance that reaches zero is **removed** rather than stored as zero.
    /// Settled obligations leave state the moment they close: the ledger keeps
    /// current obligations, not the memory of paid debts, and that is what
    /// keeps a full node runnable on a small computer a decade from now.
    #[must_use]
    pub fn debit(&mut self, asset: Option<AssetId>, amount: Amount) -> Option<()> {
        let updated = self.balance(asset).checked_sub(amount)?;
        if updated.is_zero() {
            self.balances.remove(&asset);
        } else {
            self.balances.insert(asset, updated);
        }
        Some(())
    }

    /// The sum of every device's declared share.
    #[must_use]
    pub fn allocated_nomad(&self) -> Option<Amount> {
        Amount::checked_sum(self.devices.values().map(|device| device.nomad_share))
    }

    /// The digest of this account, as stored in the sparse Merkle tree.
    ///
    /// Its own domain, not the tree's leaf domain: a leaf covers
    /// `key ‖ value_hash` and this covers a record, and sharing the two would
    /// let a record whose encoding happened to be 64 bytes long collide with a
    /// leaf.
    #[must_use]
    pub fn value_hash(&self) -> Hash {
        Hasher::new(domain::STATE_VALUE).update(&self.to_canonical_bytes()).finalize()
    }

    /// Whether this account holds nothing the ledger needs to remember.
    ///
    /// Such an account is deleted rather than stored empty, for the same reason
    /// a zero balance is.
    #[must_use]
    pub fn is_vacant(&self) -> bool {
        self.balances.is_empty()
            && self.devices.is_empty()
            && self.revoked_devices.is_empty()
            && self.guardians.is_empty()
            && self.bonded.is_zero()
            && self.nomad_credit.is_zero()
            && self.nomad_margin.is_zero()
            && self.name.is_none()
    }
}

impl Encode for Account {
    fn encode(&self, out: &mut Encoder) {
        out.write_len(self.balances.len());
        for (asset, amount) in &self.balances {
            out.write_option(asset.as_ref());
            amount.encode(out);
        }
        self.nomad_credit.encode(out);
        self.nomad_margin.encode(out);

        out.write_len(self.devices.len());
        for (id, device) in &self.devices {
            id.encode(out);
            device.encode(out);
        }

        out.write_ordered_set(&self.revoked_devices);
        self.next_lane.encode(out);

        let lanes: Vec<(Lane, u64)> = self.lanes.lanes().collect();
        out.write_len(lanes.len());
        for (lane, sequence) in lanes {
            lane.encode(out);
            out.write_varint(sequence);
        }

        out.write_ordered_set(&self.guardians);
        out.write_varint(u64::from(self.guardian_threshold));
        self.bonded.encode(out);
        out.write_option(self.name.as_ref());
    }
}

impl Decode for Account {
    fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let mut balances = BTreeMap::new();
        let balance_count = input.read_seq_len()?;
        let mut previous: Option<Option<AssetId>> = None;
        for _ in 0..balance_count {
            let asset = input.read_option::<AssetId>()?;
            // Map keys must ascend strictly, like every other canonical map.
            if let Some(ref last) = previous {
                if asset <= *last {
                    return Err(CodecError::UnorderedSet { index: balances.len() });
                }
            }
            previous = Some(asset);
            balances.insert(asset, Amount::decode(input)?);
        }

        let nomad_credit = Amount::decode(input)?;
        let nomad_margin = Amount::decode(input)?;

        let mut devices = BTreeMap::new();
        let device_count = input.read_seq_len()?;
        let mut previous_device: Option<DeviceId> = None;
        for _ in 0..device_count {
            let id = DeviceId::decode(input)?;
            if let Some(last) = previous_device {
                if id <= last {
                    return Err(CodecError::UnorderedSet { index: devices.len() });
                }
            }
            previous_device = Some(id);
            devices.insert(id, Device::decode(input)?);
        }

        let revoked_devices: BTreeSet<DeviceId> =
            input.read_set::<DeviceId>()?.into_iter().collect();
        let next_lane = Lane::decode(input)?;

        let mut lanes = LaneState::new();
        let lane_count = input.read_seq_len()?;
        let mut previous_lane: Option<Lane> = None;
        for _ in 0..lane_count {
            let lane = Lane::decode(input)?;
            if let Some(last) = previous_lane {
                if lane <= last {
                    return Err(CodecError::UnorderedSet { index: 0 });
                }
            }
            previous_lane = Some(lane);
            let sequence = input.read_varint()?;
            lanes.restore(lane, sequence);
        }

        let guardians: BTreeSet<AccountId> = input.read_set::<AccountId>()?.into_iter().collect();
        let guardian_threshold = input.read_varint_u32()?;
        let bonded = Amount::decode(input)?;
        let name = input.read_option::<Name>()?;

        Ok(Self {
            balances,
            nomad_credit,
            nomad_margin,
            devices,
            revoked_devices,
            next_lane,
            lanes,
            guardians,
            guardian_threshold,
            bonded,
            name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Account, Device};
    use vanargand_types::codec::{Decode, Encode};
    use vanargand_types::id::{AssetId, DeviceId};
    use vanargand_types::nonce::{Lane, Nonce};
    use vanargand_types::{Amount, Hash};
    use vanargand_crypto::algorithm::AlgorithmId;
    use vanargand_crypto::sign::VerifyingKey;

    fn key(byte: u8) -> VerifyingKey {
        VerifyingKey::new(AlgorithmId::InsecureTest, vec![byte; 32]).unwrap()
    }

    fn asset(byte: u8) -> AssetId {
        AssetId::from_hash(Hash::from_bytes([byte; 32]))
    }

    fn populated() -> Account {
        let mut account = Account::new();
        account.credit(None, Amount::from_ulf(1_000)).unwrap();
        account.credit(Some(asset(1)), Amount::from_ulf(50)).unwrap();
        account.nomad_credit = Amount::from_ulf(200);
        account.nomad_margin = Amount::from_ulf(20);
        account.devices.insert(
            DeviceId::of_device_key(&key(1)),
            Device {
                key: key(1),
                lane: Lane::FIRST,
                nomad_share: Amount::from_ulf(120),
                nomad_spent: Amount::from_ulf(30),
            },
        );
        account.revoked_devices.insert(DeviceId::from_hash(Hash::from_bytes([9; 32])));
        account.next_lane = Lane::new(1);
        account.lanes.consume(Nonce::new(Lane::FIRST, 0));
        account.guardian_threshold = 2;
        account.bonded = Amount::from_ulf(10_000);
        account
    }

    #[test]
    fn accounts_round_trip() {
        let account = populated();
        let bytes = account.to_canonical_bytes();
        assert_eq!(Account::from_canonical_bytes(&bytes), Ok(account));
    }

    #[test]
    fn an_empty_account_round_trips() {
        let account = Account::new();
        assert_eq!(
            Account::from_canonical_bytes(&account.to_canonical_bytes()),
            Ok(account.clone())
        );
        assert!(account.is_vacant());
    }

    #[test]
    fn the_value_hash_changes_with_every_field() {
        let base = populated();
        let baseline = base.value_hash();

        let mut other = base.clone();
        other.nomad_credit = Amount::from_ulf(201);
        assert_ne!(other.value_hash(), baseline);

        let mut other = base.clone();
        other.bonded = Amount::from_ulf(10_001);
        assert_ne!(other.value_hash(), baseline);

        let mut other = base;
        other.credit(None, Amount::ONE_ULF).unwrap();
        assert_ne!(other.value_hash(), baseline);
    }

    #[test]
    fn a_zero_balance_is_removed_rather_than_stored() {
        // "Le registre n'a pas de mémoire des dettes payées." A stored zero is
        // a row that never goes away, for every account that ever held a token.
        let mut account = Account::new();
        account.credit(Some(asset(1)), Amount::from_ulf(10)).unwrap();
        assert_eq!(account.balances.len(), 1);
        account.debit(Some(asset(1)), Amount::from_ulf(10)).unwrap();
        assert!(account.balances.is_empty(), "a zero balance was kept in state");
        assert_eq!(account.balance(Some(asset(1))), Amount::ZERO);
    }

    #[test]
    fn a_debit_beyond_the_balance_fails_and_changes_nothing() {
        let mut account = Account::new();
        account.credit(None, Amount::from_ulf(5)).unwrap();
        assert_eq!(account.debit(None, Amount::from_ulf(6)), None);
        assert_eq!(account.balance(None), Amount::from_ulf(5));
    }

    #[test]
    fn the_native_asset_is_absence_not_a_reserved_identifier() {
        let mut account = Account::new();
        account.credit(None, Amount::from_ulf(1)).unwrap();
        account.credit(Some(asset(0)), Amount::from_ulf(2)).unwrap();
        assert_eq!(account.balance(None), Amount::from_ulf(1));
        assert_eq!(account.balance(Some(asset(0))), Amount::from_ulf(2));
        // And `None` sorts first, deterministically.
        let keys: Vec<_> = account.balances.keys().copied().collect();
        assert_eq!(keys, vec![None, Some(asset(0))]);
    }

    #[test]
    fn nomad_remaining_never_goes_negative() {
        let device = Device {
            key: key(1),
            lane: Lane::FIRST,
            nomad_share: Amount::from_ulf(10),
            nomad_spent: Amount::from_ulf(25),
        };
        assert_eq!(device.nomad_remaining(), Amount::ZERO);
    }

    #[test]
    fn the_allocated_share_is_summed_with_overflow_checked() {
        let mut account = Account::new();
        for byte in 1..4_u8 {
            account.devices.insert(
                DeviceId::of_device_key(&key(byte)),
                Device {
                    key: key(byte),
                    lane: Lane::new(u32::from(byte)),
                    nomad_share: Amount::from_ulf(10),
                    nomad_spent: Amount::ZERO,
                },
            );
        }
        assert_eq!(account.allocated_nomad(), Some(Amount::from_ulf(30)));
    }
}
