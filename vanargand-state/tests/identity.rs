// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Identity and self-proving fraud, end to end through the ledger.
//!
//! The centrepiece is `a_double_spend_across_partitions_convicts_itself`: R2's
//! extension of "fraud produces its own evidence" from validators to ordinary
//! accounts, which is the design's signature claim. Nothing detects the
//! double-spend. Spending the same offline credit twice *manufactures* the
//! proof, because a nomad spend travels on one device's sequenced lane.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use vanargand_crypto::algorithm::AlgorithmId;
use vanargand_crypto::sign::{self, Keypair, VerifyingKey};
use vanargand_state::account::{Account, Device};
use vanargand_state::ledger::{BlockContext, Ledger, StateError};
use vanargand_state::recovery::{RecoveryError, RECOVERY_WINDOW_FINALIZED_BLOCKS};
use vanargand_state::slashing::AccountOffence;
use vanargand_types::block::FinalityRung;
use vanargand_types::id::{AccountId, ChainId, DeviceId};
use vanargand_types::name::Name;
use vanargand_types::nonce::{Lane, Nonce};
use vanargand_types::tx::{
    name_commitment, AccountEquivocation, Transaction, TxBody, TxKind, TX_VERSION,
};
use vanargand_types::{Amount, Hash};

fn keypair(byte: u8) -> Keypair {
    sign::keypair_from_seed(AlgorithmId::InsecureTest, &Hash::from_bytes([byte; 32])).unwrap()
}

fn account_id(byte: u8) -> AccountId {
    AccountId::from_hash(Hash::from_bytes([byte; 32]))
}

fn chain() -> ChainId {
    ChainId::from_hash(Hash::from_bytes([0x11; 32]))
}

fn funded(key: &VerifyingKey, balance: u64, margin: u64) -> Account {
    let mut account = Account::new();
    account.credit(None, Amount::from_ulf(balance)).unwrap();
    account.nomad_credit = Amount::from_ulf(balance);
    account.nomad_margin = Amount::from_ulf(margin);
    account.devices.insert(
        DeviceId::of_device_key(key),
        Device {
            key: key.clone(),
            lane: Lane::FIRST,
            nomad_share: Amount::from_ulf(balance),
            nomad_spent: Amount::ZERO,
        },
    );
    account.next_lane = Lane::new(1);
    account
}

fn context(finalized: u64) -> BlockContext {
    BlockContext {
        chain: chain(),
        height: finalized + 60,
        finalized_height: finalized,
        rung: FinalityRung::Chain,
        proposer: account_id(0xee),
    }
}

fn body(account: AccountId, device: &VerifyingKey, sequence: u64, kind: TxKind) -> TxBody {
    TxBody {
        version: TX_VERSION,
        chain: chain(),
        account,
        device: DeviceId::of_device_key(device),
        nonce: Nonce::new(Lane::FIRST, sequence),
        fee: Amount::from_ulf(10),
        valid_until_finalized: None,
        kind,
    }
}

fn signed(pair: &Keypair, inner: TxBody) -> Transaction {
    let signature = sign::sign(&pair.signing, inner.signing_digest().as_bytes()).unwrap();
    Transaction { body: inner, signature }
}

// --------------------------------------------------------------------------
// The signature claim
// --------------------------------------------------------------------------

#[test]
fn a_double_spend_across_partitions_convicts_itself() {
    // Marie is cut off. She spends the same offline credit in the village and
    // in the town, on the same device, at the same sequence number. Nothing
    // watches for this; the two signatures *are* the proof, and anyone who
    // holds both can publish them.
    let marie_key = keypair(1);
    let marie = account_id(0xa1);
    let denouncer = account_id(0xd1);
    let denouncer_key = keypair(9);

    let mut ledger = Ledger::new();
    ledger.put_account(marie, funded(&marie_key.verifying, 10_000, 2_000));
    ledger.put_account(denouncer, funded(&denouncer_key.verifying, 1_000, 0));

    let slot = Nonce::new(Lane::FIRST, 3);
    let mut to_the_baker = body(
        marie,
        &marie_key.verifying,
        0,
        TxKind::Transfer {
            to: account_id(0xb1),
            asset: None,
            amount: Amount::from_ulf(500),
        },
    );
    to_the_baker.nonce = slot;
    let mut to_the_butcher = to_the_baker.clone();
    to_the_butcher.kind = TxKind::Transfer {
        to: account_id(0xb2),
        asset: None,
        amount: Amount::from_ulf(500),
    };

    let evidence = AccountEquivocation {
        device: DeviceId::of_device_key(&marie_key.verifying),
        first: signed(&marie_key, to_the_baker),
        second: signed(&marie_key, to_the_butcher),
    };

    let burned_before = ledger.burned();
    let denunciation = body(
        denouncer,
        &denouncer_key.verifying,
        0,
        TxKind::AccountEquivocation(Box::new(evidence)),
    );
    ledger.apply(&context(500), &denunciation).expect("the proof stands on its own");

    // The margin is gone: half to whoever published, half to the fire.
    assert_eq!(ledger.account(&marie).unwrap().nomad_margin, Amount::ZERO);
    assert_eq!(
        ledger.burned().checked_sub(burned_before).unwrap(),
        Amount::from_ulf(1_000).checked_add(Amount::from_ulf(1)).unwrap(),
        "the burn was not half the margin plus the fee's own share"
    );
    assert!(
        ledger.account(&denouncer).unwrap().balance(None) > Amount::from_ulf(1_000),
        "the denouncer was not paid; a proof nobody is paid to publish is a proof nobody publishes"
    );

    // And the crime is on the record.
    assert!(ledger.offences().knows_account(&AccountOffence {
        account: marie,
        device: DeviceId::of_device_key(&marie_key.verifying),
        lane: Lane::FIRST,
        sequence: 3,
    }));
}

#[test]
fn one_crime_earns_one_bounty_through_the_ledger() {
    // Without the offence record, a denouncer republishes the same proof after
    // the offender re-funds its margin and collects twice for one crime.
    let marie_key = keypair(1);
    let marie = account_id(0xa1);
    let denouncer = account_id(0xd1);
    let denouncer_key = keypair(9);

    let mut ledger = Ledger::new();
    ledger.put_account(marie, funded(&marie_key.verifying, 10_000, 2_000));
    ledger.put_account(denouncer, funded(&denouncer_key.verifying, 1_000, 0));

    let slot = Nonce::new(Lane::FIRST, 3);
    let mut first = body(
        marie,
        &marie_key.verifying,
        0,
        TxKind::Transfer { to: account_id(0xb1), asset: None, amount: Amount::from_ulf(1) },
    );
    first.nonce = slot;
    let mut second = first.clone();
    second.kind =
        TxKind::Transfer { to: account_id(0xb2), asset: None, amount: Amount::from_ulf(1) };

    let evidence = AccountEquivocation {
        device: DeviceId::of_device_key(&marie_key.verifying),
        first: signed(&marie_key, first),
        second: signed(&marie_key, second),
    };

    let denounce = |sequence: u64| {
        body(
            denouncer,
            &denouncer_key.verifying,
            sequence,
            TxKind::AccountEquivocation(Box::new(evidence.clone())),
        )
    };
    ledger.apply(&context(500), &denounce(0)).expect("first denunciation");

    // Marie re-funds her margin, hoping the old proof is spent.
    let mut refunded = ledger.account(&marie).unwrap().clone();
    refunded.nomad_margin = Amount::from_ulf(2_000);
    ledger.put_account(marie, refunded);

    assert!(
        matches!(
            ledger.apply(&context(600), &denounce(1)),
            Err(StateError::Slashing(_))
        ),
        "one crime paid twice"
    );
    assert_eq!(ledger.account(&marie).unwrap().nomad_margin, Amount::from_ulf(2_000));
}

#[test]
fn two_honest_devices_produce_no_conviction() {
    // R2's correction, through the ledger. Two devices of one account, isolated
    // in two partitions, spend at the same sequence number on *different*
    // lanes. That is the normal operating condition, not a crime.
    let phone = keypair(1);
    let laptop = keypair(2);
    let marie = account_id(0xa1);
    let denouncer_key = keypair(9);
    let denouncer = account_id(0xd1);

    let mut account = funded(&phone.verifying, 10_000, 2_000);
    account.devices.insert(
        DeviceId::of_device_key(&laptop.verifying),
        Device {
            key: laptop.verifying.clone(),
            lane: Lane::new(1),
            nomad_share: Amount::from_ulf(1_000),
            nomad_spent: Amount::ZERO,
        },
    );
    account.next_lane = Lane::new(2);

    let mut ledger = Ledger::new();
    ledger.put_account(marie, account);
    ledger.put_account(denouncer, funded(&denouncer_key.verifying, 1_000, 0));

    let transfer =
        TxKind::Transfer { to: account_id(0xb1), asset: None, amount: Amount::from_ulf(1) };
    let from_phone = signed(&phone, body(marie, &phone.verifying, 4, transfer.clone()));
    let mut laptop_body = body(marie, &laptop.verifying, 0, transfer);
    laptop_body.nonce = Nonce::new(Lane::new(1), 4);
    let from_laptop = signed(&laptop, laptop_body);

    let accusation = AccountEquivocation {
        device: DeviceId::of_device_key(&phone.verifying),
        first: from_phone,
        second: from_laptop,
    };
    let denunciation = body(
        denouncer,
        &denouncer_key.verifying,
        0,
        TxKind::AccountEquivocation(Box::new(accusation)),
    );

    assert!(
        matches!(ledger.apply(&context(500), &denunciation), Err(StateError::BadEvidence(_))),
        "an account was convicted for being in two places, which is its normal condition"
    );
    assert_eq!(ledger.account(&marie).unwrap().nomad_margin, Amount::from_ulf(2_000));
}

#[test]
fn an_unbonded_equivocation_convicts_but_seizes_nothing() {
    // R2 makes bonding the nomad credit optional, so this is the design rather
    // than a hole: the cheat is on the record and its losing spend unwinds on
    // reconciliation, and there is simply nothing to take.
    let marie_key = keypair(1);
    let marie = account_id(0xa1);
    let denouncer = account_id(0xd1);
    let denouncer_key = keypair(9);

    let mut ledger = Ledger::new();
    ledger.put_account(marie, funded(&marie_key.verifying, 10_000, 0));
    ledger.put_account(denouncer, funded(&denouncer_key.verifying, 1_000, 0));

    let mut first = body(
        marie,
        &marie_key.verifying,
        0,
        TxKind::Transfer { to: account_id(0xb1), asset: None, amount: Amount::from_ulf(1) },
    );
    first.nonce = Nonce::new(Lane::FIRST, 2);
    let mut second = first.clone();
    second.kind =
        TxKind::Transfer { to: account_id(0xb2), asset: None, amount: Amount::from_ulf(1) };

    let evidence = AccountEquivocation {
        device: DeviceId::of_device_key(&marie_key.verifying),
        first: signed(&marie_key, first),
        second: signed(&marie_key, second),
    };
    let denunciation = body(
        denouncer,
        &denouncer_key.verifying,
        0,
        TxKind::AccountEquivocation(Box::new(evidence)),
    );
    ledger.apply(&context(500), &denunciation).expect("conviction without seizure");

    assert_eq!(ledger.offences().len(), 1, "the conviction was not recorded");
    assert_eq!(ledger.account(&denouncer).unwrap().balance(None), Amount::from_ulf(1_000 - 10));
}

// --------------------------------------------------------------------------
// Names
// --------------------------------------------------------------------------

#[test]
fn a_name_is_registered_through_commit_and_reveal() {
    let marie_key = keypair(1);
    let marie = account_id(0xa1);
    let mut ledger = Ledger::new();
    ledger.put_account(marie, funded(&marie_key.verifying, 10_000, 0));

    let wanted = Name::new("cafe-du-port").unwrap();
    let salt = [0x5a_u8; 32];

    let commit = body(
        marie,
        &marie_key.verifying,
        0,
        TxKind::NameCommit { commitment: name_commitment(&wanted, &salt, marie) },
    );
    ledger.apply(&context(100), &commit).expect("staking a claim");
    assert!(ledger.names().owner(&wanted).is_none(), "the name leaked from the commitment");

    let reveal =
        body(marie, &marie_key.verifying, 1, TxKind::NameReveal { name: wanted.clone(), salt });
    assert!(
        matches!(ledger.apply(&context(100), &reveal), Err(StateError::Name(_))),
        "a reveal in the same block was accepted; a proposer could reorder the two"
    );

    ledger.apply(&context(200), &reveal).expect("the delay has passed");
    assert_eq!(ledger.names().owner(&wanted), Some(marie));
}

#[test]
fn a_premium_name_is_refused_until_the_auction_exists() {
    // R1.7 auctions names under six characters. Handing them out first-come in
    // the meantime would give away exactly the names the auction protects, and
    // unlike refusing, it cannot be undone.
    let marie_key = keypair(1);
    let marie = account_id(0xa1);
    let mut ledger = Ledger::new();
    ledger.put_account(marie, funded(&marie_key.verifying, 10_000, 0));

    let short = Name::new("marie").unwrap();
    let salt = [0x5a_u8; 32];
    let commit = body(
        marie,
        &marie_key.verifying,
        0,
        TxKind::NameCommit { commitment: name_commitment(&short, &salt, marie) },
    );
    ledger.apply(&context(100), &commit).unwrap();

    let reveal = body(marie, &marie_key.verifying, 1, TxKind::NameReveal { name: short, salt });
    assert!(matches!(ledger.apply(&context(200), &reveal), Err(StateError::Name(_))));
    assert!(ledger.names().is_empty());
}

// --------------------------------------------------------------------------
// Recovery
// --------------------------------------------------------------------------

/// Marie, her five guardians, and a ledger they can all transact on.
fn with_guardians() -> (Ledger, Keypair, AccountId, Vec<(AccountId, Keypair)>) {
    let marie_key = keypair(1);
    let marie = account_id(0xa1);
    let mut ledger = Ledger::new();
    ledger.put_account(marie, funded(&marie_key.verifying, 10_000, 0));

    let mut guardians = Vec::new();
    for byte in 10..15_u8 {
        let key = keypair(byte);
        let id = account_id(byte);
        ledger.put_account(id, funded(&key.verifying, 1_000, 0));
        guardians.push((id, key));
    }

    let set: BTreeSet<AccountId> = guardians.iter().map(|(id, _)| *id).collect();
    let declare = body(
        marie,
        &marie_key.verifying,
        0,
        TxKind::GuardianSet { guardians: set, threshold: 3 },
    );
    ledger.apply(&context(100), &declare).expect("naming guardians");
    (ledger, marie_key, marie, guardians)
}

#[test]
fn three_of_five_guardians_recover_an_account() {
    let (mut ledger, _, marie, guardians) = with_guardians();
    let new_root = keypair(99);

    // Each guardian signs its own transaction, on its own lane, at its own
    // sequence zero — which is the point of collecting the threshold this way:
    // no aggregate signature format, and guardians can approve from different
    // sides of a partition without coordinating.
    for (id, key) in guardians.iter().take(3) {
        let approval = body(
            *id,
            &key.verifying,
            0,
            TxKind::RecoveryStart { account: marie, new_root_key: new_root.verifying.clone() },
        );
        ledger.apply(&context(200), &approval).expect("a guardian approving");
    }
    assert_eq!(ledger.recoveries().get(&marie).unwrap().approval_count(), 3);

    // The threshold alone does not finish it.
    let finish = body(
        guardians[0].0,
        &guardians[0].1.verifying,
        1,
        TxKind::RecoveryFinalise { account: marie },
    );
    assert!(matches!(
        ledger.apply(&context(200), &finish),
        Err(StateError::Recovery(RecoveryError::WindowOpen { .. }))
    ));

    ledger
        .apply(&context(200 + RECOVERY_WINDOW_FINALIZED_BLOCKS), &finish)
        .expect("threshold met and window elapsed");

    // The old device is gone for good; the new key can sign.
    let recovered = ledger.account(&marie).unwrap();
    assert!(recovered.devices.contains_key(&DeviceId::of_device_key(&new_root.verifying)));
    assert_eq!(recovered.devices.len(), 1);
    assert_eq!(recovered.revoked_devices.len(), 1);
    assert_eq!(
        recovered.nomad_credit,
        Amount::ZERO,
        "a recovered account kept an offline credit it had just proved it could not hold"
    );
}

#[test]
fn a_surviving_device_cancels_a_recovery() {
    // The defence that makes the whole mechanism safe to offer: the guardians
    // can start a recovery and cannot finish one against an owner who is still
    // there.
    let (mut ledger, marie_key, marie, guardians) = with_guardians();
    let new_root = keypair(99);

    for (id, key) in guardians.iter().take(3) {
        let approval = body(
            *id,
            &key.verifying,
            0,
            TxKind::RecoveryStart { account: marie, new_root_key: new_root.verifying.clone() },
        );
        ledger.apply(&context(200), &approval).unwrap();
    }

    let cancel =
        body(marie, &marie_key.verifying, 1, TxKind::RecoveryCancel { account: marie });
    ledger.apply(&context(300), &cancel).expect("the owner objects");
    assert!(ledger.recoveries().is_empty());

    let finish = body(
        guardians[0].0,
        &guardians[0].1.verifying,
        1,
        TxKind::RecoveryFinalise { account: marie },
    );
    assert!(matches!(
        ledger.apply(&context(200 + RECOVERY_WINDOW_FINALIZED_BLOCKS), &finish),
        Err(StateError::Recovery(RecoveryError::NotRecovering))
    ));
    assert!(ledger.account(&marie).unwrap().devices.contains_key(
        &DeviceId::of_device_key(&marie_key.verifying)
    ));
}

#[test]
fn a_stranger_cannot_approve_a_recovery() {
    let (mut ledger, _, marie, _) = with_guardians();
    let stranger_key = keypair(50);
    let stranger = account_id(50);
    ledger.put_account(stranger, funded(&stranger_key.verifying, 1_000, 0));

    let approval = body(
        stranger,
        &stranger_key.verifying,
        0,
        TxKind::RecoveryStart { account: marie, new_root_key: keypair(99).verifying },
    );
    assert!(matches!(
        ledger.apply(&context(200), &approval),
        Err(StateError::Recovery(RecoveryError::NotAGuardian(_)))
    ));
    assert!(ledger.recoveries().is_empty());
}

#[test]
fn a_rogue_guardian_cannot_redirect_a_recovery_through_the_ledger() {
    let (mut ledger, _, marie, guardians) = with_guardians();
    let agreed = keypair(99);
    let rogue_choice = keypair(98);

    for (id, key) in guardians.iter().take(2) {
        let approval = body(
            *id,
            &key.verifying,
            0,
            TxKind::RecoveryStart { account: marie, new_root_key: agreed.verifying.clone() },
        );
        ledger.apply(&context(200), &approval).unwrap();
    }

    let (rogue_id, rogue_key) = &guardians[2];
    let redirect = body(
        *rogue_id,
        &rogue_key.verifying,
        0,
        TxKind::RecoveryStart { account: marie, new_root_key: rogue_choice.verifying },
    );
    assert!(matches!(
        ledger.apply(&context(200), &redirect),
        Err(StateError::Recovery(RecoveryError::ConflictingKey))
    ));
    assert_eq!(ledger.recoveries().get(&marie).unwrap().new_root_key, agreed.verifying);
}
