// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Channels and local assets, end to end through the ledger.
//!
//! The scenario worth following is the train from `docs/01-concept.pdf`: a
//! passenger opens a channel with someone sharing their connection, pays per
//! megabyte off-chain, and settles once. Then the same channel, with the payer
//! cheating on the way out, and the payee's watchtower objecting.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use vanargand_bourse::payword::PayWordPayer;
use vanargand_bourse::purse::DISPUTE_WINDOW_FINALIZED_BLOCKS;
use vanargand_bourse::watchtower::{Verdict, Watchtower};
use vanargand_crypto::algorithm::AlgorithmId;
use vanargand_crypto::sign::{self, Keypair, VerifyingKey};
use vanargand_state::account::{Account, Device};
use vanargand_state::ledger::{BlockContext, Ledger, StateError};
use vanargand_types::block::FinalityRung;
use vanargand_types::id::{AccountId, AssetId, ChainId, DeviceId, TxId};
use vanargand_types::name::Name;
use vanargand_types::nonce::{Lane, Nonce};
use vanargand_types::tx::{asset_id_of, TxBody, TxKind, TX_VERSION};
use vanargand_types::{Amount, Hash};

const TRANCHE: u64 = 10;
const DEPOSIT: u64 = 10_000;

fn keypair(byte: u8) -> Keypair {
    sign::keypair_from_seed(AlgorithmId::InsecureTest, &Hash::from_bytes([byte; 32])).unwrap()
}

fn account_id(byte: u8) -> AccountId {
    AccountId::from_hash(Hash::from_bytes([byte; 32]))
}

fn chain() -> ChainId {
    ChainId::from_hash(Hash::from_bytes([0x11; 32]))
}

fn funded(key: &VerifyingKey, balance: u64) -> Account {
    let mut account = Account::new();
    account.credit(None, Amount::from_ulf(balance)).unwrap();
    account.nomad_credit = Amount::from_ulf(balance);
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

/// A passenger and a gateway on a train, both able to transact.
struct Train {
    ledger: Ledger,
    passenger_key: Keypair,
    gateway_key: Keypair,
    passenger: AccountId,
    gateway: AccountId,
    payword: PayWordPayer,
}

/// Both parties are funded up front, so that every test can compare the total
/// before and after without an account appearing out of nowhere half way
/// through and muddying the conservation check.
fn train() -> Train {
    let passenger_key = keypair(1);
    let gateway_key = keypair(2);
    let passenger = account_id(0xa1);
    let gateway = account_id(0xb1);

    let chain_seed = Hash::from_bytes([0x77; 32]);
    // The chain is as long as the deposit can pay for: 10 000 ÷ 10.
    let payword = PayWordPayer::open(&chain_seed, 1_000, Amount::from_ulf(TRANCHE)).unwrap();

    let mut ledger = Ledger::new();
    ledger.put_account(passenger, funded(&passenger_key.verifying, 50_000));
    ledger.put_account(gateway, funded(&gateway_key.verifying, 1_000));
    Train { ledger, passenger_key, gateway_key, passenger, gateway, payword }
}

fn open_channel(
    ledger: &mut Ledger,
    key: &Keypair,
    passenger: AccountId,
    gateway: AccountId,
    payword: &PayWordPayer,
    sequence: u64,
) -> TxId {
    let open = body(
        passenger,
        &key.verifying,
        sequence,
        TxKind::PurseOpen {
            counterparty: gateway,
            asset: None,
            deposit: Amount::from_ulf(DEPOSIT),
            payword_root: payword.root(),
            tranche_value: Amount::from_ulf(TRANCHE),
            expiry_finalized_height: 10_000_000,
        },
    );
    let id = open.id();
    ledger.apply(&context(100), &open).expect("opening a channel");
    id
}

fn total(ledger: &Ledger) -> Amount {
    ledger
        .total_native_balance()
        .unwrap()
        .checked_add(ledger.burned())
        .unwrap()
        .checked_add(ledger.context_pot())
        .unwrap()
}

// --------------------------------------------------------------------------

#[test]
fn opening_a_channel_locks_the_deposit_without_losing_it() {
    let Train { mut ledger, passenger_key: key, passenger, gateway, payword, .. } = train();
    let before = total(&ledger);

    let id = open_channel(&mut ledger, &key, passenger, gateway, &payword, 0);

    assert_eq!(ledger.purses().len(), 1);
    assert_eq!(
        ledger.account(&passenger).unwrap().balance(None),
        Amount::from_ulf(50_000 - DEPOSIT - 10)
    );
    assert_eq!(
        total(&ledger),
        before,
        "a locked deposit vanished from the accounting; every channel would look like a burn"
    );

    // And the channel is provable against the state root.
    let root = ledger.state_root();
    let purse = ledger.purses().get(&id).unwrap();
    assert!(ledger.prove_purse(&id).verify(
        &root,
        &vanargand_state::keys::purse(&id),
        Some(&vanargand_state::PurseBook::value_hash(purse))
    ));
}

#[test]
fn the_capacity_is_derived_from_the_money_not_declared() {
    // There is no capacity field in the transaction, and there should not be: a
    // declared capacity is a number that can disagree with the deposit.
    let Train { mut ledger, passenger_key: key, passenger, gateway, payword, .. } = train();
    let id = open_channel(&mut ledger, &key, passenger, gateway, &payword, 0);
    assert_eq!(ledger.purses().get(&id).unwrap().capacity, 1_000);
}

#[test]
fn a_tranche_worth_nothing_is_refused() {
    let Train { mut ledger, passenger_key: key, passenger, gateway, payword, .. } = train();
    let bad = body(
        passenger,
        &key.verifying,
        0,
        TxKind::PurseOpen {
            counterparty: gateway,
            asset: None,
            deposit: Amount::from_ulf(DEPOSIT),
            payword_root: payword.root(),
            tranche_value: Amount::ZERO,
            expiry_finalized_height: 10_000_000,
        },
    );
    assert_eq!(ledger.apply(&context(100), &bad), Err(StateError::ZeroTrancheValue));
    assert!(ledger.purses().is_empty());
}

#[test]
fn a_cooperative_closure_pays_both_sides() {
    // The ordinary end of a journey: the passenger spent 400 tranches, both
    // parties sign the split, and one entry in the register settles it.
    let Train { mut ledger, passenger_key: key, gateway_key, passenger, gateway, mut payword } = train();
    let before = total(&ledger);
    let id = open_channel(&mut ledger, &key, passenger, gateway, &payword, 0);

    let _ = payword.spend(400).unwrap();
    let spent = Amount::from_ulf(400 * TRANCHE);
    let returned = Amount::from_ulf(DEPOSIT).checked_sub(spent).unwrap();

    let close = body(
        passenger,
        &key.verifying,
        1,
        TxKind::PurseCloseCooperative {
            purse: id,
            payer_balance: returned,
            payee_balance: spent,
            counterparty_signature: sign::sign(&gateway_key.signing, b"agreed").unwrap(),
        },
    );
    ledger.apply(&context(200), &close).expect("a balanced closure");

    assert_eq!(ledger.account(&gateway).unwrap().balance(None), spent);
    assert!(ledger.purses().is_empty(), "a settled channel stayed in state");
    assert_eq!(total(&ledger), before, "value was created or lost");
}

#[test]
fn a_stale_closure_is_overturned_by_a_watchtower_and_punished() {
    // The scenario C5 and C9 exist for, played through the ledger.
    let Train { mut ledger, passenger_key: key, gateway_key, passenger, gateway, mut payword } = train();
    let before = total(&ledger);
    let id = open_channel(&mut ledger, &key, passenger, gateway, &payword, 0);

    // The passenger really spent 400 tranches.
    let stale = payword.spend(40).unwrap();
    let truth = payword.spend(360).unwrap();

    // The gateway's watchtower has the newest token.
    let mut tower = Watchtower::for_owner(gateway);
    assert!(tower.observe(id, truth));

    // The passenger closes claiming 40.
    let cheat = body(
        passenger,
        &key.verifying,
        1,
        TxKind::PurseCloseUnilateral {
            purse: id,
            tranches_claimed: 40,
            payword_token: stale.link,
        },
    );
    ledger.apply(&context(200), &cheat).expect("the stale claim is structurally valid");

    // The watchtower notices and says what to publish.
    let purse = ledger.purses().get(&id).unwrap().clone();
    let verdict = tower.inspect(&id, &purse);
    let Verdict::Dispute { tranches, token } = verdict else {
        panic!("the watchtower did not object: {verdict:?}");
    };
    assert_eq!(tranches, 400);

    // Anyone may publish it — here the gateway itself, which is what R1.6's
    // "every device is a watchtower" makes the ordinary case.
    let objection = body(
        gateway,
        &gateway_key.verifying,
        0,
        TxKind::PurseDispute { purse: id, tranches_claimed: tranches, payword_token: token.link },
    );
    ledger.apply(&context(210), &objection).expect("a genuine larger token");

    // Nothing settles until the window has run in finalised height.
    assert!(ledger.settle_elapsed_purses(210).unwrap().is_empty());
    assert_eq!(ledger.purses().len(), 1);

    let payouts = ledger
        .settle_elapsed_purses(200 + DISPUTE_WINDOW_FINALIZED_BLOCKS)
        .expect("settlement");
    assert_eq!(payouts.len(), 1);
    let payout = payouts.first().unwrap();
    assert_eq!(payout.settlement.to_payee, Amount::from_ulf(DEPOSIT), "the cheat kept something");
    assert_eq!(payout.settlement.to_payer, Amount::ZERO);

    assert!(ledger.purses().is_empty());
    assert_eq!(total(&ledger), before, "value was created or lost");

    // The passenger paid 10 000 for 4 000 of traffic. That is the penalty
    // working: a watchtower that is not paid is a watchtower that is not
    // watching, and the money comes from the party that tried to cheat it.
    assert!(
        ledger.account(&gateway).unwrap().balance(None) > Amount::from_ulf(10_000),
        "the gateway was not made whole"
    );
}

#[test]
fn a_partition_settles_nothing() {
    // C9 through the ledger: the ordinary height runs away, the finalised tip
    // does not, and nothing is paid to anybody.
    let Train { mut ledger, passenger_key: key, passenger, gateway, mut payword, .. } = train();
    let id = open_channel(&mut ledger, &key, passenger, gateway, &payword, 0);
    let token = payword.spend(10).unwrap();

    let close = body(
        passenger,
        &key.verifying,
        1,
        TxKind::PurseCloseUnilateral {
            purse: id,
            tranches_claimed: 10,
            payword_token: token.link,
        },
    );
    ledger.apply(&context(200), &close).expect("an honest claim");

    // Sixty thousand provisional blocks later, the finalised tip is unmoved.
    assert!(
        ledger.settle_elapsed_purses(200).unwrap().is_empty(),
        "a channel settled inside a partition; C9 is open"
    );
    assert_eq!(ledger.purses().len(), 1);

    // Only finalised progress pays.
    assert_eq!(
        ledger.settle_elapsed_purses(200 + DISPUTE_WINDOW_FINALIZED_BLOCKS).unwrap().len(),
        1
    );
}

#[test]
fn a_channel_cannot_be_opened_in_a_provisional_block_beyond_the_offline_credit() {
    // The two mechanisms meeting: opening a channel is whitelisted offline,
    // and the deposit still counts against the declared ceiling.
    let Train { mut ledger, passenger_key: key, passenger, gateway, payword, .. } = train();
    let mut account = ledger.account(&passenger).unwrap().clone();
    account.nomad_credit = Amount::from_ulf(500);
    if let Some(device) = account.devices.get_mut(&DeviceId::of_device_key(&key.verifying)) {
        device.nomad_share = Amount::from_ulf(500);
    }
    ledger.put_account(passenger, account);

    let offline = BlockContext {
        chain: chain(),
        height: 5_000,
        finalized_height: 100,
        rung: FinalityRung::Provisional,
        proposer: account_id(0xee),
    };
    let open = body(
        passenger,
        &key.verifying,
        0,
        TxKind::PurseOpen {
            counterparty: gateway,
            asset: None,
            deposit: Amount::from_ulf(DEPOSIT),
            payword_root: payword.root(),
            tranche_value: Amount::from_ulf(TRANCHE),
            expiry_finalized_height: 10_000_000,
        },
    );
    assert!(matches!(
        ledger.apply(&offline, &open),
        Err(StateError::NomadCreditExhausted { .. })
    ));
    assert!(ledger.purses().is_empty());
}

// --------------------------------------------------------------------------
// Local assets — R2's monetary inversion
// --------------------------------------------------------------------------

#[test]
fn a_festival_issues_its_own_token_and_the_van_stays_between_machines() {
    // The pilot's shape: the attendee pays in the organiser's closed token,
    // the VAN settles the infrastructure.
    let organiser_key = keypair(3);
    let organiser = account_id(0xc1);
    let attendee = account_id(0xc2);

    let mut ledger = Ledger::new();
    ledger.put_account(organiser, funded(&organiser_key.verifying, 10_000));

    let create = body(
        organiser,
        &organiser_key.verifying,
        0,
        TxKind::AssetCreate {
            ticker: Name::new("festi").unwrap(),
            decimals: 2,
            reissuable: true,
        },
    );
    let asset: AssetId = asset_id_of(organiser, create.id());
    ledger.apply(&context(100), &create).expect("a fresh ticker");

    assert_eq!(ledger.assets().len(), 1);
    assert_eq!(ledger.assets().get(&asset).unwrap().supply, Amount::ZERO);

    let mint = body(
        organiser,
        &organiser_key.verifying,
        1,
        TxKind::AssetMint { asset, to: attendee, amount: Amount::from_ulf(5_000) },
    );
    ledger.apply(&context(100), &mint).expect("the issuer may mint");

    assert_eq!(
        ledger.account(&attendee).unwrap().balance(Some(asset)),
        Amount::from_ulf(5_000)
    );
    assert_eq!(ledger.assets().get(&asset).unwrap().supply, Amount::from_ulf(5_000));

    // The attendee's VAN balance is untouched: the festival token is not VAN.
    assert_eq!(ledger.account(&attendee).unwrap().balance(None), Amount::ZERO);
}

#[test]
fn only_the_issuer_may_mint_through_the_ledger() {
    let organiser_key = keypair(3);
    let impostor_key = keypair(4);
    let organiser = account_id(0xc1);
    let impostor = account_id(0xc3);

    let mut ledger = Ledger::new();
    ledger.put_account(organiser, funded(&organiser_key.verifying, 10_000));
    ledger.put_account(impostor, funded(&impostor_key.verifying, 10_000));

    let create = body(
        organiser,
        &organiser_key.verifying,
        0,
        TxKind::AssetCreate { ticker: Name::new("festi").unwrap(), decimals: 0, reissuable: true },
    );
    let asset = asset_id_of(organiser, create.id());
    ledger.apply(&context(100), &create).unwrap();

    let forgery = body(
        impostor,
        &impostor_key.verifying,
        0,
        TxKind::AssetMint { asset, to: impostor, amount: Amount::from_ulf(1_000_000) },
    );
    assert!(matches!(
        ledger.apply(&context(100), &forgery),
        Err(StateError::Asset(vanargand_state::AssetError::NotTheIssuer { .. }))
    ));
    assert_eq!(ledger.assets().get(&asset).unwrap().supply, Amount::ZERO);
}

#[test]
fn a_ticker_can_be_proved_free_before_it_is_claimed() {
    // The non-inclusion half of the tree, doing something a wallet needs: check
    // that a name is available without trusting the node that said so.
    let organiser_key = keypair(3);
    let organiser = account_id(0xc1);
    let mut ledger = Ledger::new();
    ledger.put_account(organiser, funded(&organiser_key.verifying, 10_000));

    let wanted = Name::new("festi").unwrap();
    let root = ledger.state_root();
    assert!(
        ledger.prove_ticker(&wanted).verify(&root, &vanargand_state::keys::ticker(&wanted), None),
        "an unclaimed ticker could not be proved free"
    );

    let create = body(
        organiser,
        &organiser_key.verifying,
        0,
        TxKind::AssetCreate { ticker: wanted.clone(), decimals: 0, reissuable: false },
    );
    let asset = asset_id_of(organiser, create.id());
    ledger.apply(&context(100), &create).unwrap();

    let root = ledger.state_root();
    assert!(
        ledger.prove_ticker(&wanted).verify(
            &root,
            &vanargand_state::keys::ticker(&wanted),
            Some(asset.as_hash())
        ),
        "a claimed ticker could not be proved taken"
    );
}

#[test]
fn burning_a_token_reduces_its_supply() {
    let organiser_key = keypair(3);
    let organiser = account_id(0xc1);
    let mut ledger = Ledger::new();
    ledger.put_account(organiser, funded(&organiser_key.verifying, 10_000));

    let create = body(
        organiser,
        &organiser_key.verifying,
        0,
        TxKind::AssetCreate { ticker: Name::new("festi").unwrap(), decimals: 0, reissuable: true },
    );
    let asset = asset_id_of(organiser, create.id());
    ledger.apply(&context(100), &create).unwrap();

    let mint = body(
        organiser,
        &organiser_key.verifying,
        1,
        TxKind::AssetMint { asset, to: organiser, amount: Amount::from_ulf(100) },
    );
    ledger.apply(&context(100), &mint).unwrap();

    let burn = body(
        organiser,
        &organiser_key.verifying,
        2,
        TxKind::AssetBurn { asset, amount: Amount::from_ulf(40) },
    );
    ledger.apply(&context(100), &burn).unwrap();

    assert_eq!(ledger.assets().get(&asset).unwrap().supply, Amount::from_ulf(60));
    assert_eq!(ledger.account(&organiser).unwrap().balance(Some(asset)), Amount::from_ulf(60));
}

#[test]
fn burning_more_than_you_hold_changes_nothing() {
    let organiser_key = keypair(3);
    let organiser = account_id(0xc1);
    let mut ledger = Ledger::new();
    ledger.put_account(organiser, funded(&organiser_key.verifying, 10_000));

    let create = body(
        organiser,
        &organiser_key.verifying,
        0,
        TxKind::AssetCreate { ticker: Name::new("festi").unwrap(), decimals: 0, reissuable: true },
    );
    let asset = asset_id_of(organiser, create.id());
    ledger.apply(&context(100), &create).unwrap();

    let before = ledger.clone();
    let burn = body(
        organiser,
        &organiser_key.verifying,
        1,
        TxKind::AssetBurn { asset, amount: Amount::from_ulf(1) },
    );
    assert!(matches!(
        ledger.apply(&context(100), &burn),
        Err(StateError::InsufficientBalance { .. })
    ));
    assert_eq!(ledger, before, "a failed burn mutated the ledger");
}
