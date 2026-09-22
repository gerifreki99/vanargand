// SPDX-FileCopyrightText: 2026 Freki Geri
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ledger behaviour, with the nomad credit as the centrepiece.
//!
//! The scenario that matters is the one from `docs/01-concept.pdf`: a storm
//! cuts a village's fibre for a week, the villagers keep paying each other, and
//! the baker knows before she hands over the bread what she is risking.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use vanargand_crypto::algorithm::AlgorithmId;
use vanargand_crypto::sign::{self, Keypair, VerifyingKey};
use vanargand_state::account::{Account, Device};
use vanargand_state::ledger::{BlockContext, Ledger, StateError};
use vanargand_types::block::FinalityRung;
use vanargand_types::id::{AccountId, ChainId, DeviceId};
use vanargand_types::nonce::{Lane, Nonce};
use vanargand_types::tx::{TxBody, TxKind, TX_VERSION};
use vanargand_types::{Amount, Hash};

const CHAIN: [u8; 32] = [0x11; 32];

fn keypair(byte: u8) -> Keypair {
    sign::keypair_from_seed(AlgorithmId::InsecureTest, &Hash::from_bytes([byte; 32])).unwrap()
}

fn chain() -> ChainId {
    ChainId::from_hash(Hash::from_bytes(CHAIN))
}

fn account_id(byte: u8) -> AccountId {
    AccountId::from_hash(Hash::from_bytes([byte; 32]))
}

/// An account with one device, a balance, and a declared offline credit.
fn villager(key: &VerifyingKey, balance: u64, credit: u64, share: u64) -> Account {
    let mut account = Account::new();
    account.credit(None, Amount::from_ulf(balance)).unwrap();
    account.nomad_credit = Amount::from_ulf(credit);
    account.devices.insert(
        DeviceId::of_device_key(key),
        Device {
            key: key.clone(),
            lane: Lane::FIRST,
            nomad_share: Amount::from_ulf(share),
            nomad_spent: Amount::ZERO,
        },
    );
    account.next_lane = Lane::new(1);
    account
}

fn context(rung: FinalityRung) -> BlockContext {
    BlockContext {
        chain: chain(),
        height: 100,
        finalized_height: if rung == FinalityRung::Chain { 100 } else { 40 },
        rung,
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

fn transfer(to: AccountId, amount: u64) -> TxKind {
    TxKind::Transfer { to, asset: None, amount: Amount::from_ulf(amount) }
}

/// A ledger with Marie (the payer) and the baker.
fn village() -> (Ledger, Keypair, AccountId, AccountId) {
    let marie_key = keypair(1);
    let marie = account_id(0xa1);
    let baker = account_id(0xb1);

    let mut ledger = Ledger::new();
    ledger.put_account(marie, villager(&marie_key.verifying, 10_000, 500, 500));
    ledger.put_account(baker, Account::new());
    (ledger, marie_key, marie, baker)
}

// --------------------------------------------------------------------------
// The offline credit
// --------------------------------------------------------------------------

#[test]
fn an_offline_payment_within_the_declared_credit_succeeds() {
    let (mut ledger, key, marie, baker) = village();
    let ctx = context(FinalityRung::Provisional);

    let applied = ledger
        .apply(&ctx, &body(marie, &key.verifying, 0, transfer(baker, 100)))
        .expect("a payment inside the declared credit must go through");

    // The fee and the payment both count against the credit: an attacker able
    // to pay unlimited fees offline would drain the account past the ceiling
    // the merchant was shown.
    assert_eq!(applied.nomad_consumed, Amount::from_ulf(110));
    assert_eq!(ledger.account(&baker).unwrap().balance(None), Amount::from_ulf(100));
}

#[test]
fn the_declared_credit_is_a_hard_ceiling_offline() {
    // The merchant-facing guarantee. Marie has ten thousand in the bank and has
    // declared five hundred spendable offline. The village is cut off. She can
    // spend five hundred, and the five hundred and first ulf is refused by the
    // protocol rather than by anybody's judgement.
    let (mut ledger, key, marie, baker) = village();
    let ctx = context(FinalityRung::Provisional);

    let mut sequence = 0;
    let mut spent = Amount::ZERO;
    loop {
        let candidate = body(marie, &key.verifying, sequence, transfer(baker, 40));
        match ledger.apply(&ctx, &candidate) {
            Ok(applied) => {
                spent = spent.checked_add(applied.nomad_consumed).unwrap();
                sequence += 1;
            }
            Err(StateError::NomadCreditExhausted { remaining, needed, .. }) => {
                assert!(needed > remaining);
                break;
            }
            Err(other) => panic!("unexpected failure: {other}"),
        }
        assert!(sequence < 100, "the ceiling was never reached");
    }

    assert!(
        spent <= Amount::from_ulf(500),
        "spent {spent} offline against a declared credit of 500 ulf"
    );
    // Marie still has most of her money; only the declared slice was ever at
    // risk.
    assert!(ledger.account(&marie).unwrap().balance(None) > Amount::from_ulf(9_000));
}

#[test]
fn the_same_payment_is_unbounded_once_the_chain_finalises_again() {
    // The credit exists only while the chain cannot finalise. With rung-2
    // finality the ledger has the last word and there is nothing to bound.
    let (mut ledger, key, marie, baker) = village();
    let ctx = context(FinalityRung::Chain);

    let applied = ledger
        .apply(&ctx, &body(marie, &key.verifying, 0, transfer(baker, 5_000)))
        .expect("a payment far above the offline credit is fine when online");
    assert_eq!(applied.nomad_consumed, Amount::ZERO);
    assert_eq!(ledger.account(&baker).unwrap().balance(None), Amount::from_ulf(5_000));
}

#[test]
fn reconnection_restores_the_offline_allowance() {
    // The credit is a per-outage allowance, not a lifetime one: the ceiling
    // applies to the partition the merchant is standing in.
    let (mut ledger, key, marie, baker) = village();
    let ctx = context(FinalityRung::Provisional);

    ledger.apply(&ctx, &body(marie, &key.verifying, 0, transfer(baker, 400))).unwrap();
    assert!(ledger.apply(&ctx, &body(marie, &key.verifying, 1, transfer(baker, 400))).is_err());

    ledger.settle_nomad_counters();
    ledger
        .apply(&ctx, &body(marie, &key.verifying, 1, transfer(baker, 400)))
        .expect("the allowance should be restored after reconnection");
}

#[test]
fn two_devices_of_one_account_have_separate_allowances() {
    // R2's per-device split. Each device can only overspend against itself,
    // which is exactly the case that deserves punishing — and two honest
    // devices in two partitions never interfere.
    let phone = keypair(1);
    let laptop = keypair(2);
    let marie = account_id(0xa1);
    let baker = account_id(0xb1);

    let mut account = villager(&phone.verifying, 10_000, 500, 200);
    account.devices.insert(
        DeviceId::of_device_key(&laptop.verifying),
        Device {
            key: laptop.verifying.clone(),
            lane: Lane::new(1),
            nomad_share: Amount::from_ulf(300),
            nomad_spent: Amount::ZERO,
        },
    );
    account.next_lane = Lane::new(2);

    let mut ledger = Ledger::new();
    ledger.put_account(marie, account);
    ledger.put_account(baker, Account::new());
    let ctx = context(FinalityRung::Provisional);

    // The phone exhausts its own share.
    ledger.apply(&ctx, &body(marie, &phone.verifying, 0, transfer(baker, 190))).unwrap();
    assert!(matches!(
        ledger.apply(&ctx, &body(marie, &phone.verifying, 1, transfer(baker, 50))),
        Err(StateError::NomadCreditExhausted { .. })
    ));

    // The laptop, on its own lane, is untouched by that.
    let mut laptop_body = body(marie, &laptop.verifying, 0, transfer(baker, 250));
    laptop_body.nonce = Nonce::new(Lane::new(1), 0);
    ledger.apply(&ctx, &laptop_body).expect("the laptop's own share must be intact");
}

#[test]
fn a_local_asset_escapes_the_offline_ceiling() {
    // A gap, pinned rather than hidden.
    //
    // R2's monetary inversion puts the festival-goer's payments in the
    // organiser's closed token, while the nomad credit of
    // `docs/01-concept.pdf` is denominated in VAN. So the exact payment the
    // Tier 1 pilot is built around — a human paying in a local asset, offline —
    // passes this check without touching the ceiling.
    //
    // Three ways out, none of them chosen here: denominate the credit per
    // asset; forbid local assets in provisional blocks, which removes the
    // pilot's whole use case; or price local assets into the VAN ceiling via a
    // rate, which needs an oracle and is worse than both. Recorded in
    // spec/draft/04-transactions.md as an open point.
    //
    // This test asserts today's behaviour so that resolving it has to come
    // through here.
    let (mut ledger, key, marie, baker) = village();
    let asset = vanargand_types::id::AssetId::from_hash(Hash::from_bytes([0x77; 32]));

    let mut marie_account = ledger.account(&marie).unwrap().clone();
    marie_account.credit(Some(asset), Amount::from_ulf(1_000_000)).unwrap();
    ledger.put_account(marie, marie_account);

    let ctx = context(FinalityRung::Provisional);
    let huge = TxKind::Transfer {
        to: baker,
        asset: Some(asset),
        amount: Amount::from_ulf(1_000_000),
    };
    let applied = ledger
        .apply(&ctx, &body(marie, &key.verifying, 0, huge))
        .expect("today this is allowed");

    assert_eq!(
        applied.nomad_consumed,
        Amount::from_ulf(10),
        "only the VAN fee counted against the offline ceiling; the token transfer did not"
    );
}

// --------------------------------------------------------------------------
// The partition grammar
// --------------------------------------------------------------------------

#[test]
fn forbidden_kinds_are_refused_in_a_provisional_block() {
    let (mut ledger, key, marie, _) = village();
    let ctx = context(FinalityRung::Provisional);

    let raise = body(
        marie,
        &key.verifying,
        0,
        TxKind::NomadSet { credit: Amount::from_van(1_000).unwrap(), margin: Amount::ZERO },
    );
    assert_eq!(
        ledger.apply(&ctx, &raise),
        Err(StateError::ForbiddenInProvisional { kind: "nomad_set" })
    );

    // And the same transaction is fine once the chain finalises again.
    ledger.apply(&context(FinalityRung::Chain), &raise).expect("legal when online");
}

// --------------------------------------------------------------------------
// Atomicity, nonces, conservation
// --------------------------------------------------------------------------

#[test]
fn a_failed_transaction_changes_nothing() {
    // No "the fee was taken but the transfer bounced" state. A protocol with
    // two kinds of failure has two kinds of bug.
    let (mut ledger, key, marie, baker) = village();
    let ctx = context(FinalityRung::Chain);
    let before = ledger.clone();
    let root_before = ledger.state_root();

    let overdraft = body(marie, &key.verifying, 0, transfer(baker, 1_000_000));
    assert!(matches!(
        ledger.apply(&ctx, &overdraft),
        Err(StateError::InsufficientBalance { .. })
    ));

    assert_eq!(ledger, before, "a failed transaction mutated the ledger");
    assert_eq!(ledger.state_root(), root_before);
    // And it can be retried at the same nonce once the balance allows it.
    ledger
        .apply(&ctx, &body(marie, &key.verifying, 0, transfer(baker, 1)))
        .expect("the nonce must still be free");
}

#[test]
fn a_nonce_cannot_be_replayed() {
    let (mut ledger, key, marie, baker) = village();
    let ctx = context(FinalityRung::Chain);
    let payment = body(marie, &key.verifying, 0, transfer(baker, 100));

    ledger.apply(&ctx, &payment).unwrap();
    assert!(matches!(ledger.apply(&ctx, &payment), Err(StateError::BadNonce { .. })));
    assert_eq!(ledger.account(&baker).unwrap().balance(None), Amount::from_ulf(100));
}

#[test]
fn a_nonce_gap_is_refused() {
    let (mut ledger, key, marie, baker) = village();
    let ctx = context(FinalityRung::Chain);
    assert!(matches!(
        ledger.apply(&ctx, &body(marie, &key.verifying, 5, transfer(baker, 1))),
        Err(StateError::BadNonce { expected: 0, got: 5 })
    ));
}

#[test]
fn a_transaction_for_another_chain_is_refused() {
    let (mut ledger, key, marie, baker) = village();
    let ctx = context(FinalityRung::Chain);
    let mut elsewhere = body(marie, &key.verifying, 0, transfer(baker, 1));
    elsewhere.chain = ChainId::from_hash(Hash::from_bytes([0x99; 32]));
    assert_eq!(ledger.apply(&ctx, &elsewhere), Err(StateError::WrongChain));
}

#[test]
fn a_revoked_device_cannot_sign() {
    let (mut ledger, key, marie, baker) = village();
    let ctx = context(FinalityRung::Chain);

    let revoke = body(
        marie,
        &key.verifying,
        0,
        TxKind::DeviceRevoke { device: DeviceId::of_device_key(&key.verifying) },
    );
    ledger.apply(&ctx, &revoke).unwrap();

    assert_eq!(
        ledger.apply(&ctx, &body(marie, &key.verifying, 1, transfer(baker, 1))),
        Err(StateError::DeviceRevoked(DeviceId::of_device_key(&key.verifying)))
    );
}

#[test]
fn a_revoked_device_can_never_come_back() {
    // Otherwise an attacker who once held a device key waits out the
    // contestation window and has it added again.
    let (mut ledger, key, marie, _) = village();
    let ctx = context(FinalityRung::Chain);
    let device = DeviceId::of_device_key(&key.verifying);

    let second = keypair(9);
    let mut account = ledger.account(&marie).unwrap().clone();
    account.devices.insert(
        DeviceId::of_device_key(&second.verifying),
        Device {
            key: second.verifying.clone(),
            lane: Lane::new(1),
            nomad_share: Amount::ZERO,
            nomad_spent: Amount::ZERO,
        },
    );
    account.next_lane = Lane::new(2);
    ledger.put_account(marie, account);

    ledger
        .apply(&ctx, &body(marie, &key.verifying, 0, TxKind::DeviceRevoke { device }))
        .unwrap();

    let mut readd = body(
        marie,
        &second.verifying,
        0,
        TxKind::DeviceAdd {
            key: key.verifying.clone(),
            lane: Lane::new(2),
            nomad_share: Amount::ZERO,
        },
    );
    readd.nonce = Nonce::new(Lane::new(1), 0);
    assert_eq!(ledger.apply(&ctx, &readd), Err(StateError::DeviceWasRevoked(device)));
}

#[test]
fn a_lane_is_never_reused() {
    // A reused lane would let an old signature and a new one share a slot and
    // look like equivocation by an account that did nothing wrong.
    let (mut ledger, key, marie, _) = village();
    let ctx = context(FinalityRung::Chain);
    let newcomer = keypair(7);

    let reuse = body(
        marie,
        &key.verifying,
        0,
        TxKind::DeviceAdd {
            key: newcomer.verifying.clone(),
            lane: Lane::FIRST,
            nomad_share: Amount::ZERO,
        },
    );
    assert_eq!(ledger.apply(&ctx, &reuse), Err(StateError::LaneAlreadyUsed(Lane::FIRST)));
}

#[test]
fn device_shares_cannot_exceed_the_declared_credit() {
    // Otherwise the sum of what the devices may spend offline would be larger
    // than the number the merchant was shown, which is the only number that
    // makes the whole mechanism worth anything.
    let (mut ledger, key, marie, _) = village();
    let ctx = context(FinalityRung::Chain);
    let newcomer = keypair(8);

    let greedy = body(
        marie,
        &key.verifying,
        0,
        TxKind::DeviceAdd {
            key: newcomer.verifying.clone(),
            lane: Lane::new(1),
            nomad_share: Amount::from_ulf(400),
        },
    );
    assert!(matches!(
        ledger.apply(&ctx, &greedy),
        Err(StateError::NomadOverAllocated { .. })
    ));

    // Within the credit, it is fine: 500 declared, 500 already allocated to the
    // phone, so a second device needs the credit raised first.
    let raise = body(
        marie,
        &key.verifying,
        0,
        TxKind::NomadSet { credit: Amount::from_ulf(900), margin: Amount::ZERO },
    );
    ledger.apply(&ctx, &raise).unwrap();
    let modest = body(
        marie,
        &key.verifying,
        1,
        TxKind::DeviceAdd {
            key: newcomer.verifying,
            lane: Lane::new(1),
            nomad_share: Amount::from_ulf(400),
        },
    );
    ledger.apply(&ctx, &modest).expect("400 + 500 fits under 900");
}

#[test]
fn lowering_the_credit_below_what_is_allocated_is_refused() {
    let (mut ledger, key, marie, _) = village();
    let ctx = context(FinalityRung::Chain);
    let shrink = body(
        marie,
        &key.verifying,
        0,
        TxKind::NomadSet { credit: Amount::from_ulf(100), margin: Amount::ZERO },
    );
    assert!(matches!(
        ledger.apply(&ctx, &shrink),
        Err(StateError::NomadOverAllocated { .. })
    ));
}

#[test]
fn value_is_conserved_except_for_the_fire() {
    // The invariant the whole economy rests on: nothing is created, and the
    // only thing destroyed is the burn share of a fee.
    let (mut ledger, key, marie, baker) = village();
    let ctx = context(FinalityRung::Chain);

    let before = ledger.total_native_balance().unwrap();
    assert_eq!(ledger.burned(), Amount::ZERO);

    for sequence in 0..5 {
        ledger.apply(&ctx, &body(marie, &key.verifying, sequence, transfer(baker, 7))).unwrap();
    }

    let after = ledger.total_native_balance().unwrap();
    let burned = ledger.burned();
    let pot = ledger.context_pot();

    assert_eq!(
        after.checked_add(burned).and_then(|total| total.checked_add(pot)),
        Some(before),
        "value was created or lost: {before} became {after} with {burned} burned and {pot} potted"
    );
    assert!(!burned.is_zero(), "five fees burned nothing");
}

#[test]
fn bonding_moves_value_without_creating_it() {
    let (mut ledger, key, marie, _) = village();
    let ctx = context(FinalityRung::Chain);
    let before = ledger.total_native_balance().unwrap();

    ledger
        .apply(
            &ctx,
            &body(
                marie,
                &key.verifying,
                0,
                TxKind::Bond {
                    amount: Amount::from_ulf(1_000),
                    commitment_root: Hash::from_bytes([0xcc; 32]),
                },
            ),
        )
        .unwrap();

    assert_eq!(ledger.account(&marie).unwrap().bonded, Amount::from_ulf(1_000));
    let after = ledger.total_native_balance().unwrap();
    assert_eq!(
        after.checked_add(ledger.burned()).and_then(|t| t.checked_add(ledger.context_pot())),
        Some(before)
    );

    ledger
        .apply(&ctx, &body(marie, &key.verifying, 1, TxKind::Unbond { amount: Amount::from_ulf(1_000) }))
        .unwrap();
    assert_eq!(ledger.account(&marie).unwrap().bonded, Amount::ZERO);
}

// --------------------------------------------------------------------------
// State root
// --------------------------------------------------------------------------

#[test]
fn the_state_root_changes_with_every_applied_transaction() {
    let (mut ledger, key, marie, baker) = village();
    let ctx = context(FinalityRung::Chain);
    let mut roots = std::collections::BTreeSet::new();
    roots.insert(ledger.state_root());

    for sequence in 0..6 {
        ledger.apply(&ctx, &body(marie, &key.verifying, sequence, transfer(baker, 3))).unwrap();
        assert!(roots.insert(ledger.state_root()), "the root repeated at nonce {sequence}");
    }
}

#[test]
fn an_account_proves_its_balance_against_the_state_root() {
    let (mut ledger, key, marie, baker) = village();
    let ctx = context(FinalityRung::Chain);
    ledger.apply(&ctx, &body(marie, &key.verifying, 0, transfer(baker, 42))).unwrap();

    let root = ledger.state_root();
    let account = ledger.account(&baker).unwrap();
    let proof = ledger.prove_account(&baker);
    assert!(
        proof.verify(&root, baker.as_hash(), Some(&account.value_hash())),
        "an account could not prove its own balance"
    );

    // And an account that does not exist proves that it does not.
    let stranger = account_id(0xcc);
    assert!(ledger.account(&stranger).is_none());
    assert!(ledger.prove_account(&stranger).verify(&root, stranger.as_hash(), None));
}

#[test]
fn the_burn_counter_is_committed_to_by_the_state_root() {
    // A light client can prove how much has been destroyed, which is what makes
    // "toute prime provient de frais déjà payés" checkable rather than
    // asserted.
    let (mut ledger, key, marie, baker) = village();
    let ctx = context(FinalityRung::Chain);
    let before = ledger.state_root();
    ledger.apply(&ctx, &body(marie, &key.verifying, 0, transfer(baker, 1))).unwrap();
    assert_ne!(ledger.state_root(), before);
    assert!(!ledger.burned().is_zero());
}

// --------------------------------------------------------------------------
// Honest limits
// --------------------------------------------------------------------------

#[test]
fn every_defined_kind_is_dispatched() {
    // `StateError::NotImplemented` is a loud placeholder, not a design, and as
    // of now no variant of `TxKind` reaches it. The wildcard arm survives only
    // because the enum is `#[non_exhaustive]`, so a kind added tomorrow still
    // fails safe rather than being silently ignored.
    //
    // Checked through a kind that used to be the placeholder's example.
    let (mut ledger, key, marie, _) = village();
    let ctx = context(FinalityRung::Chain);
    let commit = body(
        marie,
        &key.verifying,
        0,
        TxKind::NameCommit { commitment: Hash::from_bytes([1; 32]) },
    );
    assert_eq!(ledger.apply(&ctx, &commit).map(|applied| applied.nomad_consumed), Ok(Amount::ZERO));
    assert_eq!(ledger.names().commitments().count(), 1);
}
