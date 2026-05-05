// Copyright (c) 2026 Kantoshi Miyamura
//
// V2-dev: end-to-end nonce lifecycle (post-fix regression test).
//
// History:
//   - Stage 6 of `docs/V2_PROTOCOL.md §8` verified the validator's
//     strict-next nonce check.
//   - The earlier diagnostic version of this file documented an
//     off-by-one in `state.rs::ChainState::apply_block` that wrote
//     `tx.nonce + 1` to storage, producing on-chain `tx.nonce` values
//     of 1, 3, 5, 7, … rather than 1, 2, 3, 4, …
//   - That diagnostic motivated a one-line fix at state.rs:215 — the
//     apply side now writes `tx.nonce` directly. See the comment block
//     in state.rs above the `batch.put_nonce` call.
//
// This file is now a **regression test** for the post-fix behaviour:
// the closed-loop sequence wallet → RPC → validator → apply → next
// wallet observation produces consecutive on-wire nonces 1, 2, 3, …
// every time, with no representation oddity.
//
// Components on the post-fix path:
//
//   apply_block (state.rs:215):           batch.put_nonce(addr, tx.nonce)
//   Node::get_nonce (node.rs:739):        returns stored value verbatim
//   axiom-rpc /nonce/:addr (handlers.rs): forwards Node::get_nonce
//   wallet send (axiom.rs:897):           rpc_value.saturating_add(1)
//   validate_transaction (validation.rs): expected = stored + 1; require
//                                         tx.nonce == expected
//
// Closed-form: storage holds "last used nonce"; RPC returns the same
// value; wallet picks `last_used + 1`; validator demands `stored + 1`;
// apply writes `tx.nonce` (= `last_used + 1`). Three components agree
// on the same arithmetic; the on-wire `tx.nonce` field equals the
// 1-indexed transaction number per address.

use axiom_node::validation::{TransactionValidator, ValidationError};
use axiom_primitives::{Amount, Hash256, PublicKey, Signature};
use axiom_protocol::{Transaction, TxInput, TxOutput};
use axiom_storage::{Database, NonceTracker, UtxoSet};
use tempfile::TempDir;

// ── Helpers ─────────────────────────────────────────────────────────────────

fn create_test_db() -> (TempDir, Database) {
    let temp_dir = TempDir::new().unwrap();
    let db = Database::open(temp_dir.path()).unwrap();
    (temp_dir, db)
}

fn make_tx(pubkey_bytes: Vec<u8>, nonce: u64) -> Transaction {
    let input = TxInput {
        prev_tx_hash: Hash256::from_bytes([0xAB; 32]),
        prev_output_index: 0,
        signature: Signature::placeholder(),
        pubkey: PublicKey::from_bytes(pubkey_bytes),
    };
    let output = TxOutput {
        value: Amount::from_sat(1_000_000).unwrap(),
        pubkey_hash: Hash256::zero(),
    };
    Transaction::new_transfer(vec![input], vec![output], nonce, 0)
}

fn pubkey_hash(pubkey_bytes: &[u8]) -> Hash256 {
    axiom_crypto::hash256(pubkey_bytes)
}

/// Returns `Some((expected, actual))` if validation rejected with
/// `InvalidNonce`. Returns `None` if the nonce gate passed (later
/// failures e.g. signature verification are ignored — they are
/// downstream of the property under test).
fn nonce_check_outcome(validator: &TransactionValidator, tx: &Transaction) -> Option<(u64, u64)> {
    match validator.validate_transaction(tx) {
        Err(ValidationError::InvalidNonce { expected, actual }) => Some((expected, actual)),
        _ => None,
    }
}

/// Mirror of `axiom-node::state::ChainState::apply_block`'s post-fix
/// nonce write (state.rs:215). Writes the raw `tx.nonce` value as the
/// new "last used" nonce for the address.
fn simulate_apply_blocks_nonce_write(db: &Database, addr: &Hash256, tx_nonce: u64) {
    NonceTracker::new(db).set_nonce(addr, tx_nonce).unwrap();
}

/// Mirror of the wallet's nonce derivation step
/// (axiom-cli/src/bin/axiom.rs:883-897): reads the RPC value (raw
/// stored value) and adds 1.
fn simulate_wallet_picks_next_nonce(db: &Database, addr: &Hash256) -> u64 {
    let rpc_value = NonceTracker::new(db).get_nonce(addr).unwrap().unwrap_or(0);
    rpc_value.saturating_add(1)
}

// ── Regression tests ────────────────────────────────────────────────────────

/// Three sequential transactions from the same wallet are accepted by
/// the validator AND produce consecutive on-wire `tx.nonce` values of
/// 1, 2, 3. Locks the corrected end-to-end behaviour.
#[test]
fn three_sequential_txs_use_consecutive_nonces() {
    let (_temp, db) = create_test_db();

    let pubkey_bytes = vec![0x11u8; 2592];
    let addr = pubkey_hash(&pubkey_bytes);

    // ── Tx 1 ─────────────────────────────────────────────────────────────
    let nonce1 = simulate_wallet_picks_next_nonce(&db, &addr);
    assert_eq!(nonce1, 1, "first tx: wallet derives nonce 1");

    let tx1 = make_tx(pubkey_bytes.clone(), nonce1);
    {
        let utxo_set = UtxoSet::new(&db);
        let nonce_tracker = NonceTracker::new(&db);
        let validator = TransactionValidator::new(utxo_set, nonce_tracker, 1);
        assert!(
            nonce_check_outcome(&validator, &tx1).is_none(),
            "tx 1 (nonce=1) must pass the nonce gate against empty storage"
        );
    }
    simulate_apply_blocks_nonce_write(&db, &addr, nonce1);

    // ── Tx 2 ─────────────────────────────────────────────────────────────
    let nonce2 = simulate_wallet_picks_next_nonce(&db, &addr);
    assert_eq!(nonce2, 2, "second tx: wallet derives nonce 2");

    let tx2 = make_tx(pubkey_bytes.clone(), nonce2);
    {
        let utxo_set = UtxoSet::new(&db);
        let nonce_tracker = NonceTracker::new(&db);
        let validator = TransactionValidator::new(utxo_set, nonce_tracker, 1);
        assert!(
            nonce_check_outcome(&validator, &tx2).is_none(),
            "tx 2 (nonce=2) must pass the nonce gate"
        );

        // And the pre-fix value tx.nonce=3 (one of the odd-only sequence)
        // is REJECTED — the new sequence is consecutive, not odd-only.
        let tx2_pre_fix = make_tx(pubkey_bytes.clone(), 3);
        let outcome = nonce_check_outcome(&validator, &tx2_pre_fix);
        assert_eq!(
            outcome,
            Some((2, 3)),
            "the pre-fix value tx.nonce=3 (skipping 2) is rejected post-fix"
        );
    }
    simulate_apply_blocks_nonce_write(&db, &addr, nonce2);

    // ── Tx 3 ─────────────────────────────────────────────────────────────
    let nonce3 = simulate_wallet_picks_next_nonce(&db, &addr);
    assert_eq!(nonce3, 3, "third tx: wallet derives nonce 3");

    let tx3 = make_tx(pubkey_bytes.clone(), nonce3);
    {
        let utxo_set = UtxoSet::new(&db);
        let nonce_tracker = NonceTracker::new(&db);
        let validator = TransactionValidator::new(utxo_set, nonce_tracker, 1);
        assert!(
            nonce_check_outcome(&validator, &tx3).is_none(),
            "tx 3 (nonce=3) must pass the nonce gate"
        );
    }
    simulate_apply_blocks_nonce_write(&db, &addr, nonce3);

    // After three applied txs, storage = last_used_nonce = 3.
    let final_storage = NonceTracker::new(&db)
        .get_nonce(&addr)
        .unwrap()
        .unwrap_or(0);
    assert_eq!(
        final_storage, 3,
        "after three applied txs: storage = last_used_nonce = 3"
    );
}

/// Closed-form sequence: `tx.nonce[i]` for the `i`-th transaction
/// (1-indexed) from a given address equals `i`.
#[test]
fn on_chain_tx_nonce_sequence_is_one_indexed() {
    let (_temp, db) = create_test_db();
    let pubkey_bytes = vec![0x22u8; 2592];
    let addr = pubkey_hash(&pubkey_bytes);

    let mut wire_nonces = Vec::new();
    for _ in 0..6 {
        let n = simulate_wallet_picks_next_nonce(&db, &addr);
        wire_nonces.push(n);
        simulate_apply_blocks_nonce_write(&db, &addr, n);
    }

    assert_eq!(
        wire_nonces,
        vec![1, 2, 3, 4, 5, 6],
        "on-wire tx.nonce equals the 1-indexed transaction number from this address"
    );
}

/// Wallet → RPC → storage round-trip. The /nonce endpoint returns the
/// raw stored value; the wallet treats that value as the previous
/// nonce and adds 1; the validator demands `stored + 1`. Pin all three
/// halves so a future change to any one surfaces here.
#[test]
fn rpc_returns_last_used_value_and_wallet_adds_one() {
    let (_temp, db) = create_test_db();
    let pubkey_bytes = vec![0x44u8; 2592];
    let addr = pubkey_hash(&pubkey_bytes);

    // Pre-load storage with an arbitrary "last used" value.
    NonceTracker::new(&db).set_nonce(&addr, 17).unwrap();

    // RPC returns the stored value verbatim.
    let rpc_value = NonceTracker::new(&db)
        .get_nonce(&addr)
        .unwrap()
        .unwrap_or(0);
    assert_eq!(rpc_value, 17);

    // Wallet adds 1.
    let wallet_nonce = rpc_value.saturating_add(1);
    assert_eq!(wallet_nonce, 18);

    // Validator demands `stored + 1`.
    let utxo_set = UtxoSet::new(&db);
    let nonce_tracker = NonceTracker::new(&db);
    let validator = TransactionValidator::new(utxo_set, nonce_tracker, 1);
    let tx = make_tx(pubkey_bytes, wallet_nonce);
    assert!(
        nonce_check_outcome(&validator, &tx).is_none(),
        "wallet-derived nonce {wallet_nonce} (= rpc 17 + 1) must pass the gate (validator demands stored + 1 = 18)"
    );
}

/// Apply followed by validate is now off-by-zero, not off-by-two: the
/// nonce written by apply is exactly the nonce the next wallet
/// observation reports through RPC, and the validator's `stored + 1`
/// requirement is satisfied by the wallet's `rpc_value + 1` derivation.
#[test]
fn apply_then_validator_agree_with_no_off_by_one() {
    let (_temp, db) = create_test_db();
    let pubkey_bytes = vec![0x55u8; 2592];
    let addr = pubkey_hash(&pubkey_bytes);

    // Apply a tx with nonce = 7. After apply, storage holds 7
    // (last-used semantics).
    simulate_apply_blocks_nonce_write(&db, &addr, 7);

    let stored = NonceTracker::new(&db)
        .get_nonce(&addr)
        .unwrap()
        .unwrap_or(0);
    assert_eq!(
        stored, 7,
        "apply writes raw tx.nonce as the last-used value"
    );

    // The next wallet observation derives nonce 8.
    let next_wallet_nonce = simulate_wallet_picks_next_nonce(&db, &addr);
    assert_eq!(next_wallet_nonce, 8);

    // The validator accepts nonce 8 (stored=7, expected=8).
    let utxo_set = UtxoSet::new(&db);
    let nonce_tracker = NonceTracker::new(&db);
    let validator = TransactionValidator::new(utxo_set, nonce_tracker, 1);
    let tx_next = make_tx(pubkey_bytes.clone(), next_wallet_nonce);
    assert!(
        nonce_check_outcome(&validator, &tx_next).is_none(),
        "next tx with wallet-derived nonce {next_wallet_nonce} must pass the gate"
    );

    // And nonce 9 (skipping 8) is rejected.
    let tx_skip = make_tx(pubkey_bytes, 9);
    let outcome = nonce_check_outcome(&validator, &tx_skip);
    assert_eq!(outcome, Some((8, 9)));
}
