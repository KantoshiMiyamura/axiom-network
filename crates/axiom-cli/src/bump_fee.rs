// Copyright (c) 2026 Kantoshi Miyamura

//! Replace a stuck mempool transaction with a higher-fee version (RBF).
//!
//! Reduces the user-identified change output by an explicit extra-fee amount
//! and re-signs all inputs with the correct chain_id. Refuses to run unless
//!
//!   1. the wallet file is an encrypted keystore and unlocks with the password,
//!   2. the chain_id matches the node's chain_id (queried from `/status` or
//!      provided via `--chain-id`),
//!   3. the identified change output belongs to the wallet's own pubkey_hash,
//!   4. the reduced output stays above dust.
//!
//! Never accepts passwords on the command line.

use axiom_primitives::{Amount, Hash256};
use axiom_protocol::serialize_transaction;
use axiom_wallet::{unlock_keystore, Address, KeyPair, KeystoreFile, TransactionBuilder};
use clap::Parser;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Minimum allowed value for any output after fee reduction. Outputs below this
/// are treated as dust and rejected.
pub const DUST_THRESHOLD_SAT: u64 = 546;

#[derive(Parser, Debug)]
#[command(name = "axiom-bump-fee")]
#[command(about = "Replace a stuck transaction with a higher-fee version (RBF)")]
struct Args {
    /// Transaction ID of the stuck transaction to replace (64 hex chars)
    #[arg(long)]
    txid: String,

    /// Extra fee to add, in satoshis. This is subtracted from the change output.
    /// Fee rate is intentionally not accepted here because the tool cannot reliably
    /// compute the original fee rate from the /tx endpoint alone.
    #[arg(long)]
    extra_fee_sat: u64,

    /// Path to wallet keystore file (JSON produced by axiom-keygen)
    #[arg(long, default_value = "wallet.keystore.json")]
    wallet: String,

    /// Index of the change output to reduce. Defaults to the last output.
    /// MUST be an output paying back to this wallet's own pubkey_hash.
    #[arg(long)]
    change_index: Option<usize>,

    /// Chain ID to sign with. If omitted, queried from the node's /status endpoint.
    #[arg(long)]
    chain_id: Option<String>,

    /// RPC URL of the node to query
    #[arg(long, default_value = "http://127.0.0.1:8332")]
    rpc_url: String,

    /// Skip the final confirmation prompt (for scripting).
    #[arg(long)]
    yes: bool,
}

#[derive(Debug, Deserialize)]
struct TxInputDetail {
    pub prev_tx_hash: String,
    pub prev_output_index: u32,
}

#[derive(Debug, Deserialize)]
struct TxOutputDetail {
    pub value: u64,
    pub pubkey_hash: String,
}

#[derive(Debug, Deserialize)]
struct TransactionDetail {
    pub nonce: u64,
    pub locktime: u32,
    pub inputs: Vec<TxInputDetail>,
    pub outputs: Vec<TxOutputDetail>,
    #[serde(default)]
    pub memo: Option<String>,
    #[serde(default)]
    pub tx_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NodeStatus {
    #[serde(default)]
    pub chain_id: Option<String>,
    #[serde(default)]
    pub network: Option<String>,
}

#[derive(Debug, Serialize)]
struct SubmitTransactionRequest {
    transaction_hex: String,
}

#[derive(Debug, Deserialize)]
struct SubmitTransactionResponse {
    txid: String,
}

/// Wallet JSON as written by axiom-keygen: encrypted keystore + public metadata.
#[derive(Debug, Deserialize)]
struct WalletFile {
    pub keystore: KeystoreFile,
    #[serde(default)]
    pub pubkey_hash_hex: Option<String>,
    #[serde(default)]
    pub address: Option<String>,
}

/// Identify the change output index (defaulting to the last) and verify it
/// belongs to this wallet's `own_pubkey_hash`. Reject any other choice so the
/// fee bump can never silently reduce a destination payment.
pub fn resolve_change_index(
    outputs: &[(u64, [u8; 32])],
    own_pubkey_hash: &[u8; 32],
    explicit: Option<usize>,
) -> Result<usize, String> {
    if outputs.is_empty() {
        return Err("transaction has no outputs".into());
    }
    let idx = explicit.unwrap_or(outputs.len() - 1);
    if idx >= outputs.len() {
        return Err(format!(
            "change_index {} is out of range (tx has {} outputs)",
            idx,
            outputs.len()
        ));
    }
    if &outputs[idx].1 != own_pubkey_hash {
        return Err(format!(
            "output at index {} does not pay to this wallet's pubkey_hash — \
             refusing to reduce a destination output. Use --change-index to \
             specify the correct change output, or confirm this transaction \
             actually has a change output owned by this wallet.",
            idx
        ));
    }
    Ok(idx)
}

/// Reduce output at `change_index` by `extra_fee_sat`. Rejects:
///  * zero extra fee (no-op),
///  * reduction that would push the output below dust.
pub fn compute_bumped_outputs(
    output_values: &[u64],
    change_index: usize,
    extra_fee_sat: u64,
) -> Result<Vec<u64>, String> {
    if extra_fee_sat == 0 {
        return Err("extra_fee_sat must be > 0".into());
    }
    if output_values.is_empty() {
        return Err("transaction has no outputs".into());
    }
    if change_index >= output_values.len() {
        return Err(format!(
            "change_index {} out of range ({} outputs)",
            change_index,
            output_values.len()
        ));
    }
    let mut new_values = output_values.to_vec();
    let current = new_values[change_index];
    let reduced = current
        .checked_sub(extra_fee_sat)
        .ok_or_else(|| format!(
            "change output {} sat is smaller than extra fee {} sat",
            current, extra_fee_sat
        ))?;
    if reduced < DUST_THRESHOLD_SAT && reduced != 0 {
        return Err(format!(
            "reduced change ({} sat) would be below dust threshold {} sat",
            reduced, DUST_THRESHOLD_SAT
        ));
    }
    new_values[change_index] = reduced;
    Ok(new_values)
}

fn decode_hash32(name: &str, hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("bad {} '{}': {}", name, hex_str, e))?;
    if bytes.len() != 32 {
        return Err(format!("{} must be 32 bytes, got {}", name, bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn abort<T: std::fmt::Display>(msg: T) -> ! {
    eprintln!("error: {}", msg);
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // --- Load and unlock wallet ---------------------------------------------
    let wallet_json = std::fs::read_to_string(&args.wallet)
        .unwrap_or_else(|e| abort(format!("cannot read wallet '{}': {}", args.wallet, e)));
    let wallet: WalletFile = serde_json::from_str(&wallet_json).unwrap_or_else(|e| {
        abort(format!(
            "wallet file must be an encrypted keystore produced by axiom-keygen \
             (missing 'keystore' field?): {}",
            e
        ))
    });

    let mut password = rpassword::prompt_password("Wallet password: ")
        .unwrap_or_else(|e| abort(format!("failed to read password: {}", e)));
    let priv_key_bytes = match unlock_keystore(&wallet.keystore, &password) {
        Ok(b) => b,
        Err(e) => {
            password.zeroize();
            abort(format!("could not unlock keystore: {}", e));
        }
    };
    password.zeroize();

    let keypair = KeyPair::from_private_key(priv_key_bytes.to_vec())
        .unwrap_or_else(|e| abort(format!("failed to load keypair: {}", e)));

    let own_pubkey_hash: [u8; 32] = *keypair.public_key_hash().as_bytes();

    // Cross-check against the address metadata in the wallet file, if present.
    // This catches accidental keystore/metadata mismatch before we sign anything.
    if let Some(meta_hash_hex) = wallet.pubkey_hash_hex.as_deref() {
        let expected = decode_hash32("pubkey_hash_hex", meta_hash_hex)
            .unwrap_or_else(|e| abort(e));
        if expected != own_pubkey_hash {
            abort(
                "wallet metadata pubkey_hash_hex does not match the key unlocked \
                 from the keystore — refusing to sign",
            );
        }
    }
    if let Some(addr_str) = wallet.address.as_deref() {
        if let Ok(addr) = Address::from_string(addr_str) {
            if addr.pubkey_hash().as_bytes() != &own_pubkey_hash {
                abort(
                    "wallet metadata address does not match the unlocked key — \
                     refusing to sign",
                );
            }
        }
    }

    // --- HTTP client --------------------------------------------------------
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|e| abort(format!("failed to build HTTP client: {}", e)));
    let rpc_base = args.rpc_url.trim_end_matches('/').to_string();

    // --- Resolve chain_id ---------------------------------------------------
    let chain_id = if let Some(ref cid) = args.chain_id {
        cid.clone()
    } else {
        let status_url = format!("{}/status", rpc_base);
        let resp = client
            .get(&status_url)
            .send()
            .await
            .unwrap_or_else(|e| abort(format!("failed to query {}: {}", status_url, e)));
        if !resp.status().is_success() {
            abort(format!(
                "cannot auto-detect chain_id — /status returned {} (use --chain-id)",
                resp.status()
            ));
        }
        let s: NodeStatus = resp
            .json()
            .await
            .unwrap_or_else(|e| abort(format!("invalid /status response: {}", e)));
        s.chain_id
            .or(s.network)
            .unwrap_or_else(|| abort("node /status provided no chain_id or network — use --chain-id"))
    };

    // --- Fetch original transaction -----------------------------------------
    let tx_url = format!("{}/tx/{}", rpc_base, args.txid);
    let resp = client
        .get(&tx_url)
        .send()
        .await
        .unwrap_or_else(|e| abort(format!("RPC request failed: {}", e)));
    if !resp.status().is_success() {
        abort(format!(
            "node returned status {} for GET {}",
            resp.status(),
            tx_url
        ));
    }
    let tx_detail: TransactionDetail = resp
        .json()
        .await
        .unwrap_or_else(|e| abort(format!("failed to parse transaction response: {}", e)));

    if let Some(ref t) = tx_detail.tx_type {
        if t != "transfer" {
            abort(format!(
                "only 'transfer' transactions can be bumped by this tool; got '{}'",
                t
            ));
        }
    }
    if tx_detail.inputs.is_empty() {
        abort("transaction has no inputs");
    }
    if tx_detail.outputs.len() < 2 {
        abort(
            "transaction has fewer than 2 outputs — cannot bump fee without a \
             dedicated change output (would reduce the destination instead)",
        );
    }

    // --- Parse inputs and outputs -------------------------------------------
    let inputs: Vec<([u8; 32], u32)> = tx_detail
        .inputs
        .iter()
        .map(|inp| {
            let h = decode_hash32("prev_tx_hash", &inp.prev_tx_hash).unwrap_or_else(|e| abort(e));
            (h, inp.prev_output_index)
        })
        .collect();

    let outputs: Vec<(u64, [u8; 32])> = tx_detail
        .outputs
        .iter()
        .map(|o| {
            let ph = decode_hash32("pubkey_hash", &o.pubkey_hash).unwrap_or_else(|e| abort(e));
            (o.value, ph)
        })
        .collect();

    let change_index = resolve_change_index(&outputs, &own_pubkey_hash, args.change_index)
        .unwrap_or_else(|e| abort(e));

    let output_values: Vec<u64> = outputs.iter().map(|(v, _)| *v).collect();
    let new_values = compute_bumped_outputs(&output_values, change_index, args.extra_fee_sat)
        .unwrap_or_else(|e| abort(e));

    // --- Confirmation --------------------------------------------------------
    println!();
    println!("Replacing transaction: {}", args.txid);
    println!("Chain ID:            {}", chain_id);
    println!("Change output index: {}", change_index);
    println!(
        "Change: {} sat → {} sat  (fee +{} sat)",
        output_values[change_index], new_values[change_index], args.extra_fee_sat
    );
    println!();
    if !args.yes {
        eprint!("Proceed? [y/N] ");
        use std::io::Write;
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .unwrap_or_else(|e| abort(format!("failed to read confirmation: {}", e)));
        let ans = line.trim().to_ascii_lowercase();
        if ans != "y" && ans != "yes" {
            abort("aborted by user");
        }
    }

    // --- Build and sign the replacement transaction --------------------------
    let mut builder = TransactionBuilder::new()
        .nonce(tx_detail.nonce)
        .locktime(tx_detail.locktime)
        .chain_id(chain_id.clone())
        .keypair(keypair);

    for (hash, idx) in &inputs {
        builder = builder.add_input(Hash256::from_bytes(*hash), *idx);
    }
    for (i, (_, ph)) in outputs.iter().enumerate() {
        let amount = Amount::from_sat(new_values[i])
            .unwrap_or_else(|e| abort(format!("invalid new output amount: {}", e)));
        builder = builder.add_output(amount, Hash256::from_bytes(*ph));
    }
    if let Some(memo) = tx_detail.memo.as_deref() {
        if !memo.is_empty() {
            builder = builder.memo(memo);
        }
    }

    let replacement_tx = builder
        .build()
        .unwrap_or_else(|e| abort(format!("failed to build replacement transaction: {}", e)));

    // --- Submit --------------------------------------------------------------
    let tx_bytes = serialize_transaction(&replacement_tx);
    let tx_hex = hex::encode(&tx_bytes);
    let submit_url = format!("{}/submit_transaction", rpc_base);
    let submit_resp = client
        .post(&submit_url)
        .json(&SubmitTransactionRequest { transaction_hex: tx_hex })
        .send()
        .await
        .unwrap_or_else(|e| abort(format!("failed to submit replacement tx: {}", e)));
    if !submit_resp.status().is_success() {
        let status = submit_resp.status();
        let body = submit_resp.text().await.unwrap_or_default();
        abort(format!("node rejected replacement transaction ({}): {}", status, body));
    }
    let submit_result: SubmitTransactionResponse = submit_resp
        .json()
        .await
        .unwrap_or_else(|e| abort(format!("failed to parse submit response: {}", e)));

    println!("Replacement transaction submitted: {}", submit_result.txid);
    println!(
        "Change output {} reduced from {} to {} sat (extra fee {} sat)",
        change_index, output_values[change_index], new_values[change_index], args.extra_fee_sat
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn own_hash() -> [u8; 32] {
        [7u8; 32]
    }
    fn other_hash() -> [u8; 32] {
        [9u8; 32]
    }

    #[test]
    fn resolve_change_defaults_to_last_when_owned() {
        let outs = vec![(1_000, other_hash()), (2_000, own_hash())];
        assert_eq!(resolve_change_index(&outs, &own_hash(), None).unwrap(), 1);
    }

    #[test]
    fn resolve_change_rejects_non_owned_last() {
        let outs = vec![(1_000, own_hash()), (2_000, other_hash())];
        assert!(resolve_change_index(&outs, &own_hash(), None).is_err());
    }

    #[test]
    fn resolve_change_explicit_index_must_be_owned() {
        let outs = vec![(1_000, own_hash()), (2_000, other_hash())];
        assert_eq!(resolve_change_index(&outs, &own_hash(), Some(0)).unwrap(), 0);
        assert!(resolve_change_index(&outs, &own_hash(), Some(1)).is_err());
    }

    #[test]
    fn resolve_change_out_of_range() {
        let outs = vec![(1_000, own_hash())];
        assert!(resolve_change_index(&outs, &own_hash(), Some(5)).is_err());
    }

    #[test]
    fn resolve_change_empty_outputs() {
        assert!(resolve_change_index(&[], &own_hash(), None).is_err());
    }

    #[test]
    fn bump_subtracts_from_change() {
        let new_vals = compute_bumped_outputs(&[10_000, 5_000], 1, 800).unwrap();
        assert_eq!(new_vals, vec![10_000, 4_200]);
    }

    #[test]
    fn bump_rejects_zero_extra_fee() {
        assert!(compute_bumped_outputs(&[10_000, 5_000], 1, 0).is_err());
    }

    #[test]
    fn bump_rejects_underflow() {
        assert!(compute_bumped_outputs(&[10_000, 500], 1, 1_000).is_err());
    }

    #[test]
    fn bump_rejects_dust() {
        // 1000 - 900 = 100 < DUST_THRESHOLD_SAT — must reject
        assert!(compute_bumped_outputs(&[10_000, 1_000], 1, 900).is_err());
    }

    #[test]
    fn bump_allows_exactly_zero_change() {
        // Dropping change to 0 is treated as "no change" and is allowed.
        let new_vals = compute_bumped_outputs(&[10_000, 500], 1, 500).unwrap();
        assert_eq!(new_vals[1], 0);
    }

    #[test]
    fn bump_allows_threshold_value() {
        // Reduction that leaves exactly DUST_THRESHOLD_SAT is allowed.
        let new_vals =
            compute_bumped_outputs(&[10_000, 1_000], 1, 1_000 - DUST_THRESHOLD_SAT).unwrap();
        assert_eq!(new_vals[1], DUST_THRESHOLD_SAT);
    }

    #[test]
    fn bump_does_not_touch_non_change_outputs() {
        let new_vals = compute_bumped_outputs(&[50_000, 10_000, 20_000], 2, 5_000).unwrap();
        assert_eq!(new_vals[0], 50_000);
        assert_eq!(new_vals[1], 10_000);
        assert_eq!(new_vals[2], 15_000);
    }

    #[test]
    fn bump_empty_outputs_rejected() {
        assert!(compute_bumped_outputs(&[], 0, 100).is_err());
    }

    #[test]
    fn bump_out_of_range_index_rejected() {
        assert!(compute_bumped_outputs(&[1_000], 5, 100).is_err());
    }
}
