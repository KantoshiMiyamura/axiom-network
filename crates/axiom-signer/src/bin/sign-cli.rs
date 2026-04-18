// Copyright (c) 2026 Kantoshi Miyamura
//
// axiom-sign: Command-line tool for local transaction signing
// Designed to be called from Python via subprocess
//
// Usage:
//   axiom-sign address <key_hex>
//   axiom-sign sign <key_hex> <tx_hash_hex>
//   axiom-sign verify <pubkey_hex> <tx_hash_hex> <sig_hex>

use axiom_signer::LocalSigner;
use axiom_wallet::signing::SignatureBackend;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: axiom-sign <command> [args...]");
        eprintln!("Commands:");
        eprintln!("  address <key_hex>                  - Derive address from private key");
        eprintln!("  sign <key_hex> <tx_hash_hex>       - Sign transaction");
        eprintln!("  verify <pk_hex> <tx_hash> <sig>    - Verify signature");
        std::process::exit(1);
    }

    let command = &args[1];

    match command.as_str() {
        "address" => cmd_address(&args),
        "sign" => cmd_sign(&args),
        "verify" => cmd_verify(&args),
        _ => {
            eprintln!("Unknown command: {}", command);
            std::process::exit(1);
        }
    }
}

/// Derive address from private key
fn cmd_address(args: &[String]) {
    if args.len() < 3 {
        eprintln!("Usage: axiom-sign address <key_hex>");
        std::process::exit(1);
    }

    let key_hex = &args[2];

    // Parse hex to bytes
    let key_bytes = match hex::decode(key_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: Invalid hex: {}", e);
            std::process::exit(1);
        }
    };

    // Create signer
    let signer = match LocalSigner::from_seed_bytes(&key_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    };

    // Derive address
    match signer.address() {
        Ok(addr) => println!("{}", addr),
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Sign a transaction
fn cmd_sign(args: &[String]) {
    if args.len() < 4 {
        eprintln!("Usage: axiom-sign sign <key_hex> <tx_hash_hex>");
        std::process::exit(1);
    }

    let key_hex = &args[2];
    let tx_hash_hex = &args[3];

    // Parse keys
    let key_bytes = match hex::decode(key_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: Invalid key hex: {}", e);
            std::process::exit(1);
        }
    };

    let tx_hash = match hex::decode(tx_hash_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: Invalid tx_hash hex: {}", e);
            std::process::exit(1);
        }
    };

    // Create signer
    let signer = match LocalSigner::from_seed_bytes(&key_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    };

    // Sign transaction
    match signer.sign_transaction(&tx_hash) {
        Ok(sig) => println!("{}", hex::encode(sig)),
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Verify a signature
fn cmd_verify(args: &[String]) {
    if args.len() < 5 {
        eprintln!("Usage: axiom-sign verify <pubkey_hex> <tx_hash_hex> <sig_hex>");
        std::process::exit(1);
    }

    let pk_hex = &args[2];
    let tx_hash_hex = &args[3];
    let sig_hex = &args[4];

    let pk_bytes = match hex::decode(pk_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: Invalid pubkey hex: {}", e);
            std::process::exit(1);
        }
    };

    let tx_hash = match hex::decode(tx_hash_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: Invalid tx_hash hex: {}", e);
            std::process::exit(1);
        }
    };

    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: Invalid signature hex: {}", e);
            std::process::exit(1);
        }
    };

    // Verify using axiom_wallet's ML-DSA-87 backend
    match axiom_wallet::signing::MlDsa87Backend.verify(&pk_bytes, &tx_hash, &sig_bytes) {
        Ok(()) => println!("valid"),
        Err(_) => {
            println!("invalid");
            std::process::exit(1);
        }
    }
}
