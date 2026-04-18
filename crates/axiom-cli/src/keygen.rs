// Copyright (c) 2026 Kantoshi Miyamura

//! Generate and persist an ML-DSA-87 wallet keypair with encrypted storage.
//! Private keys are encrypted using Argon2id + XChaCha20-Poly1305 (never stored in plaintext).

use axiom_wallet::{create_keystore, Address, KeyPair};
use clap::Parser;
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Parser, Debug)]
#[command(name = "axiom-keygen")]
#[command(about = "Generate an Axiom Network ML-DSA-87 wallet keypair (encrypted)")]
struct Args {
    /// Output file for encrypted keystore (JSON)
    #[arg(long, default_value = "wallet.keystore.json")]
    out: PathBuf,

    /// Overwrite output file if it already exists
    #[arg(long)]
    force: bool,
}

/// Read a password without echoing to the terminal.
/// Falls back to a clearly-labelled visible read only when no TTY is attached
/// (e.g. piped input in CI). Returned `String` is zeroized by caller.
fn read_password_silent(prompt: &str) -> std::io::Result<String> {
    match rpassword::prompt_password(prompt) {
        Ok(s) => Ok(s),
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("failed to read password: {}", e),
        )),
    }
}

fn main() {
    let args = Args::parse();

    if args.out.exists() && !args.force {
        eprintln!(
            "error: '{}' already exists — use --force to overwrite",
            args.out.display()
        );
        std::process::exit(1);
    }

    // Generate keypair — OS CSPRNG (OsRng from rand_core, backed by getrandom).
    let keypair = KeyPair::generate().expect("failed to generate keypair");

    // Derive public metadata up-front; avoid keeping extra copies of the private key.
    let public_key_hex = hex::encode(keypair.public_key());
    let pubkey_hash = keypair.public_key_hash();
    let address = Address::from_pubkey_hash(pubkey_hash);
    let address_str = address.to_string();
    let pubkey_hash_hex = hex::encode(pubkey_hash.as_bytes());

    // Get password for encryption — no echo, twice for confirmation.
    let mut password = read_password_silent("Enter password to encrypt wallet: ").unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });
    if password.len() < 8 {
        password.zeroize();
        eprintln!("error: password must be at least 8 characters");
        std::process::exit(1);
    }
    let mut confirm = read_password_silent("Confirm password: ").unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });
    if password != confirm {
        password.zeroize();
        confirm.zeroize();
        eprintln!("error: passwords do not match");
        std::process::exit(1);
    }
    confirm.zeroize();

    // Encrypt private key with Argon2id + XChaCha20-Poly1305.
    // `export_private_key()` returns a borrow into the KeyPair's Zeroizing buffer —
    // no intermediate plaintext copy escapes this function.
    let keystore = create_keystore(keypair.export_private_key(), &password).unwrap_or_else(|e| {
        password.zeroize();
        eprintln!("error: failed to encrypt keystore: {}", e);
        std::process::exit(1);
    });
    password.zeroize();

    // Build output with encrypted keystore + public metadata.
    let wallet = serde_json::json!({
        "keystore": keystore,
        "public_key_hex":  public_key_hex,
        "pubkey_hash_hex": pubkey_hash_hex,
        "address":         address_str,
        "encryption": "argon2id + xchacha20-poly1305",
        "note": "Private key is encrypted. You need your password to use this wallet."
    });

    let json = serde_json::to_string_pretty(&wallet).unwrap();
    std::fs::write(&args.out, &json).unwrap_or_else(|e| {
        eprintln!("error: failed to write '{}': {}", args.out.display(), e);
        std::process::exit(1);
    });

    // Best-effort: restrict file to owner read/write on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&args.out, std::fs::Permissions::from_mode(0o600));
    }

    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║        Axiom Network — Encrypted Wallet Generated         ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Address:      {}", address_str);
    println!("  Pubkey hash:  {}", pubkey_hash_hex);
    println!("  Encryption:   Argon2id + XChaCha20-Poly1305");
    println!();
    println!("  Wallet saved → {}", args.out.display());
    println!();
    println!("  Private key is ENCRYPTED — you need your password to unlock it.");
    println!();
    println!("  To start mining with this address:");
    println!("    axiom-node --mine --miner-address {}", address_str);
}
