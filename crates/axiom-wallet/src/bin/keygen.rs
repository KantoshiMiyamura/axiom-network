// Copyright (c) 2026 Kantoshi Miyamura
//
// keygen — generate a new Axiom Network wallet and print credentials.
//
// Usage: cargo run -p axiom-wallet --bin keygen

use axiom_wallet::{derive_account, generate_seed_phrase, Address};

fn main() {
    let (phrase, master_seed) = generate_seed_phrase();
    let keypair = derive_account(&master_seed, 0).expect("key derivation failure");
    let address = Address::from_pubkey_hash(keypair.public_key_hash());

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║              AXIOM NETWORK — NEW WALLET                      ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  WRITE DOWN YOUR SEED PHRASE. IT IS THE ONLY BACKUP.        ║");
    println!("║  Never share it. Never store it digitally.                   ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("Seed phrase:");
    println!("  {}", phrase);
    println!();
    println!("Address (use as --miner-address):");
    println!("  {}", address);
    println!();
    println!("Private key (hex — keep secret):");
    println!("  {}", hex::encode(keypair.export_private_key()));
    println!();
    println!("Public key (hex):");
    println!("  {}", hex::encode(keypair.public_key()));
    println!();
    println!("Pubkey hash (hex — raw address payload):");
    println!("  {}", hex::encode(keypair.public_key_hash().as_bytes()));
    println!();
}
