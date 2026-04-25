// Copyright (c) 2026 Kantoshi Miyamura
//
// Axiom Mining CLI — connects to a running axiom-node via RPC.
//
// Commands:
//   init     — Generate an encrypted wallet keystore
//   start    — Connect to node and begin mining
//   status   — Query the node for current mining status
//   balance  — Check miner wallet balance

use std::io::{self, Write};
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    let rpc_url = get_rpc_url(&args);

    match args[1].as_str() {
        "init" => cmd_init(),
        "start" => cmd_start(&rpc_url),
        "status" => cmd_status(&rpc_url),
        "balance" => {
            if args.len() < 3 {
                eprintln!("Usage: mining balance <address> [--rpc URL]");
                std::process::exit(1);
            }
            cmd_balance(&rpc_url, &args[2]);
        }
        "help" | "--help" | "-h" => print_usage(),
        other => {
            eprintln!("Unknown command: {}", other);
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    println!("Axiom Mining CLI");
    println!();
    println!("Usage: mining <command> [options]");
    println!();
    println!("Commands:");
    println!("  init                    Generate encrypted wallet keystore");
    println!("  start [--rpc URL]       Connect to node and start mining");
    println!("  status [--rpc URL]      Query node for current status");
    println!("  balance <addr> [--rpc]  Check wallet balance");
    println!();
    println!("Options:");
    println!("  --rpc URL    Node RPC endpoint (default: http://127.0.0.1:8332)");
}

fn get_rpc_url(args: &[String]) -> String {
    for (i, arg) in args.iter().enumerate() {
        if arg == "--rpc" {
            if let Some(url) = args.get(i + 1) {
                return url.clone();
            }
        }
    }
    "http://127.0.0.1:8332".to_string()
}

fn keystore_dir() -> PathBuf {
    dirs_next::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("axiom")
        .join("keystore")
}

fn cmd_init() {
    println!("Generating new Axiom wallet...\n");

    // Generate keypair
    let keypair = match axiom_wallet::KeyPair::generate() {
        Ok(kp) => kp,
        Err(e) => {
            eprintln!("Failed to generate keypair: {}", e);
            std::process::exit(1);
        }
    };

    let address = {
        let pubkey_hash = keypair.public_key_hash();
        axiom_wallet::Address::from_pubkey_hash(pubkey_hash).to_string()
    };

    // Prompt for password
    let password = loop {
        print!("Enter keystore password (min 8 chars): ");
        io::stdout().flush().unwrap();
        let mut pw = String::new();
        io::stdin().read_line(&mut pw).unwrap();
        let pw = pw.trim().to_string();

        if pw.len() < 8 {
            println!("Password too short. Minimum 8 characters.");
            continue;
        }

        print!("Confirm password: ");
        io::stdout().flush().unwrap();
        let mut confirm = String::new();
        io::stdin().read_line(&mut confirm).unwrap();

        if pw != confirm.trim() {
            println!("Passwords do not match. Try again.");
            continue;
        }

        break pw;
    };

    // Create keystore
    let keystore =
        match axiom_wallet::keystore::create_keystore(keypair.export_private_key(), &password) {
            Ok(ks) => ks,
            Err(e) => {
                eprintln!("Failed to create keystore: {}", e);
                std::process::exit(1);
            }
        };

    // Save keystore to file
    let dir = keystore_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("Failed to create keystore directory: {}", e);
        std::process::exit(1);
    }

    let filename = format!("axm-{}.json", &address[3..11]);
    let filepath = dir.join(&filename);

    let json = serde_json::to_string_pretty(&keystore).unwrap();
    if let Err(e) = std::fs::write(&filepath, &json) {
        eprintln!("Failed to write keystore: {}", e);
        std::process::exit(1);
    }

    println!("  Address:  {}", address);
    println!("  Keystore: {}", filepath.display());
    println!("  Encrypted with Argon2id + XChaCha20-Poly1305");
    println!("\nDone. Keep your password safe — it cannot be recovered.");
}

fn cmd_start(rpc_url: &str) {
    println!("Connecting to node at {}...\n", rpc_url);

    // Check node health first
    let health_url = format!("{}/health", rpc_url);
    match reqwest::blocking::get(&health_url) {
        Ok(resp) if resp.status().is_success() => {
            println!("  Node: connected");
        }
        Ok(resp) => {
            eprintln!("  Node returned status {}", resp.status());
            eprintln!("  Make sure axiom-node is running at {}", rpc_url);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("  Failed to connect to node: {}", e);
            eprintln!("  Make sure axiom-node is running at {}", rpc_url);
            std::process::exit(1);
        }
    }

    // Get current status
    let status_url = format!("{}/status", rpc_url);
    match reqwest::blocking::get(&status_url) {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.json::<serde_json::Value>() {
                println!(
                    "  Chain height: {}",
                    body.get("height").unwrap_or(&serde_json::Value::Null)
                );
                println!(
                    "  Best block:   {}",
                    body.get("best_block_hash")
                        .unwrap_or(&serde_json::Value::Null)
                );
            }
        }
        _ => {
            println!("  Could not fetch node status");
        }
    }

    println!("\nMining requires a running axiom-node with mining enabled.");
    println!("Submit work via POST {}/submit_transaction", rpc_url);
    println!("\nTo mine continuously, run: axiom-node --mine --rpc-port 8332");
}

fn cmd_status(rpc_url: &str) {
    println!("Querying node at {}...\n", rpc_url);

    // Node status
    let status_url = format!("{}/status", rpc_url);
    match reqwest::blocking::get(&status_url) {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.json::<serde_json::Value>() {
                println!("[NODE]");
                println!(
                    "  Height:     {}",
                    body.get("height").unwrap_or(&serde_json::Value::Null)
                );
                println!(
                    "  Best block: {}",
                    body.get("best_block_hash")
                        .unwrap_or(&serde_json::Value::Null)
                );
                println!(
                    "  Chain work: {}",
                    body.get("chain_work").unwrap_or(&serde_json::Value::Null)
                );
                println!();
            }
        }
        Ok(resp) => {
            eprintln!("Node returned status {}", resp.status());
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to connect: {}", e);
            eprintln!("Make sure axiom-node is running at {}", rpc_url);
            std::process::exit(1);
        }
    }

    // Metrics
    let metrics_url = format!("{}/metrics", rpc_url);
    if let Ok(resp) = reqwest::blocking::get(&metrics_url) {
        if resp.status().is_success() {
            if let Ok(body) = resp.json::<serde_json::Value>() {
                println!("[METRICS]");
                if let Some(mempool) = body.get("mempool_size") {
                    println!("  Mempool:    {} txs", mempool);
                }
                if let Some(peers) = body.get("peer_count") {
                    println!("  Peers:      {}", peers);
                }
                if let Some(orphans) = body.get("orphan_count") {
                    println!("  Orphans:    {}", orphans);
                }
                println!();
            }
        }
    }

    // Hashrate
    let hashrate_url = format!("{}/network/hashrate", rpc_url);
    if let Ok(resp) = reqwest::blocking::get(&hashrate_url) {
        if resp.status().is_success() {
            if let Ok(body) = resp.json::<serde_json::Value>() {
                println!("[NETWORK]");
                if let Some(hr) = body.get("hashrate") {
                    println!("  Hashrate:   {}", hr);
                }
                if let Some(diff) = body.get("difficulty") {
                    println!("  Difficulty: {}", diff);
                }
                println!();
            }
        }
    }
}

fn cmd_balance(rpc_url: &str, address: &str) {
    let url = format!("{}/balance/{}", rpc_url, address);
    match reqwest::blocking::get(&url) {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.json::<serde_json::Value>() {
                println!("Address: {}", address);
                println!(
                    "Balance: {} satoshis",
                    body.get("balance").unwrap_or(&serde_json::Value::Null)
                );
            }
        }
        Ok(resp) => {
            eprintln!("Node returned status {}", resp.status());
        }
        Err(e) => {
            eprintln!("Failed to connect: {}", e);
            eprintln!("Make sure axiom-node is running at {}", rpc_url);
            std::process::exit(1);
        }
    }
}
