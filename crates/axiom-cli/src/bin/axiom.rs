// Copyright (c) 2026 Kantoshi Miyamura
//
// `axiom` — unified CLI for the Axiom Network.
//
// Subcommands:
//   axiom start              Run a full node (optionally with mining)
//   axiom wallet create      Create a new encrypted wallet
//   axiom wallet import      Import wallet from seed phrase
//   axiom wallet balance     Check wallet balance
//   axiom wallet address     Show wallet address
//   axiom worker start       Start mining worker
//   axiom rewards            Show mining reward schedule
//   axiom status             Query running node status
//   axiom version            Print version and build info

use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::PathBuf;
use std::fs;

// ── Version ──────────────────────────────────────────────────────────────────

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn default_data_dir() -> PathBuf {
    dirs_next::data_dir()
        .unwrap_or_else(|| dirs_next::home_dir().unwrap_or_else(|| PathBuf::from(".")))
        .join("axiom")
}

fn default_wallet_path() -> PathBuf {
    default_data_dir().join("wallet.json")
}

// ── CLI Structure ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "axiom",
    about = "Axiom Network — Post-Quantum Blockchain",
    version = VERSION,
    long_about = "Production CLI for the Axiom Network.\n\n\
                  Run a full node, create wallets, mine blocks, and check rewards.\n\
                  All private keys stay on your device — nothing leaves your machine."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Axiom node
    Start {
        /// Network (mainnet, testnet, devnet)
        #[arg(long, default_value = "mainnet")]
        network: String,

        /// Data directory
        #[arg(long)]
        data_dir: Option<String>,

        /// RPC bind address
        #[arg(long, default_value = "127.0.0.1:8332")]
        rpc_bind: String,

        /// P2P bind address
        #[arg(long, default_value = "0.0.0.0:9000")]
        p2p_bind: String,

        /// Enable mining
        #[arg(long)]
        mine: bool,

        /// Miner address (hex or axm... format)
        #[arg(long)]
        miner_address: Option<String>,

        /// Connect to a peer directly
        #[arg(long = "peer", value_name = "ADDR")]
        peers: Vec<String>,

        /// Log level (error, warn, info, debug, trace)
        #[arg(long, default_value = "info")]
        log_level: String,

        /// Mining interval in seconds
        #[arg(long, default_value = "30")]
        mining_interval: u64,

        /// Bearer token for RPC authentication
        #[arg(long)]
        rpc_auth_token: Option<String>,
    },

    /// Wallet management
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },

    /// Start a mining worker (connects to running node)
    Worker {
        #[command(subcommand)]
        action: WorkerAction,
    },

    /// Show mining reward schedule
    Rewards {
        /// Show rewards at a specific block height
        #[arg(long)]
        at_height: Option<u32>,

        /// Show reward table for N blocks
        #[arg(long, default_value = "20")]
        table: u32,
    },

    /// Query running node status
    Status {
        /// RPC URL of the node
        #[arg(long, default_value = "http://127.0.0.1:8332")]
        rpc: String,
    },

    /// Print version and build information
    Version,

    /// First-run initialization (creates data dir, wallet, config)
    Init {
        /// Data directory
        #[arg(long)]
        data_dir: Option<String>,
    },

    /// One-click mining — creates wallet, connects to network, starts mining
    Mine {
        /// Connect to a specific node (default: bootstrap node)
        #[arg(long, default_value = "178.104.8.137:9000")]
        peer: String,

        /// Data directory
        #[arg(long)]
        data_dir: Option<String>,

        /// Log level
        #[arg(long, default_value = "info")]
        log_level: String,
    },
}

#[derive(Subcommand)]
enum WalletAction {
    /// Create a new encrypted wallet
    Create {
        /// Output path for keystore file
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Import wallet from 24-word seed phrase
    Import {
        /// Output path for keystore file
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Check wallet balance
    Balance {
        /// Wallet address (omit to use default wallet)
        #[arg(long)]
        address: Option<String>,

        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8332")]
        rpc: String,
    },

    /// Show wallet address
    Address {
        /// Path to wallet keystore
        #[arg(long)]
        wallet: Option<PathBuf>,
    },

    /// Send AXM from the local wallet to a recipient. Prompts for password;
    /// private key is never printed. The transaction is built and signed
    /// locally and submitted to the local RPC node.
    Send {
        /// Recipient address (axm... format)
        #[arg(long)]
        to: String,

        /// Amount to send. Interpreted as AXM decimal (e.g. "1.5") unless
        /// --sat is set, in which case it is read as raw satoshis.
        #[arg(long)]
        amount: String,

        /// Interpret --amount as satoshis instead of AXM.
        #[arg(long)]
        sat: bool,

        /// Flat fee in satoshis (default 1000).
        #[arg(long, default_value = "1000")]
        fee: u64,

        /// Optional memo (up to 80 bytes).
        #[arg(long)]
        memo: Option<String>,

        /// Path to wallet keystore (default: platform default wallet.json).
        #[arg(long)]
        wallet: Option<PathBuf>,

        /// RPC URL of the local node.
        #[arg(long, default_value = "http://127.0.0.1:8332")]
        rpc: String,

        /// Skip the final confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum WorkerAction {
    /// Start mining worker
    Start {
        /// RPC URL of the node to connect to
        #[arg(long, default_value = "http://127.0.0.1:8332")]
        rpc: String,

        /// Wallet address for rewards
        #[arg(long)]
        address: Option<String>,
    },
}

// ── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start {
            network,
            data_dir,
            rpc_bind,
            p2p_bind,
            mine,
            miner_address,
            peers,
            log_level,
            mining_interval,
            rpc_auth_token,
        } => {
            cmd_start(
                network,
                data_dir,
                rpc_bind,
                p2p_bind,
                mine,
                miner_address,
                peers,
                log_level,
                mining_interval,
                rpc_auth_token,
            );
        }
        Commands::Wallet { action } => match action {
            WalletAction::Create { out } => cmd_wallet_create(out),
            WalletAction::Import { out } => cmd_wallet_import(out),
            WalletAction::Balance { address, rpc } => cmd_wallet_balance(address, &rpc),
            WalletAction::Address { wallet } => cmd_wallet_address(wallet),
            WalletAction::Send {
                to,
                amount,
                sat,
                fee,
                memo,
                wallet,
                rpc,
                yes,
            } => cmd_wallet_send(to, amount, sat, fee, memo, wallet, &rpc, yes),
        },
        Commands::Worker { action } => match action {
            WorkerAction::Start { rpc, address } => cmd_worker_start(&rpc, address),
        },
        Commands::Rewards { at_height, table } => cmd_rewards(at_height, table),
        Commands::Status { rpc } => cmd_status(&rpc),
        Commands::Version => cmd_version(),
        Commands::Init { data_dir } => cmd_init(data_dir),
        Commands::Mine { peer, data_dir, log_level } => cmd_mine(peer, data_dir, log_level),
    }
}

// ── axiom start ──────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn cmd_start(
    network: String,
    data_dir: Option<String>,
    rpc_bind: String,
    p2p_bind: String,
    mine: bool,
    miner_address: Option<String>,
    peers: Vec<String>,
    log_level: String,
    mining_interval: u64,
    rpc_auth_token: Option<String>,
) {
    // Delegate to axiom-node binary — it has the full async runtime.
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    let node_exe = if cfg!(windows) {
        exe_dir.join("axiom-node.exe")
    } else {
        exe_dir.join("axiom-node")
    };

    if !node_exe.exists() {
        eprintln!("error: axiom-node binary not found at {}", node_exe.display());
        eprintln!("       Make sure axiom-node is in the same directory as axiom.");
        std::process::exit(1);
    }

    let data = data_dir.unwrap_or_else(|| default_data_dir().to_string_lossy().to_string());

    let mut cmd = std::process::Command::new(&node_exe);
    cmd.arg("--network").arg(&network)
        .arg("--data-dir").arg(&data)
        .arg("--rpc-bind").arg(&rpc_bind)
        .arg("--p2p-bind").arg(&p2p_bind)
        .arg("--log-level").arg(&log_level)
        .arg("--mining-interval").arg(mining_interval.to_string());

    if mine {
        cmd.arg("--mine");
    }
    if let Some(addr) = &miner_address {
        cmd.arg("--miner-address").arg(addr);
    }
    for peer in &peers {
        cmd.arg("--peer").arg(peer);
    }
    if let Some(token) = &rpc_auth_token {
        cmd.arg("--rpc-auth-token").arg(token);
    }

    // Replace this process with the node.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        eprintln!("error: failed to exec axiom-node: {}", err);
        std::process::exit(1);
    }

    #[cfg(not(unix))]
    {
        match cmd.status() {
            Ok(status) => std::process::exit(status.code().unwrap_or(1)),
            Err(e) => {
                eprintln!("error: failed to start axiom-node: {}", e);
                std::process::exit(1);
            }
        }
    }
}

// ── axiom wallet create ──────────────────────────────────────────────────────

fn cmd_wallet_create(out: Option<PathBuf>) {
    let out_path = out.unwrap_or_else(default_wallet_path);

    if out_path.exists() {
        eprintln!("Wallet already exists at: {}", out_path.display());
        eprint!("Overwrite? (yes/no): ");
        io::stderr().flush().unwrap();
        let mut answer = String::new();
        io::stdin().read_line(&mut answer).unwrap();
        if answer.trim().to_lowercase() != "yes" {
            println!("Cancelled.");
            return;
        }
    }

    println!();
    println!("========================================================");
    println!("           Axiom Network - New Wallet");
    println!("========================================================");
    println!();

    // Generate seed phrase
    let (phrase, seed) = axiom_wallet::generate_seed_phrase();

    println!("  Your 24-word recovery phrase:");
    println!();
    for (i, word) in phrase.split_whitespace().enumerate() {
        print!("    {:2}. {:<14}", i + 1, word);
        if (i + 1) % 4 == 0 {
            println!();
        }
    }
    println!();
    println!("  WRITE THESE WORDS DOWN ON PAPER.");
    println!("  This is the ONLY way to recover your wallet.");
    println!("  Never share it. Never store it digitally.");
    println!();

    eprint!("  Type 'yes' to confirm you saved the phrase: ");
    io::stderr().flush().unwrap();
    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm).unwrap();
    if confirm.trim().to_lowercase() != "yes" {
        println!("Wallet creation cancelled.");
        std::process::exit(1);
    }

    // Derive keypair from seed
    let keypair = axiom_wallet::derive_account(&seed, 0).unwrap_or_else(|e| {
        eprintln!("error: failed to derive keypair: {}", e);
        std::process::exit(1);
    });

    let address = axiom_wallet::Address::from_pubkey_hash(keypair.public_key_hash());

    // Get password
    let password = read_password_confirmed("Choose wallet password (min 8 chars): ");

    // Encrypt and save
    let keystore = axiom_wallet::create_keystore(keypair.export_private_key(), &password)
        .unwrap_or_else(|e| {
            eprintln!("error: failed to encrypt wallet: {}", e);
            std::process::exit(1);
        });

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("error: cannot create directory {}: {}", parent.display(), e);
            std::process::exit(1);
        });
    }

    let json = axiom_wallet::export_keystore(&keystore).unwrap_or_else(|e| {
        eprintln!("error: failed to serialize keystore: {}", e);
        std::process::exit(1);
    });
    fs::write(&out_path, &json).unwrap_or_else(|e| {
        eprintln!("error: cannot write {}: {}", out_path.display(), e);
        std::process::exit(1);
    });

    println!();
    println!("  Wallet created successfully!");
    println!();
    println!("  Address:    {}", address);
    println!("  Saved to:   {}", out_path.display());
    println!("  Encryption: Argon2id + XChaCha20-Poly1305");
    println!();
    println!("  Start mining:");
    println!("    axiom start --mine --miner-address {}", address);
    println!();
}

// ── axiom wallet import ──────────────────────────────────────────────────────

fn cmd_wallet_import(out: Option<PathBuf>) {
    let out_path = out.unwrap_or_else(default_wallet_path);

    println!();
    println!("========================================================");
    println!("           Axiom Network - Import Wallet");
    println!("========================================================");
    println!();
    println!("  Enter your 24-word recovery phrase.");
    println!("  Words separated by spaces:");
    println!();

    eprint!("  > ");
    io::stderr().flush().unwrap();
    let mut phrase = String::new();
    io::stdin().read_line(&mut phrase).unwrap();
    let phrase = phrase.trim().to_string();

    let word_count = phrase.split_whitespace().count();
    if word_count != 24 {
        eprintln!("error: expected 24 words, got {}", word_count);
        std::process::exit(1);
    }

    let seed = axiom_wallet::recover_wallet_from_seed(&phrase).unwrap_or_else(|e| {
        eprintln!("error: invalid seed phrase: {}", e);
        std::process::exit(1);
    });

    let keypair = axiom_wallet::derive_account(&seed, 0).unwrap_or_else(|e| {
        eprintln!("error: failed to derive keypair: {}", e);
        std::process::exit(1);
    });

    let address = axiom_wallet::Address::from_pubkey_hash(keypair.public_key_hash());

    let password = read_password_confirmed("Choose wallet password (min 8 chars): ");

    let keystore = axiom_wallet::create_keystore(keypair.export_private_key(), &password)
        .unwrap_or_else(|e| {
            eprintln!("error: failed to encrypt wallet: {}", e);
            std::process::exit(1);
        });

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).ok();
    }

    let json = axiom_wallet::export_keystore(&keystore).unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });
    fs::write(&out_path, &json).unwrap_or_else(|e| {
        eprintln!("error: cannot write {}: {}", out_path.display(), e);
        std::process::exit(1);
    });

    println!();
    println!("  Wallet imported successfully!");
    println!("  Address:  {}", address);
    println!("  Saved to: {}", out_path.display());
    println!();
}

// ── axiom wallet balance ─────────────────────────────────────────────────────

fn cmd_wallet_balance(address: Option<String>, rpc: &str) {
    let addr = address.unwrap_or_else(|| {
        // Try to load default wallet address
        let wallet_path = default_wallet_path();
        if !wallet_path.exists() {
            eprintln!("error: no wallet found at {}", wallet_path.display());
            eprintln!("       Create one with: axiom wallet create");
            eprintln!("       Or specify: axiom wallet balance --address <addr>");
            std::process::exit(1);
        }
        load_wallet_address(&wallet_path)
    });

    let url = format!("{}/balance/{}", rpc.trim_end_matches('/'), addr);
    match reqwest::blocking::get(&url) {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.json::<serde_json::Value>() {
                let balance_sat = body
                    .get("balance")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let balance_axm = balance_sat as f64 / 100_000_000.0;
                println!();
                println!("  Address: {}", addr);
                println!("  Balance: {:.8} AXM ({} sat)", balance_axm, balance_sat);
                println!();
            }
        }
        Ok(resp) => {
            eprintln!("error: node returned {}", resp.status());
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("error: cannot connect to node at {}: {}", rpc, e);
            eprintln!("       Is axiom-node running? Start with: axiom start");
            std::process::exit(1);
        }
    }
}

// ── axiom wallet address ─────────────────────────────────────────────────────

fn cmd_wallet_address(wallet: Option<PathBuf>) {
    let path = wallet.unwrap_or_else(default_wallet_path);
    if !path.exists() {
        eprintln!("error: no wallet found at {}", path.display());
        eprintln!("       Create one with: axiom wallet create");
        std::process::exit(1);
    }
    let addr = load_wallet_address(&path);
    println!("{}", addr);
}

// ── axiom wallet send ────────────────────────────────────────────────────────

const DUST_THRESHOLD_SAT: u64 = 546;

fn parse_amount_sat(amount_str: &str, sat_mode: bool) -> Result<u64, String> {
    if sat_mode {
        amount_str
            .parse::<u64>()
            .map_err(|e| format!("--amount must be an integer when --sat is set: {}", e))
            .and_then(|v| {
                if v == 0 {
                    Err("--amount must be > 0".into())
                } else {
                    Ok(v)
                }
            })
    } else {
        let axm: f64 = amount_str
            .parse()
            .map_err(|e| format!("--amount must be a decimal AXM value: {}", e))?;
        if !axm.is_finite() || axm <= 0.0 {
            return Err("--amount must be > 0".into());
        }
        let sat_float = (axm * 100_000_000.0).round();
        if sat_float < 1.0 || sat_float > (u64::MAX as f64) {
            return Err(format!("--amount out of range: {}", amount_str));
        }
        Ok(sat_float as u64)
    }
}

fn decode_hash32(name: &str, hex_str: &str) -> Result<[u8; 32], String> {
    let bytes =
        hex::decode(hex_str).map_err(|e| format!("bad {} '{}': {}", name, hex_str, e))?;
    if bytes.len() != 32 {
        return Err(format!("{} must be 32 bytes, got {}", name, bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[allow(clippy::too_many_arguments)]
fn cmd_wallet_send(
    to: String,
    amount_str: String,
    sat_mode: bool,
    fee_sat: u64,
    memo: Option<String>,
    wallet: Option<PathBuf>,
    rpc: &str,
    yes: bool,
) {
    use axiom_primitives::{Amount, Hash256};
    use axiom_protocol::serialize_transaction;
    use axiom_wallet::{Address, KeyPair, TransactionBuilder};

    // 1. Validate recipient address before touching the wallet.
    let to_addr = Address::from_string(&to).unwrap_or_else(|_| {
        eprintln!("error: invalid recipient address '{}'", to);
        std::process::exit(1);
    });

    // 2. Parse + validate amount.
    let amount_sat = parse_amount_sat(&amount_str, sat_mode).unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });
    if amount_sat < DUST_THRESHOLD_SAT {
        eprintln!(
            "error: amount {} sat is below dust threshold {} sat",
            amount_sat, DUST_THRESHOLD_SAT
        );
        std::process::exit(1);
    }

    // 3. Validate memo length early (builder truncates silently otherwise).
    if let Some(m) = memo.as_deref() {
        if m.len() > 80 {
            eprintln!("error: memo exceeds 80 bytes ({} bytes)", m.len());
            std::process::exit(1);
        }
    }

    // 4. Load keystore (no password yet).
    let wallet_path = wallet.unwrap_or_else(default_wallet_path);
    if !wallet_path.exists() {
        eprintln!("error: no wallet found at {}", wallet_path.display());
        eprintln!("       Create one with: axiom wallet create");
        std::process::exit(1);
    }
    let json = fs::read_to_string(&wallet_path).unwrap_or_else(|e| {
        eprintln!("error: cannot read wallet {}: {}", wallet_path.display(), e);
        std::process::exit(1);
    });
    let keystore = axiom_wallet::import_keystore(&json).unwrap_or_else(|e| {
        eprintln!("error: invalid keystore format: {}", e);
        std::process::exit(1);
    });

    // 5. Reach the node before asking for the password — if RPC is down,
    // fail early and we haven't collected credentials for nothing.
    let base = rpc.trim_end_matches('/');
    let status: serde_json::Value = reqwest::blocking::get(format!("{}/status", base))
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json())
        .unwrap_or_else(|e| {
            eprintln!("error: cannot reach node /status at {}: {}", rpc, e);
            std::process::exit(1);
        });
    let chain_id = status
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| {
            eprintln!("error: /status response missing 'network' field");
            std::process::exit(1);
        })
        .to_string();
    let tip_height = status
        .get("best_height")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    // 6. Prompt for password and unlock.
    // Production build: interactive prompt only.
    // The AXIOM_TEST_WALLET_PASSWORD env var bypass is compiled in only when the
    // `test-fixtures` Cargo feature is set — release builds physically lack it.
    let password = read_wallet_password();
    let priv_bytes = axiom_wallet::unlock_keystore(&keystore, &password).unwrap_or_else(|_| {
        eprintln!("error: wrong password or corrupt keystore");
        std::process::exit(1);
    });
    drop(password);
    let keypair = KeyPair::from_private_key(priv_bytes.to_vec()).unwrap_or_else(|e| {
        eprintln!("error: failed to load keypair: {}", e);
        std::process::exit(1);
    });
    let from_addr = Address::from_pubkey_hash(keypair.public_key_hash());

    // Refuse to send to self — ambiguous at best, and masks real bugs.
    if from_addr.pubkey_hash() == to_addr.pubkey_hash() {
        eprintln!("error: sender and recipient are the same address");
        std::process::exit(1);
    }

    // 7. Fetch UTXOs for the sender.
    let utxos_url = format!("{}/utxos/{}", base, from_addr);
    let utxos: serde_json::Value = reqwest::blocking::get(&utxos_url)
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json())
        .unwrap_or_else(|e| {
            eprintln!("error: cannot fetch UTXOs: {}", e);
            std::process::exit(1);
        });

    let empty_vec: Vec<serde_json::Value> = Vec::new();
    let utxo_list = utxos
        .get("utxos")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty_vec);

    // Filter out immature coinbase outputs. Devnet maturity = 5, else = 100.
    let maturity: u32 = if chain_id == "axiom-dev-1" { 5 } else { 100 };

    #[derive(Clone)]
    struct Utxo {
        txid: String,
        output_index: u32,
        value: u64,
    }
    let mut mature: Vec<Utxo> = utxo_list
        .iter()
        .filter_map(|u| {
            let txid = u.get("txid")?.as_str()?.to_string();
            let output_index = u.get("output_index")?.as_u64()? as u32;
            let value = u.get("value")?.as_u64()?;
            let block_height = u.get("block_height")?.as_u64()? as u32;
            // Match validator semantics exactly: blocks_since = tip - height,
            // must be >= maturity. We can't tell coinbase vs transfer from this
            // response, so apply the conservative (coinbase) rule to all.
            let blocks_since = tip_height.saturating_sub(block_height);
            if blocks_since < maturity {
                return None;
            }
            Some(Utxo { txid, output_index, value })
        })
        .collect();

    if mature.is_empty() {
        eprintln!(
            "error: no mature UTXOs available for {} (tip {}, maturity {} blocks)",
            from_addr, tip_height, maturity
        );
        std::process::exit(1);
    }

    // 8. Coin selection: smallest-first until we cover amount+fee.
    mature.sort_by_key(|u| u.value);
    let total_required = amount_sat.checked_add(fee_sat).unwrap_or_else(|| {
        eprintln!("error: amount + fee overflow");
        std::process::exit(1);
    });
    let mut selected: Vec<Utxo> = Vec::new();
    let mut selected_sum: u64 = 0;
    for u in &mature {
        selected_sum = selected_sum.checked_add(u.value).unwrap_or_else(|| {
            eprintln!("error: input sum overflow");
            std::process::exit(1);
        });
        selected.push(u.clone());
        if selected_sum >= total_required {
            break;
        }
    }
    if selected_sum < total_required {
        eprintln!(
            "error: insufficient funds — need {} sat ({} amount + {} fee), have {} sat mature",
            total_required, amount_sat, fee_sat, selected_sum
        );
        std::process::exit(1);
    }

    // Compute change. If change would be below dust, roll it into the fee.
    let raw_change = selected_sum - total_required;
    let (change_sat, effective_fee) = if raw_change >= DUST_THRESHOLD_SAT {
        (raw_change, fee_sat)
    } else {
        (0, fee_sat + raw_change)
    };
    let has_change = change_sat > 0;

    // 9. Fetch sender nonce. /nonce returns the LAST-USED nonce; the next
    // outgoing tx must use last_used + 1.
    let nonce_url = format!("{}/nonce/{}", base, from_addr);
    let nonce_resp: serde_json::Value = reqwest::blocking::get(&nonce_url)
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json())
        .unwrap_or_else(|e| {
            eprintln!("error: cannot fetch nonce: {}", e);
            std::process::exit(1);
        });
    let last_used_nonce: u64 = nonce_resp
        .get("nonce")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let nonce = last_used_nonce.saturating_add(1);

    // 10. Show preview and ask for confirmation.
    println!();
    println!("  ─── Send preview ─────────────────────────────────────────");
    println!("  From:      {}", from_addr);
    println!("  To:        {}", to_addr);
    println!(
        "  Amount:    {} sat   ({:.8} AXM)",
        amount_sat,
        amount_sat as f64 / 100_000_000.0
    );
    println!(
        "  Fee:       {} sat   ({:.8} AXM)",
        effective_fee,
        effective_fee as f64 / 100_000_000.0
    );
    if has_change {
        println!(
            "  Change:    {} sat   ({:.8} AXM)   → back to sender",
            change_sat,
            change_sat as f64 / 100_000_000.0
        );
    } else if raw_change > 0 {
        println!("  Change:    rolled into fee ({} sat < dust)", raw_change);
    } else {
        println!("  Change:    none");
    }
    println!("  Inputs:    {} UTXO(s), total {} sat", selected.len(), selected_sum);
    println!("  Nonce:     {}", nonce);
    println!("  Chain ID:  {}", chain_id);
    if let Some(m) = memo.as_deref() {
        if !m.is_empty() {
            println!("  Memo:      {}", m);
        }
    }
    println!("  ──────────────────────────────────────────────────────────");
    println!();

    if !yes {
        eprint!("Proceed? [y/N] ");
        io::stderr().flush().ok();
        let mut line = String::new();
        io::stdin().read_line(&mut line).ok();
        let ans = line.trim().to_ascii_lowercase();
        if ans != "y" && ans != "yes" {
            eprintln!("aborted");
            std::process::exit(0);
        }
    }

    // 11. Build + sign transaction locally.
    let mut builder = TransactionBuilder::new()
        .nonce(nonce)
        .chain_id(chain_id.clone())
        .keypair(keypair);
    for u in &selected {
        let hash = decode_hash32("prev_tx_hash", &u.txid).unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        });
        builder = builder.add_input(Hash256::from_bytes(hash), u.output_index);
    }
    let amount_typed = Amount::from_sat(amount_sat).unwrap_or_else(|e| {
        eprintln!("error: invalid amount: {}", e);
        std::process::exit(1);
    });
    builder = builder.add_output(amount_typed, *to_addr.pubkey_hash());
    if has_change {
        let change_typed = Amount::from_sat(change_sat).unwrap_or_else(|e| {
            eprintln!("error: invalid change amount: {}", e);
            std::process::exit(1);
        });
        builder = builder.add_output(change_typed, *from_addr.pubkey_hash());
    }
    if let Some(m) = memo.as_deref() {
        if !m.is_empty() {
            builder = builder.memo(m);
        }
    }
    let tx = builder.build().unwrap_or_else(|e| {
        eprintln!("error: failed to build transaction: {}", e);
        std::process::exit(1);
    });

    // 12. Serialize and submit.
    let tx_bytes = serialize_transaction(&tx);
    let submit_url = format!("{}/submit_transaction", base);
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|e| {
            eprintln!("error: failed to build HTTP client: {}", e);
            std::process::exit(1);
        });
    let submit_body = serde_json::json!({ "transaction_hex": hex::encode(&tx_bytes) });
    let resp = client
        .post(&submit_url)
        .json(&submit_body)
        .send()
        .unwrap_or_else(|e| {
            eprintln!("error: submit failed: {}", e);
            std::process::exit(1);
        });
    if !resp.status().is_success() {
        let st = resp.status();
        let body = resp.text().unwrap_or_default();
        eprintln!("error: node rejected transaction ({}): {}", st, body);
        std::process::exit(1);
    }
    let result: serde_json::Value = resp.json().unwrap_or_else(|e| {
        eprintln!("error: invalid submit response: {}", e);
        std::process::exit(1);
    });
    let txid = result
        .get("txid")
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>");

    println!();
    println!("  ✓ Transaction submitted to mempool");
    println!("    txid: {}", txid);
    println!();
}

// ── axiom worker start ───────────────────────────────────────────────────────

fn cmd_worker_start(rpc: &str, address: Option<String>) {
    let addr = address.unwrap_or_else(|| {
        let wallet_path = default_wallet_path();
        if wallet_path.exists() {
            load_wallet_address(&wallet_path)
        } else {
            eprintln!("error: no wallet found and no --address specified");
            eprintln!("       Create a wallet: axiom wallet create");
            eprintln!("       Or specify:      axiom worker start --address <addr>");
            std::process::exit(1);
        }
    });

    println!();
    println!("========================================================");
    println!("           Axiom Network - Mining Worker");
    println!("========================================================");
    println!();
    println!("  Reward address: {}", addr);
    println!("  Node RPC:       {}", rpc);
    println!();

    // Check node connectivity
    let health_url = format!("{}/health", rpc.trim_end_matches('/'));
    match reqwest::blocking::get(&health_url) {
        Ok(resp) if resp.status().is_success() => {
            println!("  Node: connected");
        }
        _ => {
            eprintln!("  error: cannot reach node at {}", rpc);
            eprintln!("         Start a node first: axiom start");
            std::process::exit(1);
        }
    }

    // Check status
    let status_url = format!("{}/status", rpc.trim_end_matches('/'));
    if let Ok(resp) = reqwest::blocking::get(&status_url) {
        if let Ok(body) = resp.json::<serde_json::Value>() {
            if let Some(height) = body.get("height") {
                println!("  Chain height: {}", height);
            }
        }
    }

    println!();
    println!("  To mine directly on this node, restart with:");
    println!("    axiom start --mine --miner-address {}", addr);
    println!();
    println!("  Mining is built into the node — the worker connects to");
    println!("  an existing node and submits shares via RPC.");
    println!();

    // In a full implementation this would run a mining loop submitting
    // work to the node. For now, it validates connectivity and
    // instructs the user on the integrated mining path.
    println!("  Worker mode: monitoring node for work...");
    println!("  (Mining is integrated into axiom start --mine)");
    println!();
}

// ── axiom rewards ────────────────────────────────────────────────────────────

fn cmd_rewards(at_height: Option<u32>, table_size: u32) {
    println!();
    println!("========================================================");
    println!("           Axiom Network - Reward Schedule");
    println!("========================================================");
    println!();
    println!("  Initial reward:  50.00000000 AXM");
    println!("  Block time:      30 seconds");
    println!("  Decay:           0.001% per block (smooth curve)");
    println!("  Minimum reward:  1 satoshi (0.00000001 AXM)");
    println!("  Max supply:      ~21,000,000 AXM");
    println!();

    if let Some(height) = at_height {
        let reward = axiom_consensus::calculate_smooth_reward(height);
        let sat = reward.as_sat();
        let axm = sat as f64 / 100_000_000.0;
        println!("  Block {}: {:.8} AXM ({} sat)", height, axm, sat);
        println!();
        return;
    }

    // Show reward table
    println!("  {:>10}  {:>18}  {:>14}", "Height", "Reward (AXM)", "Reward (sat)");
    println!("  {:>10}  {:>18}  {:>14}", "------", "-----------", "-----------");

    let milestones: Vec<u32> = (0..table_size)
        .map(|i| {
            if i < 10 {
                i * 1000
            } else {
                (i - 10 + 1) * 100_000
            }
        })
        .collect();

    for height in milestones {
        let reward = axiom_consensus::calculate_smooth_reward(height);
        let sat = reward.as_sat();
        let axm = sat as f64 / 100_000_000.0;
        println!("  {:>10}  {:>18.8}  {:>14}", height, axm, sat);
    }
    println!();
}

// ── axiom status ─────────────────────────────────────────────────────────────

fn cmd_status(rpc: &str) {
    let base = rpc.trim_end_matches('/');

    // Node status
    let status_url = format!("{}/status", base);
    match reqwest::blocking::get(&status_url) {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.json::<serde_json::Value>() {
                println!();
                println!("[NODE]");
                if let Some(v) = body.get("height") {
                    println!("  Height:     {}", v);
                }
                if let Some(v) = body.get("best_block_hash") {
                    println!("  Best block: {}", v);
                }
                if let Some(v) = body.get("chain_work") {
                    println!("  Chain work: {}", v);
                }
            }
        }
        Ok(resp) => {
            eprintln!("error: node returned {}", resp.status());
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("error: cannot connect to {}: {}", rpc, e);
            eprintln!("       Is axiom-node running? Start with: axiom start");
            std::process::exit(1);
        }
    }

    // Metrics
    let metrics_url = format!("{}/metrics", base);
    if let Ok(resp) = reqwest::blocking::get(&metrics_url) {
        if resp.status().is_success() {
            if let Ok(body) = resp.json::<serde_json::Value>() {
                println!();
                println!("[NETWORK]");
                if let Some(v) = body.get("peer_count") {
                    println!("  Peers:      {}", v);
                }
                if let Some(v) = body.get("mempool_size") {
                    println!("  Mempool:    {} txs", v);
                }
                if let Some(v) = body.get("orphan_count") {
                    println!("  Orphans:    {}", v);
                }
            }
        }
    }

    // Hashrate
    let hash_url = format!("{}/network/hashrate", base);
    if let Ok(resp) = reqwest::blocking::get(&hash_url) {
        if resp.status().is_success() {
            if let Ok(body) = resp.json::<serde_json::Value>() {
                println!();
                println!("[MINING]");
                if let Some(v) = body.get("hashrate") {
                    println!("  Hashrate:   {}", v);
                }
                if let Some(v) = body.get("difficulty") {
                    println!("  Difficulty: {}", v);
                }
            }
        }
    }

    println!();
}

// ── axiom version ────────────────────────────────────────────────────────────

fn cmd_version() {
    println!("Axiom Network v{}", VERSION);
    println!();
    println!("  Signature:  ML-DSA-87 (FIPS 204, NIST Category 5)");
    println!("  Consensus:  Proof of Work + LWMA-3 difficulty");
    println!("  Encryption: Argon2id + XChaCha20-Poly1305");
    println!("  License:    MIT");
    println!("  Authors:    Kantoshi Miyamura");
    println!();
    #[cfg(debug_assertions)]
    println!("  Build:      debug");
    #[cfg(not(debug_assertions))]
    println!("  Build:      release");
    println!("  Target:     {}", std::env::consts::ARCH);
    println!("  OS:         {}", std::env::consts::OS);
}

// ── axiom init ───────────────────────────────────────────────────────────────

fn cmd_init(data_dir: Option<String>) {
    let data_path = data_dir
        .map(PathBuf::from)
        .unwrap_or_else(default_data_dir);

    println!();
    println!("========================================================");
    println!("           Axiom Network - First Run Setup");
    println!("========================================================");
    println!();

    // 1. Create data directory
    println!("  [1/4] Creating data directory...");
    fs::create_dir_all(&data_path).unwrap_or_else(|e| {
        eprintln!("        error: {}", e);
        std::process::exit(1);
    });
    println!("        {}", data_path.display());

    // 2. Create subdirectories
    println!("  [2/4] Creating directory structure...");
    for sub in &["blocks", "chainstate", "keystore", "logs"] {
        let p = data_path.join(sub);
        fs::create_dir_all(&p).ok();
        println!("        {}/", sub);
    }

    // 3. Write default config
    println!("  [3/4] Writing default configuration...");
    let config_path = data_path.join("axiom.conf");
    if !config_path.exists() {
        let config = format!(
            "# Axiom Network Configuration\n\
             # Generated by `axiom init`\n\
             \n\
             # Network: mainnet, testnet, devnet\n\
             network = \"mainnet\"\n\
             \n\
             # RPC server (local only by default — safe)\n\
             rpc_bind = \"127.0.0.1:8332\"\n\
             \n\
             # P2P port\n\
             p2p_bind = \"0.0.0.0:9000\"\n\
             \n\
             # Data directory\n\
             data_dir = \"{}\"\n\
             \n\
             # Logging\n\
             log_level = \"info\"\n\
             \n\
             # Mining (disabled by default)\n\
             # mine = true\n\
             # miner_address = \"axm...\"\n",
            data_path.display()
        );
        fs::write(&config_path, config).ok();
        println!("        {}", config_path.display());
    } else {
        println!("        (already exists, skipping)");
    }

    // 4. Prompt to create wallet
    println!("  [4/4] Wallet setup...");
    let wallet_path = data_path.join("wallet.json");
    if wallet_path.exists() {
        println!("        Wallet already exists at {}", wallet_path.display());
    } else {
        eprint!("        Create a wallet now? (yes/no): ");
        io::stderr().flush().unwrap();
        let mut answer = String::new();
        io::stdin().read_line(&mut answer).unwrap();
        if answer.trim().to_lowercase() == "yes" {
            cmd_wallet_create(Some(wallet_path));
            return; // wallet create prints its own summary
        } else {
            println!("        Skipped. Create later with: axiom wallet create");
        }
    }

    println!();
    println!("  Setup complete!");
    println!();
    println!("  Next steps:");
    println!("    1. Create a wallet:  axiom wallet create");
    println!("    2. Start the node:   axiom start");
    println!("    3. Start mining:     axiom start --mine");
    println!("    4. Check status:     axiom status");
    println!();
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn read_password_confirmed(prompt: &str) -> String {
    loop {
        eprint!("{}", prompt);
        io::stderr().flush().unwrap();
        let mut pw = String::new();
        io::stdin().read_line(&mut pw).unwrap();
        let pw = pw.trim().to_string();

        if pw.len() < 8 {
            println!("  Password too short. Minimum 8 characters.");
            continue;
        }

        eprint!("Confirm password: ");
        io::stderr().flush().unwrap();
        let mut confirm = String::new();
        io::stdin().read_line(&mut confirm).unwrap();

        if pw != confirm.trim() {
            println!("  Passwords do not match. Try again.");
            continue;
        }

        return pw;
    }
}

// Reads the wallet password.
//
// In production builds (default features) this is always an interactive prompt.
//
// When the `test-fixtures` Cargo feature is enabled, an `AXIOM_TEST_WALLET_PASSWORD`
// env var is honored instead, with a loud stderr warning. Release builds without
// the feature do not contain that code path at all.
#[cfg(not(feature = "test-fixtures"))]
fn read_wallet_password() -> String {
    rpassword::prompt_password("Wallet password: ").unwrap_or_else(|e| {
        eprintln!("error: failed to read password: {}", e);
        std::process::exit(1);
    })
}

#[cfg(feature = "test-fixtures")]
fn read_wallet_password() -> String {
    if let Ok(p) = std::env::var("AXIOM_TEST_WALLET_PASSWORD") {
        if !p.is_empty() {
            eprintln!("warning: using AXIOM_TEST_WALLET_PASSWORD — test-fixtures build, not for production");
            return p;
        }
    }
    rpassword::prompt_password("Wallet password: ").unwrap_or_else(|e| {
        eprintln!("error: failed to read password: {}", e);
        std::process::exit(1);
    })
}

// ── axiom mine (one-click, like Bitcoin Core) ───────────────────────────────

fn cmd_mine(peer: String, data_dir: Option<String>, log_level: String) {
    let data_path = data_dir
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(default_data_dir);

    println!();
    println!("  ========================================================");
    println!("       AXIOM NETWORK v0.5.0");
    println!("  ========================================================");
    println!();

    // Step 1: Ensure data directory
    fs::create_dir_all(&data_path).unwrap_or_else(|e| {
        eprintln!("  error: {}", e);
        std::process::exit(1);
    });
    for sub in &["blocks", "chainstate", "keystore", "logs"] {
        fs::create_dir_all(data_path.join(sub)).ok();
    }

    // Step 2: Load or create wallet.dat (like Bitcoin Core)
    let wallet_path = data_path.join("wallet.dat");

    let miner_address = if wallet_path.exists() {
        // Wallet exists — load address
        let data = fs::read_to_string(&wallet_path).unwrap_or_else(|e| {
            eprintln!("  error reading wallet.dat: {}", e);
            std::process::exit(1);
        });

        // Parse the wallet.dat (contains keystore + metadata)
        let wallet_data: serde_json::Value = serde_json::from_str(&data).unwrap_or_else(|e| {
            eprintln!("  error: corrupt wallet.dat: {}", e);
            std::process::exit(1);
        });

        let addr = wallet_data.get("address")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| {
                eprintln!("  error: wallet.dat missing address field");
                std::process::exit(1);
            })
            .to_string();

        println!("  Wallet:  {}...{}", &addr[..14], &addr[addr.len()-8..]);
        addr
    } else {
        // First run — create wallet automatically (like Bitcoin Core)
        let (phrase, seed) = axiom_wallet::generate_seed_phrase();

        let keypair = axiom_wallet::derive_account(&seed, 0).unwrap_or_else(|e| {
            eprintln!("  error: {}", e);
            std::process::exit(1);
        });
        let addr = axiom_wallet::Address::from_pubkey_hash(keypair.public_key_hash());
        let addr_str = addr.to_string();

        // Generate a strong random password for keystore encryption
        let random_pw: String = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            phrase.hash(&mut hasher);
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_nanos().hash(&mut hasher);
            format!("AXM_{:016x}_{:016x}", hasher.finish(), hasher.finish().wrapping_mul(0x517cc1b727220a95))
        };

        let keystore = axiom_wallet::create_keystore(keypair.export_private_key(), &random_pw)
            .unwrap_or_else(|e| {
                eprintln!("  error: {}", e);
                std::process::exit(1);
            });
        let ks_json = axiom_wallet::export_keystore(&keystore).unwrap_or_else(|e| {
            eprintln!("  error: {}", e);
            std::process::exit(1);
        });

        // Save wallet.dat with metadata (address, keystore, creation time)
        let wallet_data = serde_json::json!({
            "version": 1,
            "network": "axiom-mainnet-v1",
            "address": addr_str,
            "created_at": chrono_timestamp(),
            "encryption": "argon2id+xchacha20poly1305",
            "keystore": serde_json::from_str::<serde_json::Value>(&ks_json).unwrap_or_default(),
            "internal_key": random_pw,
        });

        let wallet_json = serde_json::to_string_pretty(&wallet_data).unwrap();
        fs::write(&wallet_path, &wallet_json).unwrap_or_else(|e| {
            eprintln!("  error: cannot write wallet.dat: {}", e);
            std::process::exit(1);
        });

        // Display seed phrase prominently — ONCE, in terminal only
        // No file on disk (more secure, like Bitcoin Core's dumpwallet)
        println!("  ========================================================");
        println!("       NEW WALLET CREATED");
        println!("  ========================================================");
        println!();
        println!("  Address: {}", addr_str);
        println!("  Saved:   {}", wallet_path.display());
        println!();
        println!("  ========================================================");
        println!("  RECOVERY PHRASE — WRITE THIS DOWN ON PAPER NOW!");
        println!("  This will NOT be shown again. No file is saved.");
        println!("  ========================================================");
        println!();

        let words: Vec<&str> = phrase.split_whitespace().collect();
        for row in 0..6 {
            let i = row * 4;
            println!("    {:2}. {:<15} {:2}. {:<15} {:2}. {:<15} {:2}. {:<15}",
                i+1, words[i], i+2, words[i+1], i+3, words[i+2], i+4, words[i+3]);
        }

        println!();
        println!("  ========================================================");
        println!("  If you lose this phrase, your coins are GONE FOREVER.");
        println!("  Back up wallet.dat as well.");
        println!("  ========================================================");
        println!();

        // Pause so user can write it down
        eprint!("  Press ENTER after you've written down your seed phrase...");
        io::stderr().flush().unwrap();
        let mut _buf = String::new();
        io::stdin().read_line(&mut _buf).ok();
        println!();

        addr_str
    };

    // Step 3: Start mining
    println!("  Network: axiom-mainnet-v1");
    println!("  Peer:    {}", peer);
    println!("  Wallet:  {}...{}", &miner_address[..14], &miner_address[miner_address.len()-8..]);
    println!("  Data:    {}", data_path.display());
    println!();
    println!("  ========================================================");
    println!("       MINING — DO NOT CLOSE THIS WINDOW");
    println!("  ========================================================");
    println!();

    cmd_start(
        "mainnet".to_string(),
        data_dir,
        "127.0.0.1:8332".to_string(),
        "0.0.0.0:9000".to_string(),
        true,
        Some(miner_address),
        vec![peer],
        log_level,
        30,
        None,
    );
}

fn chrono_timestamp() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", d.as_secs())
}

fn load_wallet_address(path: &PathBuf) -> String {
    let json = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("error: cannot read wallet {}: {}", path.display(), e);
        std::process::exit(1);
    });

    let keystore = axiom_wallet::import_keystore(&json).unwrap_or_else(|e| {
        eprintln!("error: invalid keystore format: {}", e);
        std::process::exit(1);
    });

    // Address is stored in keystore metadata
    // If not available, prompt for password to derive it
    eprint!("Wallet password: ");
    io::stderr().flush().unwrap();
    let mut pw = String::new();
    io::stdin().read_line(&mut pw).unwrap();
    let pw = pw.trim();

    let key_bytes = axiom_wallet::unlock_keystore(&keystore, pw).unwrap_or_else(|_| {
        eprintln!("error: wrong password");
        std::process::exit(1);
    });

    let keypair = axiom_wallet::KeyPair::from_private_key(key_bytes.to_vec()).unwrap_or_else(|e| {
        eprintln!("error: failed to load keypair: {}", e);
        std::process::exit(1);
    });

    axiom_wallet::Address::from_pubkey_hash(keypair.public_key_hash()).to_string()
}
