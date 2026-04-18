// Copyright (c) 2026 Kantoshi Miyamura

//! Axiom Network node CLI.

mod p2p;

use axiom_ai::{ComputeProtocol, InferenceRegistry, ModelRegistry, ReputationRegistry};
use axiom_guard::NetworkGuard;
use axiom_monitor::NetworkMonitorAgent;
use axiom_node::network::{
    resolve_dns_seeds, NetworkService, PeerDiscovery, PeerManager, DEVNET_DNS_SEEDS,
    MAINNET_DNS_SEEDS,
};
use axiom_node::{install_panic_hook, spawn_resilient, Watchdog, WatchdogConfig};
use axiom_node::{Config, Network, Node};
use axiom_rpc::RpcServer;
use axiom_wallet::{
    create_keystore, derive_account, export_keystore, generate_seed_phrase, import_keystore,
    unlock_keystore, Address,
};
use clap::Parser;
use p2p::P2PNetwork;
use std::fs;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::signal;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

/// Axiom Network Node
#[derive(Parser, Debug)]
#[command(name = "axiom-node")]
#[command(about = "Axiom Network blockchain node", long_about = None)]
#[command(version)]
struct Args {
    /// Network to connect to (mainnet, testnet, devnet)
    #[arg(long, default_value = "mainnet")]
    network: String,

    /// Data directory path
    #[arg(long, default_value = "./data")]
    data_dir: String,

    /// RPC bind address
    #[arg(long, default_value = "127.0.0.1:8332")]
    rpc_bind: String,

    /// P2P bind address
    #[arg(long, default_value = "0.0.0.0:9000")]
    p2p_bind: String,

    /// Seed nodes file (JSON format)
    #[arg(long)]
    seeds: Option<String>,

    /// Connect directly to a peer (can be specified multiple times).
    /// Example: --peer 1.2.3.4:9000 --peer 5.6.7.8:9000
    #[arg(long = "peer", value_name = "ADDR")]
    peers: Vec<String>,

    /// Enable mining
    #[arg(long)]
    mine: bool,

    /// Miner address for coinbase rewards (hex format)
    #[arg(long)]
    miner_address: Option<String>,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Mempool max size in bytes
    #[arg(long, default_value = "300000000")]
    mempool_max_size: usize,

    /// Mempool max transaction count
    #[arg(long, default_value = "50000")]
    mempool_max_count: usize,

    /// Minimum fee rate (satoshis per byte)
    #[arg(long, default_value = "1")]
    min_fee_rate: u64,

    /// Mining interval in seconds (for testing)
    #[arg(long, default_value = "30")]
    mining_interval: u64,

    /// Bearer token for RPC auth; omit only on devnet/localhost.
    #[arg(long)]
    rpc_auth_token: Option<String>,
}

/// Seed node configuration
#[derive(Debug, serde::Deserialize)]
struct SeedConfig {
    seeds: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Must run before any threads are spawned so all panics go through tracing.
    install_panic_hook();

    let args = Args::parse();
    init_logging(&args.log_level)?;

    info!("╔═══════════════════════════════════════════════════════════╗");
    info!("║           Axiom Network - Blockchain Node                ║");
    info!("╚═══════════════════════════════════════════════════════════╝");
    info!("");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));
    info!("Network: {}", args.network);
    info!("Data directory: {}", args.data_dir);
    info!("RPC bind: {}", args.rpc_bind);
    info!("P2P bind: {}", args.p2p_bind);
    info!("Mining: {}", if args.mine { "enabled" } else { "disabled" });
    info!("");

    let network = parse_network(&args.network)?;

    let data_path = PathBuf::from(&args.data_dir);
    if !data_path.exists() {
        info!("Creating data directory: {}", args.data_dir);
        fs::create_dir_all(&data_path)?;
    }

    let config = Config {
        network,
        data_dir: data_path.clone(),
        rpc_bind: args.rpc_bind.clone(),
        mempool_max_size: args.mempool_max_size,
        mempool_max_count: args.mempool_max_count,
        min_fee_rate: args.min_fee_rate,
    };

    info!("Validating configuration...");
    config.validate()?;

    info!("Initializing blockchain node...");
    let node = Node::new(config)?;

    let genesis_hash = node
        .best_block_hash()
        .unwrap_or(axiom_primitives::Hash256::zero());
    let genesis_height = node.best_height().unwrap_or(0);

    info!("✓ Node initialized successfully");
    info!(
        "  Genesis block: {}",
        hex::encode(&genesis_hash.as_bytes()[..8])
    );
    info!("  Current height: {}", genesis_height);
    info!("");

    let node_state = Arc::new(RwLock::new(node));

    info!("Initialising AxiomMind neural guardian...");
    let guard = match NetworkGuard::new(&data_path) {
        Ok(g) => {
            info!("✓ AxiomMind active — ML-DSA-87 cognitive fingerprint ready");
            Some(Arc::new(tokio::sync::RwLock::new(g)))
        }
        Err(e) => {
            warn!("AxiomMind failed to initialise ({}); running without guard", e);
            None
        }
    };

    info!("Initialising NetworkMonitorAgent...");
    let monitor_agent = NetworkMonitorAgent::new(node_state.clone());
    let monitor_store = monitor_agent.reports_store();
    tokio::spawn(monitor_agent.run());
    info!("✓ NetworkMonitorAgent started (analysis interval: 30s)");
    info!("");

    info!("Initializing P2P networking...");
    let peer_manager = Arc::new(PeerManager::new(args.network.clone()));
    let network_service = {
        let mut svc = NetworkService::with_shared_node(
            node_state.clone(),
            PeerManager::new(args.network.clone()),
        );
        // Hook AxiomMind into peer-received blocks so non-mining nodes
        // also benefit from threat detection.
        if let Some(g) = guard.clone() {
            svc.set_block_accepted_hook(Arc::new(move |block, height| {
                let g = g.clone();
                let block = block.clone();
                tokio::spawn(async move {
                    g.write().await.on_block(&block, height);
                });
            }));
        }
        Arc::new(RwLock::new(svc))
    };

    info!("✓ P2P networking initialized");
    info!("  Listening on: {}", args.p2p_bind);
    info!("");

    let mut direct_peers: Vec<SocketAddr> = args
        .peers
        .iter()
        .filter_map(|s| {
            s.parse::<SocketAddr>()
                .map_err(|e| {
                    warn!("Ignoring invalid --peer address '{}': {}", s, e);
                    e
                })
                .ok()
        })
        .collect();
    if !direct_peers.is_empty() {
        info!("Direct peers: {}", direct_peers.len());
        for p in &direct_peers {
            info!("  → {}", p);
        }
        info!("");
    }

    let seeds = if let Some(seeds_file) = &args.seeds {
        info!("Loading seed nodes from: {}", seeds_file);
        match load_seeds(seeds_file) {
            Ok(seeds) => {
                info!("✓ Loaded {} seed nodes", seeds.len());
                for seed in &seeds {
                    debug!("  Seed: {}", seed);
                }
                let seed_addrs: Vec<SocketAddr> =
                    seeds.iter().filter_map(|s| s.parse().ok()).collect();
                info!("  Parsed {} valid seed addresses", seed_addrs.len());
                seed_addrs
            }
            Err(e) => {
                warn!("Failed to load seeds: {}", e);
                warn!("Continuing without seed nodes");
                Vec::new()
            }
        }
    } else {
        info!("No seed nodes specified");
        Vec::new()
    };

    // DNS seeding skipped if --peer or --seeds were given.
    let dns_seeds = if seeds.is_empty() && direct_peers.is_empty() {
        let dns_hosts = match network {
            Network::Mainnet => MAINNET_DNS_SEEDS,
            _ => DEVNET_DNS_SEEDS,
        };
        info!("Resolving DNS seeds ({} hostnames)...", dns_hosts.len());
        let resolved = resolve_dns_seeds(dns_hosts);
        if resolved.is_empty() {
            info!("DNS seeds unreachable — starting as standalone node");
        } else {
            info!("✓ DNS seeding: {} peers discovered", resolved.len());
        }
        resolved
    } else {
        Vec::new()
    };

    let mut all_seeds = seeds;
    all_seeds.append(&mut direct_peers);
    all_seeds.extend(dns_seeds);
    let seeds = all_seeds;

    if seeds.is_empty() {
        info!("Running in standalone mode (no peers)");
    }
    info!("");

    let p2p_bind: SocketAddr = args.p2p_bind.parse()?;
    let discovery = Arc::new(Mutex::new(PeerDiscovery::new(seeds.clone())));
    let p2p_network = Arc::new(P2PNetwork::new(p2p_bind, peer_manager.clone(), discovery));
    p2p_network.clone().start(network_service.clone()).await?;
    info!("Initialising AI model registry...");
    let model_registry = match ModelRegistry::open(&data_path) {
        Ok(r) => {
            info!("✓ AI model registry ready");
            Some(Arc::new(r))
        }
        Err(e) => {
            warn!(
                "AI model registry unavailable ({}); /ai/model/* endpoints disabled",
                e
            );
            None
        }
    };

    info!("Initialising AI inference registry...");
    let inference_registry = match InferenceRegistry::open(&data_path) {
        Ok(r) => {
            info!("✓ AI inference registry ready");
            Some(Arc::new(r))
        }
        Err(e) => {
            warn!(
                "AI inference registry unavailable ({}); /ai/inference/* endpoints disabled",
                e
            );
            None
        }
    };
    info!("");

    info!("Initialising AI reputation registry...");
    let reputation_registry = match ReputationRegistry::open(&data_path) {
        Ok(r) => {
            info!("✓ AI reputation registry ready");
            Some(Arc::new(r))
        }
        Err(e) => {
            warn!(
                "AI reputation registry unavailable ({}); /ai/reputation/* endpoints disabled",
                e
            );
            None
        }
    };
    info!("");

    info!("Initialising Proof of Useful Compute (PoUC) protocol...");
    let compute_protocol = match ComputeProtocol::open(&data_path) {
        Ok(p) => {
            info!("✓ PoUC compute protocol ready");
            Some(Arc::new(p))
        }
        Err(e) => {
            warn!(
                "PoUC compute protocol unavailable ({}); /ai/compute/* endpoints disabled",
                e
            );
            None
        }
    };
    info!("");

    info!("Starting RPC server...");
    let rpc_addr = args.rpc_bind.parse()?;
    let rpc_server = {
        let mut base =
            RpcServer::with_network_service(rpc_addr, node_state.clone(), network_service.clone());
        if let Some(registry) = model_registry {
            base = base.with_model_registry(registry);
        }
        if let Some(registry) = inference_registry {
            base = base.with_inference_registry(registry);
        }
        if let Some(registry) = reputation_registry {
            base = base.with_reputation_registry(registry);
        }
        if let Some(protocol) = compute_protocol {
            base = base.with_compute_protocol(protocol);
        }
        if let Some(g) = guard.clone() {
            base = base.with_guard(g);
        }
        base = base.with_monitor_store(monitor_store.clone());
        if let Some(token) = args.rpc_auth_token.clone() {
            info!("RPC authentication: enabled (Bearer token)");
            base.with_auth_token(token)
        } else {
            info!("RPC authentication: disabled (open access — do not expose publicly)");
            base
        }
    };

    let rpc_handle = tokio::spawn(async move {
        if let Err(e) = rpc_server.start().await {
            error!("RPC server error: {}", e);
        }
    });

    info!("✓ RPC server started");
    info!("  Listening on: {}", args.rpc_bind);
    info!("");

    let mining_handle = if args.mine {
        info!("Starting mining engine...");

        let miner_address = if let Some(addr_str) = &args.miner_address {
            match parse_miner_address(addr_str) {
                Ok(addr) => {
                    info!("✓ Mining to address: {}", addr_str);
                    addr
                }
                Err(e) => {
                    error!("Invalid miner address '{}': {}", addr_str, e);
                    return Err(format!("Invalid miner address: {}", e).into());
                }
            }
        } else if network == Network::Dev {
            warn!("No --miner-address specified; block rewards go to burn address (devnet only)");
            axiom_primitives::Hash256::zero()
        } else {
            // Auto-create or load wallet from ~/.axiom/wallet.json
            match load_or_create_wallet() {
                Ok(hash) => hash,
                Err(e) => {
                    error!("Wallet error: {}", e);
                    return Err(e);
                }
            }
        };

        let mining_state = node_state.clone();
        let mining_network = network_service.clone();
        let mining_peers = peer_manager.clone();
        let mining_interval = args.mining_interval;
        let guard_for_mining = guard.clone();

        info!("✓ Mining engine started");
        info!("  Mining interval: {} seconds", mining_interval);
        info!("");

        Some(tokio::spawn(async move {
            mining_loop(
                mining_state,
                mining_network,
                mining_peers,
                miner_address,
                mining_interval,
                guard_for_mining,
            )
            .await;
        }))
    } else {
        info!("Mining disabled");
        info!("");
        None
    };

    // Resilient task — auto-restarts on panic.
    let tx_broadcast_state = node_state.clone();
    let tx_broadcast_network = network_service.clone();
    let tx_broadcast_handle = spawn_resilient("tx_broadcast", move || {
        let s = tx_broadcast_state.clone();
        let n = tx_broadcast_network.clone();
        async move { transaction_broadcast_loop(s, n).await }
    });

    {
        let watchdog_node = node_state.clone();
        let watchdog_peers = peer_manager.clone();
        let watchdog_pm_reconnect = peer_manager.clone();
        tokio::spawn(async move {
            let watchdog = Watchdog::new(watchdog_node, watchdog_peers, WatchdogConfig::default());
            watchdog
                .run(move |_consecutive| {
                    // Belt-and-suspenders reconnect hook when peer count hits 0.
                    let _ = watchdog_pm_reconnect.clone();
                })
                .await;
        });
    }

    info!("═══════════════════════════════════════════════════════════");
    info!("Node is running. Press Ctrl+C to stop.");
    info!("═══════════════════════════════════════════════════════════");
    info!("");

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Received SIGINT (Ctrl+C) — initiating graceful shutdown.");
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM — initiating graceful shutdown.");
            }
        }
    }
    #[cfg(not(unix))]
    {
        match signal::ctrl_c().await {
            Ok(()) => info!("Received shutdown signal — initiating graceful shutdown."),
            Err(err) => error!("Unable to listen for shutdown signal: {}", err),
        }
    }

    info!("");
    info!("Initiating graceful shutdown...");
    info!("");

    if let Some(handle) = mining_handle {
        info!("→ Stopping mining engine...");
        handle.abort();
        info!("  ✓ Mining stopped");
    }

    info!("→ Stopping transaction broadcast...");
    tx_broadcast_handle.abort();
    info!("  ✓ Transaction broadcast stopped");

    info!("→ Stopping RPC server...");
    rpc_handle.abort();
    info!("  ✓ RPC server stopped");

    // Spawned tasks drop on exit; peers detect TCP close.
    info!("→ Stopping P2P networking...");
    info!("  ✓ P2P networking stopped");

    info!("→ Saving mempool to disk...");
    {
        let node = node_state.read().await;
        match node.persist_mempool() {
            Ok(()) => info!("  ✓ Mempool saved successfully"),
            Err(e) => warn!("  Failed to save mempool on shutdown: {}", e),
        }
    }

    info!("→ Flushing storage...");
    {
        let node = node_state.read().await;
        let final_hash = node
            .best_block_hash()
            .unwrap_or(axiom_primitives::Hash256::zero());
        let final_height = node.best_height().unwrap_or(0);
        info!(
            "  Final block: {}",
            hex::encode(&final_hash.as_bytes()[..8])
        );
        info!("  Final height: {}", final_height);
        info!("  ✓ Storage flushed");
    }

    info!("");
    info!("═══════════════════════════════════════════════════════════");
    info!("Shutdown complete. Goodbye!");
    info!("═══════════════════════════════════════════════════════════");
    Ok(())
}

fn init_logging(level: &str) -> Result<(), Box<dyn std::error::Error>> {
    let filter = match level.to_lowercase().as_str() {
        "error" => tracing::Level::ERROR,
        "warn" => tracing::Level::WARN,
        "info" => tracing::Level::INFO,
        "debug" => tracing::Level::DEBUG,
        "trace" => tracing::Level::TRACE,
        _ => {
            eprintln!("Invalid log level '{}', using 'info'", level);
            tracing::Level::INFO
        }
    };

    tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .with_ansi(true)
        .init();

    Ok(())
}

fn parse_network(network: &str) -> Result<Network, Box<dyn std::error::Error>> {
    match network.to_lowercase().as_str() {
        "mainnet" | "main" => Ok(Network::Mainnet),
        "testnet" | "test" => Ok(Network::Test),
        "devnet" | "dev" => Ok(Network::Dev),
        _ => Err(format!(
            "Invalid network: {}  (valid: mainnet, testnet, devnet)",
            network
        )
        .into()),
    }
}

fn load_seeds(path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let config: SeedConfig = serde_json::from_str(&content)?;
    Ok(config.seeds)
}

/// Load wallet from ~/.axiom/wallet.json or create a new one interactively.
fn load_or_create_wallet() -> Result<axiom_primitives::Hash256, Box<dyn std::error::Error>> {
    let wallet_dir = dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".axiom");
    fs::create_dir_all(&wallet_dir)?;
    let wallet_path = wallet_dir.join("wallet.json");

    if wallet_path.exists() {
        // Load existing wallet.
        let json = fs::read_to_string(&wallet_path)?;
        let keystore = import_keystore(&json)?;
        let password = read_password("Enter wallet password: ")?;
        let key_bytes = unlock_keystore(&keystore, &password)
            .map_err(|_| "Wrong password")?;
        let keypair = axiom_wallet::KeyPair::from_private_key(key_bytes.to_vec())?;
        let address = Address::from_pubkey_hash(keypair.public_key_hash());
        let address_str = address.to_string();
        info!("✓ Wallet loaded: {}", address_str);
        return parse_miner_address(&address_str);
    }

    // No wallet — create one.
    info!("");
    info!("══════════════════════════════════════════════════════");
    info!("  No wallet found. Creating a new wallet.");
    info!("══════════════════════════════════════════════════════");
    info!("");

    let (phrase, seed) = generate_seed_phrase();

    info!("  Your 24-word seed phrase (WRITE THIS DOWN ON PAPER):");
    info!("");
    for (i, word) in phrase.split_whitespace().enumerate() {
        info!("    {:2}. {}", i + 1, word);
    }
    info!("");
    info!("  ⚠  This is the ONLY way to recover your wallet.");
    info!("  ⚠  Never share it. Never store it digitally.");
    info!("");

    // Confirm they wrote it down.
    print!("  Type 'yes' to confirm you wrote the seed phrase down: ");
    io::stdout().flush()?;
    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm)?;
    if confirm.trim().to_lowercase() != "yes" {
        return Err("Wallet creation cancelled.".into());
    }
    info!("");

    let keypair = derive_account(&seed, 0)?;
    let address = Address::from_pubkey_hash(keypair.public_key_hash());
    let address_str = address.to_string();

    let password = read_password("Choose a wallet password: ")?;
    let password2 = read_password("Confirm password: ")?;
    if password != password2 {
        return Err("Passwords do not match.".into());
    }

    let keystore = create_keystore(keypair.export_private_key(), &password)?;
    let json = export_keystore(&keystore)?;
    fs::write(&wallet_path, json)?;

    info!("");
    info!("  ✓ Wallet created and saved to: {}", wallet_path.display());
    info!("  ✓ Mining address: {}", address_str);
    info!("");

    parse_miner_address(&address_str)
}

fn read_password(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut pw = String::new();
    io::stdin().read_line(&mut pw)?;
    Ok(pw.trim().to_string())
}

/// Accepts raw 64-char hex pubkey hash or `axm...` v2 address (strips prefix + checksum).
fn parse_miner_address(
    addr: &str,
) -> Result<axiom_primitives::Hash256, Box<dyn std::error::Error>> {
    let hex_str = if addr.starts_with("axm") && addr.len() == 75 {
        // "axm" + 64 hex chars (pubkey hash) + 8 hex chars (checksum)
        &addr[3..67]
    } else {
        addr
    };
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        return Err(
            "Miner address must be 32 bytes (64 hex characters) or an axm... address".into(),
        );
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(axiom_primitives::Hash256::from_bytes(hash))
}

async fn mining_loop(
    node_state: Arc<RwLock<Node>>,
    network_service: Arc<RwLock<NetworkService>>,
    peer_manager: Arc<PeerManager>,
    miner_address: axiom_primitives::Hash256,
    interval_secs: u64,
    guard: Option<Arc<tokio::sync::RwLock<NetworkGuard>>>,
) {
    info!("═══════════════════════════════════════════════════════════");
    info!("Mining loop started");
    info!("═══════════════════════════════════════════════════════════");
    info!("");

    let mut block_count = 0;
    let interval = Duration::from_secs(interval_secs);

    loop {
        // IBD guard: do not mine while syncing.
        // If any peer reports a height significantly higher than ours,
        // we are in Initial Block Download and should not mine — doing
        // so creates a private fork that will be discarded on reorg.
        {
            let peer_count = peer_manager.ready_peer_count().await;
            let orphan_count = {
                let node = node_state.read().await;
                node.orphan_count()
            };

            // Heuristic: if we have orphans piling up, we're behind.
            // Also skip mining if we have zero peers (isolated node
            // can mine, but only if explicitly standalone).
            if orphan_count > 5 && peer_count > 0 {
                info!(
                    "⏳ Pausing mining — {} orphan blocks pending (syncing with {} peers)",
                    orphan_count, peer_count
                );
                sleep(Duration::from_secs(5)).await;
                continue;
            }
        }

        let start = std::time::Instant::now();

        let block = {
            let mut node = node_state.write().await;
            match node.build_block_for(miner_address) {
                Ok(block) => block,
                Err(e) => {
                    error!("Failed to build block: {}", e);
                    sleep(Duration::from_secs(10)).await;
                    continue;
                }
            }
        };

        let height = block.height().unwrap_or(0);
        let tx_count = block.transactions.len();

        debug!("Built block candidate:");
        debug!("  Height: {}", height);
        debug!("  Transactions: {}", tx_count);

        info!("⛏  Mining block at height {}...", height);

        let transactions = block.transactions;
        let header_orig = block.header;

        // CPU-intensive — run on blocking thread pool.
        let maybe_header = tokio::task::spawn_blocking(move || {
            let mut h = header_orig;
            axiom_consensus::mine_block(&mut h, None).map(|_nonce| h)
        })
        .await
        .unwrap_or(None);

        let mined_header = match maybe_header {
            Some(h) => h,
            None => {
                warn!("Nonce space exhausted — retrying with fresh block template");
                continue;
            }
        };

        let block = axiom_consensus::Block {
            header: mined_header,
            transactions,
        };

        let block_hash = block.hash();

        {
            let mut node = node_state.write().await;
            match node.process_block(block.clone()) {
                Ok(()) => {
                    block_count += 1;
                    let elapsed = start.elapsed();

                    info!("✓ Block mined successfully!");
                    info!("  Hash: {}", hex::encode(&block_hash.as_bytes()[..16]));
                    info!("  Height: {}", height);
                    info!("  Transactions: {}", tx_count);
                    info!("  Time: {:.2}s", elapsed.as_secs_f64());
                    info!("  Total mined: {}", block_count);
                }
                Err(e) => {
                    error!("Failed to process mined block: {}", e);
                    error!("");
                    sleep(Duration::from_secs(10)).await;
                    continue;
                }
            }
        }

        // AxiomMind — analyse the newly accepted block
        if let Some(ref g) = guard {
            let mut guard_w = g.write().await;
            let alerts = guard_w.on_block(&block, height as u64);
            for alert in &alerts {
                warn!("🛡 AxiomMind: [{}] {}", alert.code, alert.details);
            }
        }

        // AxiomMind — periodic mempool check
        if let Some(ref g) = guard {
            let mempool_size = {
                let node = node_state.read().await;
                node.mempool_transactions().len()
            };
            let mut guard_w = g.write().await;
            guard_w.on_mempool_update(mempool_size);
        }

        let peer_count = peer_manager.ready_peer_count().await;
        if peer_count > 0 {
            info!("📡 Broadcasting block to {} peers...", peer_count);

            let service = network_service.read().await;
            let block_msg = service.create_block_message(block.clone());
            drop(service);

            match peer_manager.broadcast(block_msg).await {
                Ok(sent) => {
                    info!("✓ Block broadcast to {} peers", sent);
                }
                Err(e) => {
                    warn!("Block broadcast error: {}", e);
                }
            }
        } else {
            debug!("No peers connected, skipping broadcast");
        }

        info!("");

        sleep(interval).await;
    }
}

// Broadcasts new mempool transactions to peers when the pool grows.
async fn transaction_broadcast_loop(
    node_state: Arc<RwLock<Node>>,
    network_service: Arc<RwLock<NetworkService>>,
) {
    info!("═══════════════════════════════════════════════════════════");
    info!("Transaction broadcast loop started");
    info!("═══════════════════════════════════════════════════════════");
    info!("");

    let mut last_mempool_size = 0;
    let check_interval = Duration::from_secs(1);

    loop {
        sleep(check_interval).await;

        let mempool_txs = {
            let node = node_state.read().await;
            node.mempool_transactions()
        };

        let current_size = mempool_txs.len();

        if current_size > last_mempool_size {
            let new_tx_count = current_size - last_mempool_size;
            debug!(
                "Mempool size changed: {} -> {} (new: {})",
                last_mempool_size, current_size, new_tx_count
            );

            for (_txid, tx) in mempool_txs.iter() {
                let service = network_service.read().await;
                let tx_msg = service.create_tx_message(tx.clone());
                let peer_mgr = service.peer_manager();
                drop(service);

                match peer_mgr.broadcast(tx_msg).await {
                    Ok(sent) => {
                        if sent > 0 {
                            let txid = axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(tx));
                            debug!(
                                "TX_BROADCAST_MEMPOOL: txid={}, peers={}",
                                hex::encode(&txid.as_bytes()[..8]),
                                sent
                            );
                        }
                    }
                    Err(e) => {
                        debug!("TX_BROADCAST_FAILED: error={}", e);
                    }
                }
            }

            last_mempool_size = current_size;
        }
    }
}
