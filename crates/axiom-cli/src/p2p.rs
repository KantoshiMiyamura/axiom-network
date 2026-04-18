// Copyright (c) 2026 Kantoshi Miyamura

//! P2P networking for CLI node.

use axiom_node::network::{
    Connection, Direction, Message, NetworkService, PeerDiscovery, PeerId, PeerManager, Transport,
};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};

/// How often the discovery connector loop wakes up (seconds).
const DISCOVERY_LOOP_INTERVAL_SECS: u64 = 30;

pub struct P2PNetwork {
    bind_addr: SocketAddr,
    peer_manager: Arc<PeerManager>,
    discovery: Arc<Mutex<PeerDiscovery>>,
    /// Outbound connector tasks currently in flight.
    pending_connections: Arc<Mutex<HashSet<SocketAddr>>>,
}

impl P2PNetwork {
    pub fn new(
        bind_addr: SocketAddr,
        peer_manager: Arc<PeerManager>,
        discovery: Arc<Mutex<PeerDiscovery>>,
    ) -> Self {
        P2PNetwork {
            bind_addr,
            peer_manager,
            discovery,
            pending_connections: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub async fn start(
        self: Arc<Self>,
        network_service: Arc<RwLock<NetworkService>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener_network = self.clone();
        let listener_service = network_service.clone();
        tokio::spawn(async move {
            if let Err(e) = listener_network.run_listener(listener_service).await {
                error!("Listener error: {}", e);
            }
        });

        let seeds = {
            let disc = self.discovery.lock().unwrap_or_else(|e| e.into_inner());
            disc.get_seed_nodes()
        };

        info!("DISCOVERY: connecting to {} seed nodes", seeds.len());
        for seed_addr in seeds {
            let connector_network = self.clone();
            let connector_service = network_service.clone();
            tokio::spawn(async move {
                connector_network
                    .connect_to_seed(seed_addr, connector_service)
                    .await;
            });
        }

        let discovery_network = self.clone();
        let discovery_service = network_service.clone();
        tokio::spawn(async move {
            discovery_network
                .run_discovery_loop(discovery_service)
                .await;
        });

        Ok(())
    }

    async fn run_listener(
        &self,
        network_service: Arc<RwLock<NetworkService>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut transport = Transport::new();
        transport.bind(self.bind_addr).await?;

        info!("P2P listener started on {}", self.bind_addr);

        loop {
            match transport.accept().await {
                Ok(connection) => {
                    let addr = connection.addr();
                    info!("PEER_INBOUND: {}", addr);

                    let peer_id = match self.peer_manager.add_peer(addr, Direction::Inbound).await {
                        Ok(id) => id,
                        Err(e) => {
                            warn!("Rejected inbound peer {}: {}", addr, e);
                            continue;
                        }
                    };
                    let service = network_service.clone();
                    let peer_mgr = self.peer_manager.clone();
                    let discovery = self.discovery.clone();
                    let bind_addr = self.bind_addr;

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(
                            connection, peer_id, service, peer_mgr, discovery, bind_addr,
                        )
                        .await
                        {
                            warn!("Connection handler error for {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    async fn connect_to_seed(
        &self,
        seed_addr: SocketAddr,
        network_service: Arc<RwLock<NetworkService>>,
    ) {
        let mut retry_delay = 1u64;

        loop {
            match Transport::connect(seed_addr).await {
                Ok(connection) => {
                    info!("PEER_SEED_CONNECTED: {}", seed_addr);
                    retry_delay = 1;

                    let peer_id = match self
                        .peer_manager
                        .add_peer(seed_addr, Direction::Outbound)
                        .await
                    {
                        Ok(id) => id,
                        Err(e) => {
                            warn!("Rejected outbound seed {}: {}", seed_addr, e);
                            sleep(Duration::from_secs(retry_delay)).await;
                            retry_delay = (retry_delay * 2).min(60);
                            continue;
                        }
                    };
                    let discovery = self.discovery.clone();
                    let bind_addr = self.bind_addr;

                    if let Err(e) = Self::handle_connection(
                        connection,
                        peer_id,
                        network_service.clone(),
                        self.peer_manager.clone(),
                        discovery,
                        bind_addr,
                    )
                    .await
                    {
                        warn!("Seed connection error for {}: {}", seed_addr, e);
                        self.peer_manager.remove_peer(peer_id).await;
                    }

                    info!("PEER_SEED_RECONNECT: {} in {}s", seed_addr, retry_delay);
                    sleep(Duration::from_secs(retry_delay)).await;
                    retry_delay = (retry_delay * 2).min(60);
                }
                Err(e) => {
                    debug!("Failed to connect to seed {}: {}", seed_addr, e);
                    sleep(Duration::from_secs(retry_delay)).await;
                    retry_delay = (retry_delay * 2).min(60);
                }
            }
        }
    }

    // Removes the address from `pending_connections` when done.
    async fn connect_to_discovered(
        self: Arc<Self>,
        addr: SocketAddr,
        network_service: Arc<RwLock<NetworkService>>,
    ) {
        match Transport::connect(addr).await {
            Ok(connection) => {
                info!("PEER_DISCOVERED_CONNECTED: {}", addr);
                let peer_id = match self.peer_manager.add_peer(addr, Direction::Outbound).await {
                    Ok(id) => id,
                    Err(e) => {
                        debug!("Rejected discovered peer {}: {}", addr, e);
                        let mut pending = self
                            .pending_connections
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        pending.remove(&addr);
                        return;
                    }
                };
                let discovery = self.discovery.clone();
                let bind_addr = self.bind_addr;

                if let Err(e) = Self::handle_connection(
                    connection,
                    peer_id,
                    network_service,
                    self.peer_manager.clone(),
                    discovery,
                    bind_addr,
                )
                .await
                {
                    debug!("Discovered peer error for {}: {}", addr, e);
                    self.peer_manager.remove_peer(peer_id).await;
                }
            }
            Err(e) => {
                debug!("Failed to connect to discovered peer {}: {}", addr, e);
            }
        }

        // Always remove from pending so the discovery loop can retry later.
        let mut pending = self
            .pending_connections
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pending.remove(&addr);
    }

    async fn run_discovery_loop(self: Arc<Self>, network_service: Arc<RwLock<NetworkService>>) {
        let mut interval = tokio::time::interval(Duration::from_secs(DISCOVERY_LOOP_INTERVAL_SECS));

        loop {
            interval.tick().await;

            let should_discover = {
                let disc = self.discovery.lock().unwrap_or_else(|e| e.into_inner());
                disc.should_discover()
            };

            if !should_discover {
                continue;
            }

            let known = {
                let disc = self.discovery.lock().unwrap_or_else(|e| e.into_inner());
                disc.get_peers()
            };

            let mut to_connect = Vec::new();
            for addr in known {
                if addr == self.bind_addr {
                    continue; // don't connect to ourselves
                }
                if self.peer_manager.is_addr_connected(addr).await {
                    continue; // already connected
                }
                let already_pending = {
                    let pending = self
                        .pending_connections
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    pending.contains(&addr)
                };
                if already_pending {
                    continue;
                }
                to_connect.push(addr);
            }

            if !to_connect.is_empty() {
                debug!("DISCOVERY_LOOP: attempting {} new peers", to_connect.len());
            }

            for addr in to_connect {
                {
                    let mut pending = self
                        .pending_connections
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    pending.insert(addr);
                }
                let network = self.clone();
                let service = network_service.clone();
                tokio::spawn(async move {
                    network.connect_to_discovered(addr, service).await;
                });
            }

            // Mark discovery cycle complete.
            let mut disc = self.discovery.lock().unwrap_or_else(|e| e.into_inner());
            disc.mark_discovery();
        }
    }

    async fn handle_connection(
        mut connection: Connection,
        peer_id: PeerId,
        network_service: Arc<RwLock<NetworkService>>,
        peer_manager: Arc<PeerManager>,
        discovery: Arc<Mutex<PeerDiscovery>>,
        bind_addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = connection.addr();

        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Message>();
        peer_manager.set_peer_sender(peer_id, outbound_tx).await?;

        let best_height = {
            let service = network_service.read().await;
            let (_, h) = service.get_tip().await;
            h
        };
        let version_msg = peer_manager.create_version(best_height);
        connection.send(&version_msg).await?;

        let writer = connection.clone_writer();
        let outbound_handle = tokio::spawn(async move {
            while let Some(message) = outbound_rx.recv().await {
                if let Message::Block(ref block) = message {
                    let bh = block.hash();
                    let ht = block.height().unwrap_or(0);
                    tracing::info!(
                        "OUTBOUND_BLOCK: peer={}, hash={}, height={}",
                        addr,
                        hex::encode(&bh.as_bytes()[..8]),
                        ht
                    );
                }
                if let Err(e) = writer.send(&message).await {
                    tracing::error!("OUTBOUND_SEND_ERROR: peer={}, error={}", addr, e);
                    break;
                }
            }
        });

        loop {
            match connection.receive().await {
                Ok(message) => {
                    if let Message::Block(ref block) = message {
                        let bh = block.hash();
                        let ht = block.height().unwrap_or(0);
                        tracing::info!(
                            "INBOUND_BLOCK: peer={}, hash={}, height={}",
                            addr,
                            hex::encode(&bh.as_bytes()[..8]),
                            ht
                        );
                    } else {
                        tracing::debug!("INBOUND_MSG: peer={}, type={:?}", addr, message);
                    }

                    if matches!(message, Message::Version(_) | Message::VerAck) {
                        match peer_manager.process_handshake(peer_id, &message).await {
                            Ok(Some(response)) => {
                                connection.send(&response).await?;
                            }
                            Ok(None) => {
                                if matches!(message, Message::VerAck) {
                                    tracing::info!("HANDSHAKE_COMPLETE: peer={}", addr);
                                    let _ =
                                        peer_manager.send_to_peer(peer_id, Message::GetPeers).await;

                                    let peer_height = peer_manager
                                        .get_peer(peer_id)
                                        .await
                                        .and_then(|p| p.best_height)
                                        .unwrap_or(0);
                                    let our_height = {
                                        let svc = network_service.read().await;
                                        svc.get_tip().await.1
                                    };
                                    if our_height > peer_height {
                                        let blocks = {
                                            let svc = network_service.read().await;
                                            svc.get_canonical_blocks_since(peer_height).await
                                        };
                                        tracing::info!(
                                            "IBD_PUSH: peer={}, sending {} blocks \
                                             (peer_height={} our_height={})",
                                            addr,
                                            blocks.len(),
                                            peer_height,
                                            our_height
                                        );
                                        for block in blocks {
                                            let _ = peer_manager
                                                .send_to_peer(peer_id, Message::Block(block))
                                                .await;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("HANDSHAKE_ERROR: peer={}, error={}", addr, e);
                                break;
                            }
                        }
                    } else if let Message::Peers(addrs) = message {
                        let new_count = addrs.len();
                        {
                            let mut disc = discovery.lock().unwrap_or_else(|e| e.into_inner());
                            for a in &addrs {
                                if *a != bind_addr {
                                    disc.add_peer(*a);
                                }
                            }
                        }
                        tracing::info!("PEERS_RECEIVED: peer={}, count={}", addr, new_count);
                    } else {
                        let service = network_service.clone();
                        let writer = connection.clone_writer();
                        let peer_addr = addr;

                        tokio::spawn(async move {
                            match service.read().await.handle_message(peer_id, message).await {
                                Ok(Some(resp)) => {
                                    if let Err(e) = writer.send(&resp).await {
                                        tracing::error!(
                                            "RESPONSE_SEND_ERROR: peer={}, error={}",
                                            peer_addr,
                                            e
                                        );
                                    }
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    tracing::error!(
                                        "MESSAGE_HANDLER_ERROR: peer={}, error={}",
                                        peer_addr,
                                        e
                                    );
                                }
                            }
                        });
                    }
                }
                Err(e) => {
                    tracing::debug!("Connection closed for {}: {}", addr, e);
                    break;
                }
            }
        }

        outbound_handle.abort();
        peer_manager.remove_peer(peer_id).await;
        info!("PEER_DISCONNECTED: {}", addr);

        Ok(())
    }
}
