// Copyright (c) 2026 Kantoshi Miyamura

//! WebSocket subscription endpoint (`GET /ws`).
//!
//! Broadcasts `new_block` and `new_tx` JSON events to all connected clients.
//! Lagged subscribers skip missed events and stay connected.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, Extension,
    },
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use crate::types::BlockSummary;

/// Broadcast channel capacity; subscribers lagging beyond this skip missed events.
pub const WS_CHANNEL_CAPACITY: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsTxEvent {
    pub txid: String,
    pub input_count: usize,
    pub output_count: usize,
    /// Total output value in satoshis.
    pub total_output: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum WsEvent {
    NewBlock(BlockSummary),
    NewTx(WsTxEvent),
}

/// Cheaply cloneable; all clones share the same underlying broadcast channel.
pub type EventBus = Arc<broadcast::Sender<WsEvent>>;

pub fn create_event_bus() -> EventBus {
    let (tx, _) = broadcast::channel(WS_CHANNEL_CAPACITY);
    Arc::new(tx)
}

/// Tracks WebSocket connections to prevent DoS via connection exhaustion.
#[derive(Clone)]
pub struct WsConnectionLimiter {
    total: Arc<AtomicUsize>,
    per_ip: Arc<RwLock<HashMap<IpAddr, usize>>>,
    max_total: usize,
    max_per_ip: usize,
}

impl WsConnectionLimiter {
    pub fn new(max_total: usize, max_per_ip: usize) -> Self {
        Self {
            total: Arc::new(AtomicUsize::new(0)),
            per_ip: Arc::new(RwLock::new(HashMap::new())),
            max_total,
            max_per_ip,
        }
    }

    async fn try_acquire(&self, ip: IpAddr) -> bool {
        let current_total = self.total.load(Ordering::Relaxed);
        if current_total >= self.max_total {
            return false;
        }

        let mut per_ip = self.per_ip.write().await;
        let ip_count = per_ip.entry(ip).or_insert(0);
        if *ip_count >= self.max_per_ip {
            return false;
        }

        self.total.fetch_add(1, Ordering::Relaxed);
        *ip_count += 1;
        true
    }

    async fn release(&self, ip: IpAddr) {
        self.total.fetch_sub(1, Ordering::Relaxed);
        let mut per_ip = self.per_ip.write().await;
        if let Some(count) = per_ip.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                per_ip.remove(&ip);
            }
        }
    }

    pub fn active_connections(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(bus): Extension<EventBus>,
    Extension(limiter): Extension<WsConnectionLimiter>,
) -> std::result::Result<impl IntoResponse, StatusCode> {
    let ip = addr.ip();

    if !limiter.try_acquire(ip).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(ws.on_upgrade(move |socket| async move {
        handle_socket(socket, bus.subscribe()).await;
        limiter.release(ip).await;
    }))
}

// Read-only subscription — client messages are ignored; exits on disconnect or channel close.
async fn handle_socket(mut socket: WebSocket, mut rx: broadcast::Receiver<WsEvent>) {
    loop {
        tokio::select! {
            client_msg = socket.recv() => {
                match client_msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {} // ignore pings / unexpected client messages
                    Some(Err(_)) => break,
                }
            }

            event = rx.recv() => {
                match event {
                    Ok(ev) => {
                        let json = match serde_json::to_string(&ev) {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        if socket.send(Message::Text(json)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BlockSummary;

    fn make_block_summary() -> BlockSummary {
        BlockSummary {
            hash: "a".repeat(64),
            height: 42,
            timestamp: 1_700_000_000,
            prev_block_hash: "b".repeat(64),
            merkle_root: "c".repeat(64),
            nonce: 999,
            difficulty: 0x1d00_ffff,
            transaction_count: 3,
        }
    }

    fn make_tx_event() -> WsTxEvent {
        WsTxEvent {
            txid: "d".repeat(64),
            input_count: 2,
            output_count: 2,
            total_output: 99_000,
        }
    }

    #[test]
    fn test_new_block_event_json_shape() {
        let ev = WsEvent::NewBlock(make_block_summary());
        let json = serde_json::to_string(&ev).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["type"], "new_block");
        assert_eq!(parsed["data"]["height"], 42);
        assert_eq!(parsed["data"]["transaction_count"], 3);
        assert_eq!(parsed["data"]["nonce"], 999);
    }

    #[test]
    fn test_new_tx_event_json_shape() {
        let ev = WsEvent::NewTx(make_tx_event());
        let json = serde_json::to_string(&ev).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["type"], "new_tx");
        assert_eq!(parsed["data"]["input_count"], 2);
        assert_eq!(parsed["data"]["output_count"], 2);
        assert_eq!(parsed["data"]["total_output"], 99_000);
    }

    #[test]
    fn test_ws_event_deserializes_new_block() {
        let ev = WsEvent::NewBlock(make_block_summary());
        let json = serde_json::to_string(&ev).unwrap();
        let decoded: WsEvent = serde_json::from_str(&json).unwrap();
        match decoded {
            WsEvent::NewBlock(b) => assert_eq!(b.height, 42),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_ws_event_deserializes_new_tx() {
        let ev = WsEvent::NewTx(make_tx_event());
        let json = serde_json::to_string(&ev).unwrap();
        let decoded: WsEvent = serde_json::from_str(&json).unwrap();
        match decoded {
            WsEvent::NewTx(tx) => assert_eq!(tx.total_output, 99_000),
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn test_event_bus_single_subscriber_receives_event() {
        let bus = create_event_bus();
        let mut rx = bus.subscribe();

        let ev = WsEvent::NewBlock(make_block_summary());
        bus.send(ev.clone()).unwrap();

        let received = rx.recv().await.unwrap();
        match received {
            WsEvent::NewBlock(b) => assert_eq!(b.height, 42),
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn test_event_bus_multiple_subscribers_each_receive_event() {
        let bus = create_event_bus();
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        bus.send(WsEvent::NewTx(make_tx_event())).unwrap();

        let ev1 = rx1.recv().await.unwrap();
        let ev2 = rx2.recv().await.unwrap();

        match (ev1, ev2) {
            (WsEvent::NewTx(t1), WsEvent::NewTx(t2)) => {
                assert_eq!(t1.total_output, 99_000);
                assert_eq!(t2.total_output, 99_000);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn test_event_bus_no_subscribers_send_ok() {
        let bus = create_event_bus();
        let result = bus.send(WsEvent::NewBlock(make_block_summary()));
        assert!(result.is_err(), "expected Err when no subscribers");
    }

    #[tokio::test]
    async fn test_event_bus_subscriber_after_send_misses_event() {
        let bus = create_event_bus();
        let mut rx_early = bus.subscribe();

        bus.send(WsEvent::NewBlock(make_block_summary())).unwrap();

        // Late subscriber misses the already-sent event.
        let mut rx_late = bus.subscribe();

        assert!(rx_early.recv().await.is_ok());

        bus.send(WsEvent::NewTx(make_tx_event())).unwrap();

        let late_ev = rx_late.recv().await.unwrap();
        assert!(matches!(late_ev, WsEvent::NewTx(_)));
    }

    #[tokio::test]
    async fn test_event_bus_lagged_receiver_recovers() {
        // Small capacity to force lagging.
        let (tx, mut rx) = broadcast::channel::<WsEvent>(2);
        let bus: EventBus = Arc::new(tx);

        for i in 0..4u32 {
            let _ = bus.send(WsEvent::NewBlock(BlockSummary {
                hash: "a".repeat(64),
                height: i,
                timestamp: 0,
                prev_block_hash: "b".repeat(64),
                merkle_root: "c".repeat(64),
                nonce: 0,
                difficulty: 0,
                transaction_count: 0,
            }));
        }

        let result = rx.recv().await;
        assert!(matches!(
            result,
            Err(broadcast::error::RecvError::Lagged(_))
        ));

        let next = rx.recv().await;
        assert!(next.is_ok(), "receiver should recover after Lagged");
    }

    #[test]
    fn test_create_event_bus_is_arc() {
        let bus = create_event_bus();
        let bus2 = bus.clone();
        assert_eq!(Arc::strong_count(&bus), 2);
        drop(bus2);
        assert_eq!(Arc::strong_count(&bus), 1);
    }
}
