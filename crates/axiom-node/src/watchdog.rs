// Copyright (c) 2026 Kantoshi Miyamura

//! Background watchdog for chain stalls, peer loss, and memory pressure.

use crate::network::PeerManager;
use crate::Node;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{error, info, warn};

pub const DEFAULT_STALL_THRESHOLD_SECS: u64 = 30 * 60;
pub const DEFAULT_CHECK_INTERVAL_SECS: u64 = 60;
pub const DEFAULT_MAX_RSS_MB: u64 = 2048;

#[derive(Debug, Clone)]
pub struct WatchdogConfig {
    pub stall_threshold: Duration,
    pub check_interval: Duration,
    pub max_rss_mb: u64,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        WatchdogConfig {
            stall_threshold: Duration::from_secs(DEFAULT_STALL_THRESHOLD_SECS),
            check_interval: Duration::from_secs(DEFAULT_CHECK_INTERVAL_SECS),
            max_rss_mb: DEFAULT_MAX_RSS_MB,
        }
    }
}

pub struct Watchdog {
    node: Arc<RwLock<Node>>,
    peer_manager: Arc<PeerManager>,
    config: WatchdogConfig,
}

impl Watchdog {
    pub fn new(
        node: Arc<RwLock<Node>>,
        peer_manager: Arc<PeerManager>,
        config: WatchdogConfig,
    ) -> Self {
        Watchdog {
            node,
            peer_manager,
            config,
        }
    }

    pub async fn run<F>(&self, on_zero_peers: F)
    where
        F: Fn(u32) + Send + Sync + 'static,
    {
        info!(
            "[watchdog] started (check_interval={}s, stall_threshold={}s, max_rss={}MiB)",
            self.config.check_interval.as_secs(),
            self.config.stall_threshold.as_secs(),
            self.config.max_rss_mb,
        );

        let mut last_height: Option<u32> = None;
        let mut last_height_change: Instant = Instant::now();
        let mut consecutive_zero_peers: u32 = 0;
        let mut stall_logged = false;

        loop {
            sleep(self.config.check_interval).await;

            let current_height = {
                match self.node.try_read() {
                    Ok(node) => node.best_height(),
                    Err(_) => None,
                }
            };

            match (last_height, current_height) {
                (None, h) => {
                    last_height = h;
                    last_height_change = Instant::now();
                }
                (Some(prev), Some(curr)) if curr > prev => {
                    last_height = Some(curr);
                    last_height_change = Instant::now();
                    stall_logged = false;
                }
                (Some(prev), same) => {
                    let stall_duration = Instant::now().duration_since(last_height_change);
                    if stall_duration >= self.config.stall_threshold && !stall_logged {
                        warn!(
                            "[watchdog] CHAIN STALL detected — tip has not advanced for {}m \
                             (stuck at height {:?}). Check peer connectivity.",
                            stall_duration.as_secs() / 60,
                            same.unwrap_or(prev),
                        );
                        stall_logged = true;
                    }
                }
            }

            let peer_count = self.peer_manager.ready_peer_count().await;

            if peer_count == 0 {
                consecutive_zero_peers += 1;
                if consecutive_zero_peers == 1 || consecutive_zero_peers.is_multiple_of(5) {
                    warn!(
                        "[watchdog] ISOLATED — 0 connected peers (tick #{}).",
                        consecutive_zero_peers,
                    );
                }
                on_zero_peers(consecutive_zero_peers);
            } else {
                if consecutive_zero_peers > 0 {
                    info!("[watchdog] reconnected — {} peer(s) available.", peer_count);
                }
                consecutive_zero_peers = 0;
            }

            #[cfg(target_os = "linux")]
            self.check_memory();

            static TICK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let tick = TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if tick.is_multiple_of(10) {
                info!(
                    "[watchdog] heartbeat — height={:?} peers={} uptime={}min",
                    current_height,
                    peer_count,
                    tick * self.config.check_interval.as_secs() / 60,
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn check_memory(&self) {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("VmRSS:") {
                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                        if let Ok(kb) = kb_str.parse::<u64>() {
                            let mb = kb / 1024;
                            if mb > self.config.max_rss_mb {
                                warn!(
                                    "[watchdog] MEMORY WARNING — RSS {}MiB exceeds limit {}MiB. \
                                     Consider reducing --mempool-max-size or restarting.",
                                    mb, self.config.max_rss_mb
                                );
                            }
                        }
                    }
                    break;
                }
            }
        }
    }
}

pub fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<unknown>".to_string());

        let message = if let Some(s) = info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "Box<dyn Any>".to_string()
        };

        error!(
            "[PANIC] {} at {} — the process will terminate and systemd/Task Scheduler \
             should restart it automatically.",
            message, location
        );

        eprintln!("[PANIC] {} at {}", message, location);

        default_hook(info);
    }));
}

/// Spawn a task that restarts on panic with exponential backoff.
pub fn spawn_resilient<F, Fut>(name: &'static str, factory: F) -> tokio::task::JoinHandle<()>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        let mut attempt: u32 = 0;

        loop {
            let handle = tokio::spawn(factory());

            match handle.await {
                Ok(()) => {
                    info!("[resilient:{}] task exited normally.", name);
                    return;
                }
                Err(join_err) if join_err.is_panic() => {
                    attempt += 1;
                    error!(
                        "[resilient:{}] PANIC on attempt {} — restarting in {}s",
                        name,
                        attempt,
                        backoff.as_secs()
                    );
                    sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
                Err(join_err) => {
                    info!("[resilient:{}] task cancelled: {}", name, join_err);
                    return;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watchdog_config_default() {
        let cfg = WatchdogConfig::default();
        assert_eq!(cfg.stall_threshold.as_secs(), DEFAULT_STALL_THRESHOLD_SECS);
        assert_eq!(cfg.check_interval.as_secs(), DEFAULT_CHECK_INTERVAL_SECS);
        assert_eq!(cfg.max_rss_mb, DEFAULT_MAX_RSS_MB);
    }

    #[tokio::test]
    async fn test_spawn_resilient_normal_exit() {
        let count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let count2 = count.clone();

        let handle = spawn_resilient("test_normal", move || {
            let c = count2.clone();
            async move {
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });

        handle.await.unwrap();
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
