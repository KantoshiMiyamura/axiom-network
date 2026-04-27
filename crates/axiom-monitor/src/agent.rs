// Copyright (c) 2026 Kantoshi Miyamura

//! Autonomous monitoring agent — runs in a background tokio task, periodically
//! analyses the network, stores reports, and broadcasts them to subscribers.

use crate::analyzer::NetworkAnalyzer;
use crate::types::MonitorReport;
use axiom_node::Node;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};
use tokio::time::interval;

const ANALYSIS_INTERVAL_SECS: u64 = 30;
const MAX_STORED_REPORTS: usize = 100;

/// Autonomous network-monitoring agent.
pub struct NetworkMonitorAgent {
    analyzer: NetworkAnalyzer,
    report_tx: broadcast::Sender<MonitorReport>,
    reports: Arc<RwLock<Vec<MonitorReport>>>,
}

impl NetworkMonitorAgent {
    /// Construct an agent.
    ///
    /// `expects_peers` should be `true` when the operator has configured at
    /// least one peer source (a `--peer ADDR` argument or a resolvable DNS
    /// seed list); `false` for a standalone-by-design first node. The flag
    /// changes how zero/low peer counts are surfaced in alerts.
    pub fn new(node: Arc<RwLock<Node>>, expects_peers: bool) -> Self {
        let (tx, _) = broadcast::channel(64);
        NetworkMonitorAgent {
            analyzer: NetworkAnalyzer::new(node, expects_peers),
            report_tx: tx,
            reports: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Subscribe to real-time monitoring reports.
    pub fn subscribe(&self) -> broadcast::Receiver<MonitorReport> {
        self.report_tx.subscribe()
    }

    /// Access the shared reports store.
    pub fn reports_store(&self) -> Arc<RwLock<Vec<MonitorReport>>> {
        self.reports.clone()
    }

    /// Run the agent forever — call this inside a spawned tokio task.
    pub async fn run(mut self) {
        let mut ticker = interval(Duration::from_secs(ANALYSIS_INTERVAL_SECS));
        tracing::info!(
            "NetworkMonitorAgent started (analysis interval: {}s)",
            ANALYSIS_INTERVAL_SECS
        );

        loop {
            ticker.tick().await;

            let report = self.analyzer.analyze().await;

            // Log summary
            tracing::info!(
                "MONITOR: health={:.1} mempool={} block_time={:.1}s alerts={}",
                report.health.overall,
                report.fee_analysis.mempool_depth,
                report.block_time_analysis.avg_block_time_secs,
                report.alerts.len()
            );

            // Log critical / warning alerts
            for alert in &report.alerts {
                match alert.severity {
                    crate::types::AlertSeverity::Critical => {
                        tracing::warn!(
                            "MONITOR_ALERT [CRITICAL] {}: {}",
                            alert.category,
                            alert.message
                        );
                    }
                    crate::types::AlertSeverity::Warning => {
                        tracing::info!(
                            "MONITOR_ALERT [WARNING] {}: {}",
                            alert.category,
                            alert.message
                        );
                    }
                    _ => {}
                }
            }

            // Store report, capping at MAX_STORED_REPORTS
            {
                let mut reports = self.reports.write().await;
                reports.push(report.clone());
                if reports.len() > MAX_STORED_REPORTS {
                    let excess = reports.len() - MAX_STORED_REPORTS;
                    reports.drain(0..excess);
                }
            }

            // Broadcast to subscribers (ignore SendError — no active receivers is OK)
            let _ = self.report_tx.send(report);
        }
    }
}
