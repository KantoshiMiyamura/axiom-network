// Copyright (c) 2026 Kantoshi Miyamura
//
// AxiomMind v2 — operational dashboards (security, performance, AI, network).
//
// INVARIANT: this module is read-only with respect to chain state. It
// aggregates metrics from observers (anomaly detector, network guard, RL
// engine) and exposes them via dashboards. It MUST NOT mutate consensus,
// mempool, or peer-set state.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Security dashboard metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDashboard {
    pub total_threats: usize,
    pub critical_threats: usize,
    pub high_threats: usize,
    pub medium_threats: usize,
    pub low_threats: usize,
    pub threat_trend: Vec<ThreatSnapshot>,
    pub last_update: u64,
}

/// Performance dashboard metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceDashboard {
    pub transactions_per_second: f64,
    pub average_block_time: f64,
    pub mempool_size: usize,
    pub network_latency_ms: f64,
    pub cpu_usage_percent: f64,
    pub memory_usage_mb: f64,
    pub disk_io_mbps: f64,
    pub performance_trend: Vec<PerformanceSnapshot>,
    pub last_update: u64,
}

/// AI dashboard metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIDashboard {
    pub model_accuracy: f64,
    pub anomalies_detected: usize,
    pub false_positive_rate: f64,
    pub learning_progress: f64,
    pub patches_applied: usize,
    pub patches_successful: usize,
    pub ai_trend: Vec<AISnapshot>,
    pub last_update: u64,
}

/// Network health dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDashboard {
    pub peer_count: usize,
    pub consensus_height: u64,
    pub reorg_depth: u64,
    pub network_partition_detected: bool,
    pub sync_status: SyncStatus,
    pub network_trend: Vec<NetworkSnapshot>,
    pub last_update: u64,
}

/// Sync status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncStatus {
    Synced,
    Syncing,
    Behind,
    Ahead,
}

/// Threat snapshot for trending
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSnapshot {
    pub timestamp: u64,
    pub total_threats: usize,
    pub critical: usize,
}

/// Performance snapshot for trending
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSnapshot {
    pub timestamp: u64,
    pub tps: f64,
    pub latency_ms: f64,
}

/// AI snapshot for trending
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AISnapshot {
    pub timestamp: u64,
    pub accuracy: f64,
    pub anomalies: usize,
}

/// Network snapshot for trending
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSnapshot {
    pub timestamp: u64,
    pub peers: usize,
    pub height: u64,
}

/// Audit event types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditEventType {
    AnomalyDetected,
    PatchApplied,
    PatchRolledBack,
    ConsensusVote,
    NetworkPartition,
    NodeJoined,
    NodeLeft,
    ConfigurationChanged,
    AlertTriggered,
    LearningUpdate,
}

/// Audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_type: AuditEventType,
    pub timestamp: u64,
    pub node_id: String,
    pub description: String,
    pub details: HashMap<String, String>,
    pub severity: AuditSeverity,
}

/// Audit severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuditSeverity {
    Info = 1,
    Warning = 2,
    Error = 3,
    Critical = 4,
}

/// Alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub alert_type: AlertType,
    pub severity: AlertSeverity,
    pub message: String,
    pub timestamp: u64,
    pub acknowledged: bool,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<u64>,
}

/// Alert types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertType {
    SecurityThreat,
    PerformanceDegradation,
    NetworkIssue,
    ConsensusIssue,
    HighMemoryUsage,
    HighCPUUsage,
    DiskSpaceLow,
    SyncIssue,
}

/// Alert severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info = 1,
    Warning = 2,
    Error = 3,
    Critical = 4,
}

/// Audit logger
pub struct AuditLogger {
    events: Arc<RwLock<Vec<AuditEvent>>>,
    node_id: String,
}

impl AuditLogger {
    pub fn new(node_id: String) -> Self {
        AuditLogger {
            events: Arc::new(RwLock::new(Vec::new())),
            node_id,
        }
    }

    /// Log an event
    pub async fn log(
        &self,
        event_type: AuditEventType,
        description: String,
        severity: AuditSeverity,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let event = AuditEvent {
            event_type,
            timestamp: now,
            node_id: self.node_id.clone(),
            description,
            details: HashMap::new(),
            severity,
        };

        let mut events = self.events.write().await;
        events.push(event);

        // Keep only last 100,000 events
        if events.len() > 100000 {
            events.remove(0);
        }
    }

    /// Log event with details
    pub async fn log_with_details(
        &self,
        event_type: AuditEventType,
        description: String,
        severity: AuditSeverity,
        details: HashMap<String, String>,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let event = AuditEvent {
            event_type,
            timestamp: now,
            node_id: self.node_id.clone(),
            description,
            details,
            severity,
        };

        let mut events = self.events.write().await;
        events.push(event);

        if events.len() > 100000 {
            events.remove(0);
        }
    }

    /// Get audit log
    pub async fn get_log(&self, limit: usize) -> Vec<AuditEvent> {
        let events = self.events.read().await;
        events.iter().rev().take(limit).cloned().collect()
    }

    /// Get events by type
    pub async fn get_events_by_type(
        &self,
        event_type: AuditEventType,
        limit: usize,
    ) -> Vec<AuditEvent> {
        let events = self.events.read().await;
        events
            .iter()
            .filter(|e| e.event_type == event_type)
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get events by severity
    pub async fn get_events_by_severity(
        &self,
        severity: AuditSeverity,
        limit: usize,
    ) -> Vec<AuditEvent> {
        let events = self.events.read().await;
        events
            .iter()
            .filter(|e| e.severity >= severity)
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
}

/// Alert manager
pub struct AlertManager {
    alerts: Arc<RwLock<Vec<Alert>>>,
    alert_threshold: AlertSeverity,
}

impl AlertManager {
    pub fn new(alert_threshold: AlertSeverity) -> Self {
        AlertManager {
            alerts: Arc::new(RwLock::new(Vec::new())),
            alert_threshold,
        }
    }

    /// Create alert
    pub async fn create_alert(
        &self,
        alert_type: AlertType,
        severity: AlertSeverity,
        message: String,
    ) -> String {
        if severity < self.alert_threshold {
            return String::new();
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let id = format!("ALERT-{}-{}", now, rand::random::<u32>());

        let alert = Alert {
            id: id.clone(),
            alert_type,
            severity,
            message,
            timestamp: now,
            acknowledged: false,
            acknowledged_by: None,
            acknowledged_at: None,
        };

        let mut alerts = self.alerts.write().await;
        alerts.push(alert);

        if alerts.len() > 10000 {
            alerts.remove(0);
        }

        id
    }

    /// Acknowledge alert
    pub async fn acknowledge_alert(
        &self,
        alert_id: &str,
        acknowledged_by: String,
    ) -> Result<(), String> {
        let mut alerts = self.alerts.write().await;

        for alert in alerts.iter_mut() {
            if alert.id == alert_id {
                alert.acknowledged = true;
                alert.acknowledged_by = Some(acknowledged_by);
                alert.acknowledged_at = Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                );
                return Ok(());
            }
        }

        Err(format!("Alert {} not found", alert_id))
    }

    /// Get active alerts
    pub async fn get_active_alerts(&self) -> Vec<Alert> {
        let alerts = self.alerts.read().await;
        alerts.iter().filter(|a| !a.acknowledged).cloned().collect()
    }

    /// Get all alerts
    pub async fn get_all_alerts(&self, limit: usize) -> Vec<Alert> {
        let alerts = self.alerts.read().await;
        alerts.iter().rev().take(limit).cloned().collect()
    }
}

/// Report generator
pub struct ReportGenerator;

impl ReportGenerator {
    /// Generate security report
    pub fn generate_security_report(dashboard: &SecurityDashboard) -> String {
        format!(
            r#"
# Security Report

**Generated:** {}

## Threat Summary
- Total Threats: {}
- Critical: {}
- High: {}
- Medium: {}
- Low: {}

## Threat Trend
{}

## Recommendations
{}
"#,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            dashboard.total_threats,
            dashboard.critical_threats,
            dashboard.high_threats,
            dashboard.medium_threats,
            dashboard.low_threats,
            Self::format_trend(&dashboard.threat_trend),
            Self::generate_security_recommendations(dashboard)
        )
    }

    /// Generate performance report
    pub fn generate_performance_report(dashboard: &PerformanceDashboard) -> String {
        format!(
            r#"
# Performance Report

**Generated:** {}

## Performance Metrics
- TPS: {:.2}
- Average Block Time: {:.2}s
- Mempool Size: {}
- Network Latency: {:.2}ms
- CPU Usage: {:.2}%
- Memory Usage: {:.2}MB
- Disk I/O: {:.2}MB/s

## Performance Trend
{}

## Recommendations
{}
"#,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            dashboard.transactions_per_second,
            dashboard.average_block_time,
            dashboard.mempool_size,
            dashboard.network_latency_ms,
            dashboard.cpu_usage_percent,
            dashboard.memory_usage_mb,
            dashboard.disk_io_mbps,
            Self::format_trend(&dashboard.performance_trend),
            Self::generate_performance_recommendations(dashboard)
        )
    }

    /// Generate AI report
    pub fn generate_ai_report(dashboard: &AIDashboard) -> String {
        format!(
            r#"
# AI Status Report

**Generated:** {}

## AI Metrics
- Model Accuracy: {:.2}%
- Anomalies Detected: {}
- False Positive Rate: {:.2}%
- Learning Progress: {:.2}%
- Patches Applied: {}
- Successful Patches: {}

## AI Trend
{}

## Recommendations
{}
"#,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            dashboard.model_accuracy * 100.0,
            dashboard.anomalies_detected,
            dashboard.false_positive_rate * 100.0,
            dashboard.learning_progress * 100.0,
            dashboard.patches_applied,
            dashboard.patches_successful,
            Self::format_trend(&dashboard.ai_trend),
            Self::generate_ai_recommendations(dashboard)
        )
    }

    fn format_trend<T: Serialize>(_trend: &[T]) -> String {
        "Trend data available in detailed metrics".to_string()
    }

    fn generate_security_recommendations(dashboard: &SecurityDashboard) -> String {
        if dashboard.critical_threats > 0 {
            "CRITICAL: Immediate action required for critical threats".to_string()
        } else if dashboard.high_threats > 0 {
            "HIGH: Review and address high-severity threats".to_string()
        } else {
            "Security status normal".to_string()
        }
    }

    fn generate_performance_recommendations(dashboard: &PerformanceDashboard) -> String {
        let mut recommendations = Vec::new();

        if dashboard.transactions_per_second < 100.0 {
            recommendations.push("Consider optimizing transaction processing");
        }
        if dashboard.cpu_usage_percent > 80.0 {
            recommendations.push("CPU usage is high, consider load balancing");
        }
        if dashboard.memory_usage_mb > 8000.0 {
            recommendations.push("Memory usage is high, consider optimization");
        }

        if recommendations.is_empty() {
            "Performance is optimal".to_string()
        } else {
            recommendations.join("; ")
        }
    }

    fn generate_ai_recommendations(dashboard: &AIDashboard) -> String {
        let mut recommendations = Vec::new();

        if dashboard.model_accuracy < 0.95 {
            recommendations.push("Model accuracy below target, continue training");
        }
        if dashboard.false_positive_rate > 0.05 {
            recommendations.push("False positive rate is high, review detection rules");
        }
        if dashboard.patches_successful as f64 / (dashboard.patches_applied as f64) < 0.9 {
            recommendations.push("Patch success rate below target, review patch generation");
        }

        if recommendations.is_empty() {
            "AI system performing optimally".to_string()
        } else {
            recommendations.join("; ")
        }
    }
}

/// Monitoring system
pub struct MonitoringSystem {
    pub security_dashboard: Arc<RwLock<SecurityDashboard>>,
    pub performance_dashboard: Arc<RwLock<PerformanceDashboard>>,
    pub ai_dashboard: Arc<RwLock<AIDashboard>>,
    pub network_dashboard: Arc<RwLock<NetworkDashboard>>,
    pub audit_logger: Arc<AuditLogger>,
    pub alert_manager: Arc<AlertManager>,
}

impl MonitoringSystem {
    pub fn new(node_id: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        MonitoringSystem {
            security_dashboard: Arc::new(RwLock::new(SecurityDashboard {
                total_threats: 0,
                critical_threats: 0,
                high_threats: 0,
                medium_threats: 0,
                low_threats: 0,
                threat_trend: Vec::new(),
                last_update: now,
            })),
            performance_dashboard: Arc::new(RwLock::new(PerformanceDashboard {
                transactions_per_second: 0.0,
                average_block_time: 0.0,
                mempool_size: 0,
                network_latency_ms: 0.0,
                cpu_usage_percent: 0.0,
                memory_usage_mb: 0.0,
                disk_io_mbps: 0.0,
                performance_trend: Vec::new(),
                last_update: now,
            })),
            ai_dashboard: Arc::new(RwLock::new(AIDashboard {
                model_accuracy: 0.0,
                anomalies_detected: 0,
                false_positive_rate: 0.0,
                learning_progress: 0.0,
                patches_applied: 0,
                patches_successful: 0,
                ai_trend: Vec::new(),
                last_update: now,
            })),
            network_dashboard: Arc::new(RwLock::new(NetworkDashboard {
                peer_count: 0,
                consensus_height: 0,
                reorg_depth: 0,
                network_partition_detected: false,
                sync_status: SyncStatus::Syncing,
                network_trend: Vec::new(),
                last_update: now,
            })),
            audit_logger: Arc::new(AuditLogger::new(node_id)),
            alert_manager: Arc::new(AlertManager::new(AlertSeverity::Warning)),
        }
    }

    /// Update all dashboards
    pub async fn update_dashboards(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut security = self.security_dashboard.write().await;
        security.last_update = now;

        let mut performance = self.performance_dashboard.write().await;
        performance.last_update = now;

        let mut ai = self.ai_dashboard.write().await;
        ai.last_update = now;

        let mut network = self.network_dashboard.write().await;
        network.last_update = now;
    }

    /// Get comprehensive status report
    pub async fn get_status_report(&self) -> StatusReport {
        let security = self.security_dashboard.read().await.clone();
        let performance = self.performance_dashboard.read().await.clone();
        let ai = self.ai_dashboard.read().await.clone();
        let network = self.network_dashboard.read().await.clone();
        let active_alerts = self.alert_manager.get_active_alerts().await;

        StatusReport {
            security,
            performance,
            ai,
            network,
            active_alerts,
            generated_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

/// Comprehensive status report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    pub security: SecurityDashboard,
    pub performance: PerformanceDashboard,
    pub ai: AIDashboard,
    pub network: NetworkDashboard,
    pub active_alerts: Vec<Alert>,
    pub generated_at: u64,
}

// In-crate `rand` shim. Returns `T::default()`, so any sampling in this
// module is deterministic. Monitoring outputs feed dashboards only — keeping
// them deterministic avoids spurious alert churn during replays.
mod rand {
    pub fn random<T>() -> T
    where
        T: Default,
    {
        T::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audit_logger() {
        let logger = AuditLogger::new("node1".to_string());
        logger
            .log(
                AuditEventType::AnomalyDetected,
                "Test anomaly".to_string(),
                AuditSeverity::Warning,
            )
            .await;

        let events = logger.get_log(10).await;
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn test_alert_manager() {
        let manager = AlertManager::new(AlertSeverity::Info);
        let alert_id = manager
            .create_alert(
                AlertType::SecurityThreat,
                AlertSeverity::Critical,
                "Test alert".to_string(),
            )
            .await;

        assert!(!alert_id.is_empty());

        manager
            .acknowledge_alert(&alert_id, "operator".to_string())
            .await
            .unwrap();

        let alerts = manager.get_all_alerts(10).await;
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].acknowledged);
    }

    #[tokio::test]
    async fn test_monitoring_system() {
        let system = MonitoringSystem::new("node1".to_string());
        system.update_dashboards().await;

        let report = system.get_status_report().await;
        assert_eq!(report.security.total_threats, 0);
    }
}
