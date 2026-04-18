// Copyright (c) 2026 Kantoshi Miyamura

//! Transaction anomaly detection engine.

use axiom_primitives::Hash256;
use axiom_protocol::Transaction;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);
const MAX_OUTPUTS_WARN: usize = 20;
const DUST_THRESHOLD_SAT: u64 = 546;
const FLOOD_THRESHOLD: usize = 10;
const MAX_INPUTS_WARN: usize = 50;
const MAX_ALERTS: usize = 100;
const SCORE_HISTORY: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyAlert {
    pub timestamp: u64,
    pub txid: String,
    pub code: String,
    pub description: String,
    pub severity: Severity,
    pub score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStats {
    pub total_analysed: u64,
    pub total_alerts: u64,
    pub active_addresses_60s: usize,
    pub max_score_60s: f64,
    pub avg_score_last_100: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAnalysisReport {
    pub alerts: Vec<AnomalyAlert>,
    pub stats: EngineStats,
}

struct AddressWindow {
    events: VecDeque<Instant>,
}

impl AddressWindow {
    fn new() -> Self {
        AddressWindow {
            events: VecDeque::new(),
        }
    }

    fn push(&mut self, now: Instant) -> usize {
        self.events.push_back(now);
        self.prune(now);
        self.events.len()
    }

    fn prune(&mut self, now: Instant) {
        while let Some(&front) = self.events.front() {
            if now.duration_since(front) > WINDOW {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }

    fn count(&self) -> usize {
        self.events.len()
    }
}

pub struct AnomalyDetector {
    address_windows: HashMap<Hash256, AddressWindow>,
    recent_alerts: VecDeque<AnomalyAlert>,
    recent_scores: VecDeque<f64>,
    scores_60s: VecDeque<(Instant, f64)>,
    total_analysed: u64,
    total_alerts: u64,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        AnomalyDetector {
            address_windows: HashMap::new(),
            recent_alerts: VecDeque::new(),
            recent_scores: VecDeque::new(),
            scores_60s: VecDeque::new(),
            total_analysed: 0,
            total_alerts: 0,
        }
    }

    /// Heuristic anomaly score for a transaction, in [0.0, 1.0].
    pub fn analyse(&mut self, txid: &Hash256, tx: &Transaction) -> f64 {
        let now = Instant::now();
        self.total_analysed += 1;

        let mut score: f64 = 0.0;
        let txid_hex = hex::encode(txid.as_bytes());

        let output_count = tx.outputs.len();
        if output_count > MAX_OUTPUTS_WARN {
            let rule_score = ((output_count - MAX_OUTPUTS_WARN) as f64 / 100.0).min(0.5);
            score += rule_score;
            let severity = if output_count > 50 {
                Severity::High
            } else {
                Severity::Medium
            };
            self.push_alert(AnomalyAlert {
                timestamp: unix_now(),
                txid: txid_hex.clone(),
                code: "FAN_OUT".into(),
                description: format!(
                    "Transaction has {} outputs (warn threshold: {})",
                    output_count, MAX_OUTPUTS_WARN
                ),
                severity,
                score: rule_score,
            });
        }

        let dust_count = tx
            .outputs
            .iter()
            .filter(|o| {
                let sat = o.value.as_sat();
                sat > 0 && sat < DUST_THRESHOLD_SAT
            })
            .count();
        if dust_count > 0 {
            let rule_score = (dust_count as f64 * 0.1).min(0.4);
            score += rule_score;
            self.push_alert(AnomalyAlert {
                timestamp: unix_now(),
                txid: txid_hex.clone(),
                code: "DUST_OUTPUT".into(),
                description: format!(
                    "{} dust output(s) detected (< {} sat each)",
                    dust_count, DUST_THRESHOLD_SAT
                ),
                severity: if dust_count > 3 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                score: rule_score,
            });
        }

        let zero_count = tx.outputs.iter().filter(|o| o.value.as_sat() == 0).count();
        if zero_count > 0 {
            let rule_score = (zero_count as f64 * 0.15).min(0.3);
            score += rule_score;
            self.push_alert(AnomalyAlert {
                timestamp: unix_now(),
                txid: txid_hex.clone(),
                code: "ZERO_VALUE_OUTPUT".into(),
                description: format!("{} zero-value output(s) detected", zero_count),
                severity: Severity::Medium,
                score: rule_score,
            });
        }

        if let Some(first_output) = tx.outputs.first() {
            let addr = first_output.pubkey_hash;
            let window = self
                .address_windows
                .entry(addr)
                .or_insert_with(AddressWindow::new);
            let count = window.push(now);
            if count > FLOOD_THRESHOLD {
                let rule_score = ((count - FLOOD_THRESHOLD) as f64 * 0.05).min(0.5);
                score += rule_score;
                self.push_alert(AnomalyAlert {
                    timestamp: unix_now(),
                    txid: txid_hex.clone(),
                    code: "ADDRESS_FLOOD".into(),
                    description: format!(
                        "Address submitted {} TX in the last 60 s (threshold: {})",
                        count, FLOOD_THRESHOLD
                    ),
                    severity: if count > 20 {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    score: rule_score,
                });
            }
        }

        let input_count = tx.inputs.len();
        if input_count > MAX_INPUTS_WARN {
            let rule_score = ((input_count - MAX_INPUTS_WARN) as f64 / 200.0).min(0.3);
            score += rule_score;
            self.push_alert(AnomalyAlert {
                timestamp: unix_now(),
                txid: txid_hex.clone(),
                code: "EXCESSIVE_INPUTS".into(),
                description: format!(
                    "Transaction has {} inputs (warn threshold: {})",
                    input_count, MAX_INPUTS_WARN
                ),
                severity: Severity::Low,
                score: rule_score,
            });
        }

        let score = score.min(1.0);

        self.recent_scores.push_back(score);
        if self.recent_scores.len() > SCORE_HISTORY {
            self.recent_scores.pop_front();
        }

        self.scores_60s.push_back((now, score));
        while let Some(&(ts, _)) = self.scores_60s.front() {
            if now.duration_since(ts) > WINDOW {
                self.scores_60s.pop_front();
            } else {
                break;
            }
        }

        score
    }

    pub fn report(&mut self) -> AiAnalysisReport {
        let now = Instant::now();

        for window in self.address_windows.values_mut() {
            window.prune(now);
        }

        let active_addresses_60s = self
            .address_windows
            .values()
            .filter(|w| w.count() > 0)
            .count();

        let max_score_60s = self
            .scores_60s
            .iter()
            .map(|(_, s)| *s)
            .fold(0.0_f64, f64::max);

        let avg_score_last_100 = if self.recent_scores.is_empty() {
            0.0
        } else {
            self.recent_scores.iter().sum::<f64>() / self.recent_scores.len() as f64
        };

        AiAnalysisReport {
            alerts: self.recent_alerts.iter().cloned().collect(),
            stats: EngineStats {
                total_analysed: self.total_analysed,
                total_alerts: self.total_alerts,
                active_addresses_60s,
                max_score_60s,
                avg_score_last_100,
            },
        }
    }

    fn push_alert(&mut self, alert: AnomalyAlert) {
        self.total_alerts += 1;
        self.recent_alerts.push_front(alert);
        if self.recent_alerts.len() > MAX_ALERTS {
            self.recent_alerts.pop_back();
        }
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_primitives::Amount;
    use axiom_protocol::{Transaction, TxOutput};

    fn make_tx(outputs: Vec<TxOutput>) -> (Hash256, Transaction) {
        let tx = Transaction::new_transfer(vec![], outputs, 1, 0);
        let txid = axiom_crypto::double_hash256(&axiom_protocol::serialize_transaction_unsigned(&tx));
        (txid, tx)
    }

    #[test]
    fn clean_tx_scores_zero() {
        let mut det = AnomalyDetector::new();
        let output = TxOutput {
            value: Amount::from_sat(100_000).unwrap(),
            pubkey_hash: Hash256::zero(),
        };
        let (txid, tx) = make_tx(vec![output]);
        let score = det.analyse(&txid, &tx);
        assert_eq!(score, 0.0);
        let report = det.report();
        assert_eq!(report.alerts.len(), 0);
        assert_eq!(report.stats.total_analysed, 1);
    }

    #[test]
    fn dust_output_raises_alert() {
        let mut det = AnomalyDetector::new();
        let output = TxOutput {
            value: Amount::from_sat(100).unwrap(),
            pubkey_hash: Hash256::zero(),
        };
        let (txid, tx) = make_tx(vec![output]);
        let score = det.analyse(&txid, &tx);
        assert!(score > 0.0);
        let report = det.report();
        assert!(report.alerts.iter().any(|a| a.code == "DUST_OUTPUT"));
    }

    #[test]
    fn fan_out_raises_alert() {
        let mut det = AnomalyDetector::new();
        let outputs: Vec<TxOutput> = (0..25)
            .map(|i| TxOutput {
                value: Amount::from_sat(1000 + i).unwrap(),
                pubkey_hash: Hash256::zero(),
            })
            .collect();
        let (txid, tx) = make_tx(outputs);
        let score = det.analyse(&txid, &tx);
        assert!(score > 0.0);
        let report = det.report();
        assert!(report.alerts.iter().any(|a| a.code == "FAN_OUT"));
    }

    #[test]
    fn flood_detection() {
        let mut det = AnomalyDetector::new();
        let pubkey_hash = Hash256::zero();
        let mut last_score = 0.0;
        for i in 0..=FLOOD_THRESHOLD {
            let output = TxOutput {
                value: Amount::from_sat(1000 + i as u64).unwrap(),
                pubkey_hash,
            };
            let (txid, tx) = make_tx(vec![output]);
            last_score = det.analyse(&txid, &tx);
        }
        assert!(last_score > 0.0);
        let report = det.report();
        assert!(report.alerts.iter().any(|a| a.code == "ADDRESS_FLOOD"));
    }
}
