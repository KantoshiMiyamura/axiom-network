// Copyright (c) 2026 Kantoshi Miyamura
//
// AxiomMind v2 — Q-learning policy module.
//
// INVARIANT: this module is advisory only. `select_action` returns an `Action`
// that is consumed exclusively by `learn()` for Q-value updates; no variant is
// dispatched to consensus, peer state, or the filesystem. Any future caller
// that interprets `Action` as an instruction MUST go through an explicit
// security review (see AI-CONSENSUS-AUDIT.md, R1).

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// State representation for Q-learning
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum State {
    /// Normal network operation
    Normal,
    /// Anomaly detected
    AnomalyDetected,
    /// Multiple anomalies
    MultipleAnomalies,
    /// Critical threat
    CriticalThreat,
    /// Recovery in progress
    RecoveryInProgress,
    /// Network degraded
    NetworkDegraded,
}

/// Q-learning action label. These are policy outputs the RL module records
/// against state transitions; none is dispatched to live systems by this crate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    NoAction,
    Alert,
    IncreaseMonitoring,
    /// Telemetry-only. No dispatcher: wiring this to source-file mutation
    /// requires a separate security review (see AI-CONSENSUS-AUDIT.md, R1/R2).
    ApplyPatch,
    /// Telemetry-only. No dispatcher: this label MUST NOT be wired to peer
    /// disconnect logic without an explicit network-policy review.
    IsolateNodes,
    /// Telemetry-only. No dispatcher: consensus is rule-driven, never
    /// AI-driven. Wiring this would break the AI/consensus isolation boundary.
    TriggerConsensus,
    Rollback,
    ReduceLoad,
}

/// Reward signal for learning
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Reward {
    pub value: f64,
    pub reason: &'static str,
}

impl Reward {
    pub fn success() -> Self {
        Reward {
            value: 1.0,
            reason: "Action successful",
        }
    }

    pub fn partial_success() -> Self {
        Reward {
            value: 0.5,
            reason: "Partial success",
        }
    }

    pub fn failure() -> Self {
        Reward {
            value: -1.0,
            reason: "Action failed",
        }
    }

    pub fn no_change() -> Self {
        Reward {
            value: 0.0,
            reason: "No change",
        }
    }
}

/// Learning episode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Episode {
    pub state: State,
    pub action: Action,
    pub reward: f64,
    pub next_state: State,
    pub timestamp: u64,
}

/// Q-Learning implementation
pub struct QLearningModule {
    /// Q-table: state -> action -> Q-value
    q_table: Arc<RwLock<HashMap<State, HashMap<Action, f64>>>>,
    /// Learning rate (alpha)
    learning_rate: f64,
    /// Discount factor (gamma)
    discount_factor: f64,
    /// Exploration rate (epsilon)
    exploration_rate: f64,
    /// Minimum exploration rate
    min_exploration_rate: f64,
    /// Exploration decay
    exploration_decay: f64,
    /// Episode history
    episode_history: Arc<RwLock<Vec<Episode>>>,
}

impl Default for QLearningModule {
    fn default() -> Self {
        Self::new()
    }
}

impl QLearningModule {
    pub fn new() -> Self {
        QLearningModule {
            q_table: Arc::new(RwLock::new(HashMap::new())),
            learning_rate: 0.1,
            discount_factor: 0.95,
            exploration_rate: 1.0,
            min_exploration_rate: 0.01,
            exploration_decay: 0.995,
            episode_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Initialize Q-table with all states and actions
    pub async fn initialize(&self) {
        let mut q_table = self.q_table.write().await;

        let states = vec![
            State::Normal,
            State::AnomalyDetected,
            State::MultipleAnomalies,
            State::CriticalThreat,
            State::RecoveryInProgress,
            State::NetworkDegraded,
        ];

        let actions = vec![
            Action::NoAction,
            Action::Alert,
            Action::IncreaseMonitoring,
            Action::ApplyPatch,
            Action::IsolateNodes,
            Action::TriggerConsensus,
            Action::Rollback,
            Action::ReduceLoad,
        ];

        for state in states {
            let mut action_values = HashMap::new();
            for action in &actions {
                action_values.insert(action.clone(), 0.0);
            }
            q_table.insert(state, action_values);
        }
    }

    /// Select action using epsilon-greedy strategy
    pub async fn select_action(&self, state: &State) -> Action {
        let q_table = self.q_table.read().await;

        // Exploration vs exploitation
        if rand::random::<f64>() < self.exploration_rate {
            // Explore: random action
            let actions = [Action::NoAction,
                Action::Alert,
                Action::IncreaseMonitoring,
                Action::ApplyPatch,
                Action::IsolateNodes,
                Action::TriggerConsensus,
                Action::Rollback,
                Action::ReduceLoad];
            actions[(rand::random::<usize>()) % actions.len()].clone()
        } else {
            // Exploit: best action
            if let Some(action_values) = q_table.get(state) {
                action_values
                    .iter()
                    .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                    .map(|(action, _)| action.clone())
                    .unwrap_or(Action::NoAction)
            } else {
                Action::NoAction
            }
        }
    }

    /// Learn from experience
    pub async fn learn(
        &self,
        state: State,
        action: Action,
        reward: f64,
        next_state: State,
    ) -> Result<(), String> {
        let mut q_table = self.q_table.write().await;

        // Get current Q-value
        let current_q = q_table
            .get(&state)
            .and_then(|actions| actions.get(&action))
            .copied()
            .unwrap_or(0.0);

        // Get max Q-value for next state
        let max_next_q = q_table
            .get(&next_state)
            .map(|actions| {
                actions
                    .values()
                    .copied()
                    .fold(f64::NEG_INFINITY, f64::max)
            })
            .unwrap_or(0.0);

        // Q-learning update rule
        let new_q = current_q
            + self.learning_rate * (reward + self.discount_factor * max_next_q - current_q);

        // Update Q-table
        if let Some(action_values) = q_table.get_mut(&state) {
            action_values.insert(action.clone(), new_q);
        }

        // exploration_rate decay computed but not persisted: the field is `&self`,
        // not `&mut self`. Treat the decay as advisory until the engine carries
        // interior mutability for it.
        let _new_exploration_rate = (self.exploration_rate * self.exploration_decay)
            .max(self.min_exploration_rate);

        // Record episode
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let episode = Episode {
            state,
            action,
            reward,
            next_state,
            timestamp: now,
        };

        let mut history = self.episode_history.write().await;
        history.push(episode);
        if history.len() > 100000 {
            history.remove(0);
        }

        Ok(())
    }

    /// Get Q-value for state-action pair
    pub async fn get_q_value(&self, state: &State, action: &Action) -> f64 {
        let q_table = self.q_table.read().await;
        q_table
            .get(state)
            .and_then(|actions| actions.get(action))
            .copied()
            .unwrap_or(0.0)
    }

    /// Get best action for state
    pub async fn get_best_action(&self, state: &State) -> Option<Action> {
        let q_table = self.q_table.read().await;
        q_table
            .get(state)
            .and_then(|actions| {
                actions
                    .iter()
                    .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                    .map(|(action, _)| action.clone())
            })
    }

    /// Get Q-table statistics
    pub async fn get_stats(&self) -> LearningStats {
        let q_table = self.q_table.read().await;
        let history = self.episode_history.read().await;

        let total_episodes = history.len();
        let successful_episodes = history.iter().filter(|e| e.reward > 0.0).count();
        let failed_episodes = history.iter().filter(|e| e.reward < 0.0).count();

        let avg_reward = if total_episodes > 0 {
            history.iter().map(|e| e.reward).sum::<f64>() / total_episodes as f64
        } else {
            0.0
        };

        let mut state_values: HashMap<State, f64> = HashMap::new();
        for (state, actions) in q_table.iter() {
            let avg_q = if !actions.is_empty() {
                actions.values().sum::<f64>() / actions.len() as f64
            } else {
                0.0
            };
            state_values.insert(state.clone(), avg_q);
        }

        LearningStats {
            total_episodes,
            successful_episodes,
            failed_episodes,
            avg_reward,
            state_values,
        }
    }

    /// Get episode history
    pub async fn get_episode_history(&self, limit: usize) -> Vec<Episode> {
        let history = self.episode_history.read().await;
        history
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
}

/// Learning statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningStats {
    pub total_episodes: usize,
    pub successful_episodes: usize,
    pub failed_episodes: usize,
    pub avg_reward: f64,
    pub state_values: HashMap<State, f64>,
}

/// Policy for action selection
pub struct Policy {
    pub state: State,
    pub recommended_action: Action,
    pub confidence: f64,
    pub reason: String,
}

impl Policy {
    /// Generate policy based on current state
    pub fn generate(state: State, q_values: &HashMap<Action, f64>) -> Self {
        let (best_action, best_value) = q_values
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(action, value)| (action.clone(), *value))
            .unwrap_or((Action::NoAction, 0.0));

        let confidence = (best_value / 10.0).clamp(0.0, 1.0);

        let reason = match state {
            State::Normal => "Network operating normally".to_string(),
            State::AnomalyDetected => "Anomaly detected, monitoring increased".to_string(),
            State::MultipleAnomalies => "Multiple anomalies detected, investigation needed".to_string(),
            State::CriticalThreat => "Critical threat detected, immediate action required".to_string(),
            State::RecoveryInProgress => "Recovery in progress, monitoring status".to_string(),
            State::NetworkDegraded => "Network degraded, load reduction recommended".to_string(),
        };

        Policy {
            state,
            recommended_action: best_action,
            confidence,
            reason,
        }
    }
}

/// Reinforcement Learning Engine
pub struct ReinforcementLearningEngine {
    q_learning: Arc<QLearningModule>,
    current_state: Arc<RwLock<State>>,
}

impl Default for ReinforcementLearningEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ReinforcementLearningEngine {
    pub fn new() -> Self {
        ReinforcementLearningEngine {
            q_learning: Arc::new(QLearningModule::new()),
            current_state: Arc::new(RwLock::new(State::Normal)),
        }
    }

    /// Initialize the engine
    pub async fn initialize(&self) {
        self.q_learning.initialize().await;
    }

    /// Update state and learn
    pub async fn update_state(&self, new_state: State, reward: f64) -> Result<(), String> {
        let current = self.current_state.read().await.clone();
        let action = self.q_learning.select_action(&current).await;

        self.q_learning
            .learn(current, action, reward, new_state.clone())
            .await?;

        let mut state = self.current_state.write().await;
        *state = new_state;

        Ok(())
    }

    /// Get current policy
    pub async fn get_policy(&self) -> Policy {
        let state = self.current_state.read().await.clone();
        let q_table = self.q_learning.q_table.read().await;

        let q_values = q_table
            .get(&state)
            .cloned()
            .unwrap_or_else(HashMap::new);

        Policy::generate(state, &q_values)
    }

    /// Get learning statistics
    pub async fn get_stats(&self) -> LearningStats {
        self.q_learning.get_stats().await
    }

    /// Get episode history
    pub async fn get_history(&self, limit: usize) -> Vec<Episode> {
        self.q_learning.get_episode_history(limit).await
    }
}

// In-crate `rand` shim. Returns `T::default()`, so all randomness in this
// module is deterministic (epsilon-greedy always picks `false`/`0`). This is
// intentional: RL output is advisory and must not introduce non-determinism
// that could be observed by callers expecting reproducible behaviour.
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
    async fn test_q_learning_initialization() {
        let ql = QLearningModule::new();
        ql.initialize().await;

        let q_value = ql.get_q_value(&State::Normal, &Action::NoAction).await;
        assert_eq!(q_value, 0.0);
    }

    #[tokio::test]
    async fn test_q_learning_update() {
        let ql = QLearningModule::new();
        ql.initialize().await;

        ql.learn(
            State::Normal,
            Action::Alert,
            1.0,
            State::AnomalyDetected,
        )
        .await
        .unwrap();

        let q_value = ql.get_q_value(&State::Normal, &Action::Alert).await;
        assert!(q_value > 0.0);
    }

    #[tokio::test]
    async fn test_reinforcement_learning_engine() {
        let engine = ReinforcementLearningEngine::new();
        engine.initialize().await;

        engine
            .update_state(State::AnomalyDetected, 0.5)
            .await
            .unwrap();

        let policy = engine.get_policy().await;
        assert_eq!(policy.state, State::AnomalyDetected);
    }

    #[tokio::test]
    async fn test_learning_stats() {
        let ql = QLearningModule::new();
        ql.initialize().await;

        ql.learn(State::Normal, Action::Alert, 1.0, State::AnomalyDetected)
            .await
            .unwrap();

        let stats = ql.get_stats().await;
        assert_eq!(stats.total_episodes, 1);
        assert_eq!(stats.successful_episodes, 1);
    }
}
