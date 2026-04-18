// Copyright (c) 2026 Kantoshi Miyamura
// AxiomMind v2 - Distributed Neural Network

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

/// Lightweight neural model for anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeuralModel {
    pub weights: Vec<f64>,
    pub biases: Vec<f64>,
    pub accuracy: f64,
}

impl NeuralModel {
    pub fn new(input_size: usize, hidden_size: usize, output_size: usize) -> Self {
        NeuralModel {
            weights: vec![0.1; input_size * hidden_size + hidden_size * output_size],
            biases: vec![0.0; hidden_size + output_size],
            accuracy: 0.0,
        }
    }

    /// Forward pass through neural network
    pub fn infer(&self, input: &[f64]) -> f64 {
        // Simple 2-layer network
        let hidden_size = 16;
        let mut hidden = vec![0.0; hidden_size];

        // Input to hidden layer
        for i in 0..hidden_size {
            for j in 0..input.len() {
                hidden[i] += input[j] * self.weights[j * hidden_size + i];
            }
            hidden[i] += self.biases[i];
            hidden[i] = hidden[i].max(0.0); // ReLU activation
        }

        // Hidden to output layer
        let mut output = 0.0;
        for i in 0..hidden_size {
            output += hidden[i] * self.weights[input.len() * hidden_size + i];
        }
        output += self.biases[hidden_size];

        // Sigmoid activation
        1.0 / (1.0 + (-output).exp())
    }

    /// Update weights based on gradient
    pub fn update(&mut self, gradient: &[f64], learning_rate: f64) {
        for i in 0..self.weights.len() {
            self.weights[i] -= learning_rate * gradient[i];
        }
    }
}

/// Distributed Neural Network across all nodes
pub struct DistributedNeuralNetwork {
    pub node_id: String,
    pub local_model: Arc<RwLock<NeuralModel>>,
    pub peer_models: Arc<RwLock<HashMap<String, NeuralModel>>>,
    pub consensus_threshold: f64,
}

impl DistributedNeuralNetwork {
    pub fn new(node_id: String, input_size: usize) -> Self {
        DistributedNeuralNetwork {
            node_id,
            local_model: Arc::new(RwLock::new(NeuralModel::new(input_size, 16, 1))),
            peer_models: Arc::new(RwLock::new(HashMap::new())),
            consensus_threshold: 0.66, // 2/3 majority
        }
    }

    /// Detect anomaly with local model
    pub async fn detect_anomaly_local(&self, data: &[f64]) -> f64 {
        let model = self.local_model.read().await;
        model.infer(data)
    }

    /// Aggregate scores from peers for consensus
    pub async fn aggregate_peer_scores(&self, local_score: f64, peer_scores: Vec<f64>) -> f64 {
        let mut all_scores = vec![local_score];
        all_scores.extend(peer_scores);

        // Weighted average (local score has higher weight)
        let local_weight = 0.5;
        let peer_weight = 0.5 / (all_scores.len() - 1) as f64;

        let mut weighted_sum = local_score * local_weight;
        for score in &all_scores[1..] {
            weighted_sum += score * peer_weight;
        }

        weighted_sum
    }

    /// Update model with new training data
    pub async fn update_model(&self, gradient: &[f64], learning_rate: f64) {
        let mut model = self.local_model.write().await;
        model.update(gradient, learning_rate);
    }

    /// Sync model with peers
    pub async fn sync_with_peers(&self, peer_models: HashMap<String, NeuralModel>) {
        let mut peers = self.peer_models.write().await;
        *peers = peer_models;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_neural_model_inference() {
        let model = NeuralModel::new(5, 16, 1);
        let input = vec![0.1, 0.2, 0.3, 0.4, 0.5];
        let output = model.infer(&input);
        assert!(output >= 0.0 && output <= 1.0);
    }

    #[tokio::test]
    async fn test_distributed_network() {
        let dnn = DistributedNeuralNetwork::new("node1".to_string(), 5);
        let input = vec![0.1, 0.2, 0.3, 0.4, 0.5];
        let score = dnn.detect_anomaly_local(&input).await;
        assert!(score >= 0.0 && score <= 1.0);
    }
}
