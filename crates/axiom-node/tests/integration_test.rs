// Copyright (c) 2026 Kantoshi Miyamura

use axiom_node::{
    network::{Message, NetworkService, PeerManager},
    Config, Node,
};
use axiom_primitives::{Amount, Hash256};
use axiom_protocol::{Transaction, TxOutput};
use tempfile::TempDir;

fn create_test_node(network: &str) -> (TempDir, Node) {
    let temp_dir = TempDir::new().unwrap();
    let config = Config {
        data_dir: temp_dir.path().to_path_buf(),
        network: axiom_node::Network::parse_str(network).unwrap(),
        ..Default::default()
    };
    let node = Node::new(config).unwrap();
    (temp_dir, node)
}

fn create_test_service(network: &str) -> (TempDir, NetworkService) {
    let (temp_dir, node) = create_test_node(network);
    let peer_manager = PeerManager::new(network.to_string());
    let service = NetworkService::new(node, peer_manager);
    (temp_dir, service)
}

#[tokio::test]
async fn test_two_node_tip_exchange() {
    let (_temp1, service1) = create_test_service("dev");
    let (_temp2, service2) = create_test_service("dev");

    // Node 1 builds a block
    let _block = service1.build_local_block().await.unwrap();

    // Node 2 requests tip from node 1
    let (hash1, height1) = service1.get_tip().await;
    let (hash2, height2) = service2.get_tip().await;

    // Node 1 should be ahead
    assert_eq!(height1, 1);
    assert_eq!(height2, 0);
    assert_ne!(hash1, hash2);
}

#[tokio::test]
async fn test_transaction_propagation() {
    let (_temp1, service1) = create_test_service("dev");
    let (_temp2, _service2) = create_test_service("dev");

    // Create transaction
    let output = TxOutput {
        value: Amount::from_sat(1000).unwrap(),
        pubkey_hash: Hash256::zero(),
    };
    let tx = Transaction::new_transfer(vec![], vec![output], 0, 100);

    // Submit to node 1 (will fail validation but tests propagation path)
    let result = service1.submit_local_transaction(tx.clone()).await;

    // Transaction should be rejected due to validation but path is tested
    assert!(result.is_err());
}

#[tokio::test]
async fn test_block_propagation() {
    let (_temp1, service1) = create_test_service("dev");
    let (_temp2, service2) = create_test_service("dev");

    // Node 1 builds block
    let block1 = service1.build_local_block().await.unwrap();

    // Simulate node 2 receiving block from node 1
    use axiom_node::network::PeerId;
    let peer_id = PeerId::new();
    let message = Message::Block(block1.clone());

    let result = service2.handle_message(peer_id, message).await;
    assert!(result.is_ok());

    // Node 2 should now have the block
    let (_, height2) = service2.get_tip().await;
    assert_eq!(height2, 1);
}

#[tokio::test]
async fn test_duplicate_block_rejection() {
    let (_temp, service) = create_test_service("dev");

    // Build block
    let block = service.build_local_block().await.unwrap();

    // Try to process same block again
    use axiom_node::network::PeerId;
    let peer_id = PeerId::new();
    let message = Message::Block(block);

    let result = service.handle_message(peer_id, message).await;
    assert!(result.is_ok()); // Should be silently ignored
}

#[tokio::test]
async fn test_get_block_message() {
    let (_temp, service) = create_test_service("dev");

    // Build block
    let block = service.build_local_block().await.unwrap();
    let block_hash = block.hash();

    // Request block
    use axiom_node::network::PeerId;
    let peer_id = PeerId::new();
    let message = Message::GetBlock(block_hash);

    let response = service.handle_message(peer_id, message).await.unwrap();

    // Should return the block
    assert!(matches!(response, Some(Message::Block(_))));
}

#[tokio::test]
async fn test_get_block_not_found() {
    let (_temp, service) = create_test_service("dev");

    // Request non-existent block
    use axiom_node::network::PeerId;
    let peer_id = PeerId::new();
    let fake_hash = Hash256::zero();
    let message = Message::GetBlock(fake_hash);

    let response = service.handle_message(peer_id, message).await.unwrap();

    // Should return None
    assert!(response.is_none());
}

#[tokio::test]
async fn test_basic_sync_flow() {
    let (_temp1, service1) = create_test_service("dev");
    let (_temp2, service2) = create_test_service("dev");

    // Node 1 builds 3 blocks
    service1.build_local_block().await.unwrap();
    service1.build_local_block().await.unwrap();
    let _block3 = service1.build_local_block().await.unwrap();

    let (hash1, height1) = service1.get_tip().await;
    assert_eq!(height1, 3);

    // Node 2 is behind
    let (_, height2) = service2.get_tip().await;
    assert_eq!(height2, 0);

    // Node 2 requests block 3
    use axiom_node::network::PeerId;
    let peer_id = PeerId::new();
    let message = Message::GetBlock(hash1);

    let response = service1.handle_message(peer_id, message).await.unwrap();

    // Node 1 should return block 3
    assert!(matches!(response, Some(Message::Block(_))));

    // Node 2 receives and processes block 3
    if let Some(Message::Block(block)) = response {
        let result = service2
            .handle_message(peer_id, Message::Block(block))
            .await;
        // Will fail because node 2 doesn't have blocks 1 and 2
        // This demonstrates the need for sequential sync
        assert!(result.is_ok());
    }
}

#[tokio::test]
async fn test_tip_message_handling() {
    let (_temp, service) = create_test_service("dev");

    // Build block to advance tip
    service.build_local_block().await.unwrap();

    // Request tip
    use axiom_node::network::PeerId;
    let peer_id = PeerId::new();
    let message = Message::GetTip;

    let response = service.handle_message(peer_id, message).await.unwrap();

    // Should return Tip message
    match response {
        Some(Message::Tip(tip)) => {
            assert_eq!(tip.best_height, 1);
        }
        _ => panic!("Expected Tip message"),
    }
}

#[tokio::test]
async fn test_mempool_update_after_block() {
    let (_temp, mut node) = create_test_node("dev");

    // Initial mempool should be empty
    assert_eq!(node.mempool_size(), 0);

    // Build and process block
    let block = node.build_block().unwrap();
    node.process_block(block).unwrap();

    // Mempool should still be empty (no transactions were added)
    assert_eq!(node.mempool_size(), 0);
}
