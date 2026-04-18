//! Client application state

use axiom_community_shared::models::UserInfo;

/// User session state
pub struct SessionState {
    /// Current session ID
    pub session_id: String,
    /// JWT token
    pub session_token: String,
    /// User information
    pub user: UserInfo,
}

/// Application state
pub struct AppState {
    /// Current session (if logged in)
    pub session: Option<SessionState>,
    /// Current selected channel
    pub current_channel: String,
    /// Messages loaded for current channel
    pub messages: Vec<Message>,
    /// Jobs loaded
    pub jobs: Vec<Job>,
}

/// Message in channel
#[derive(Clone)]
pub struct Message {
    pub id: String,
    pub author: String,
    pub content: String,
    pub timestamp: i64,
}

/// Job posting
#[derive(Clone)]
pub struct Job {
    pub id: String,
    pub title: String,
    pub requester: String,
    pub reward_sat: u64,
}

impl AppState {
    /// Create new application state
    pub fn new() -> Self {
        AppState {
            session: None,
            current_channel: "general".to_string(),
            messages: vec![],
            jobs: vec![],
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
