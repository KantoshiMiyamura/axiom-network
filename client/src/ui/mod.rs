//! Terminal UI components

use crate::config::ClientConfig;
use crossterm::event::KeyEvent;
use ratatui::Frame;

/// Main application UI
pub struct App {
    pub config: ClientConfig,
    pub current_tab: usize,
    pub selected_item: usize,
}

impl App {
    /// Create new app UI
    pub fn new(config: ClientConfig) -> Self {
        App {
            config,
            current_tab: 0,
            selected_item: 0,
        }
    }

    /// Switch to next tab
    pub fn next_tab(&mut self) {
        self.current_tab = (self.current_tab + 1) % 4; // 4 tabs
    }

    /// Switch to previous tab
    pub fn prev_tab(&mut self) {
        if self.current_tab == 0 {
            self.current_tab = 3;
        } else {
            self.current_tab -= 1;
        }
    }

    /// Move to next item in list
    pub fn next_item(&mut self) {
        self.selected_item = self.selected_item.saturating_add(1);
    }

    /// Move to previous item in list
    pub fn previous_item(&mut self) {
        self.selected_item = self.selected_item.saturating_sub(1);
    }

    /// Select current item
    pub async fn select_item(&mut self) {
        // Selection handling depends on the active tab and available items.
        // The TUI event loop should dispatch to the appropriate handler.
    }

    /// Reset state
    pub fn reset(&mut self) {
        self.selected_item = 0;
    }

    /// Handle key input
    pub fn handle_key(&mut self, _key: KeyEvent) {
        // Key handling is dispatched by the TUI event loop in main.
    }
}

/// Draw the UI frame.
///
/// Layout:
/// - Header with connection status and user info
/// - Tab bar (Messages, Jobs, Disputes, Settings)
/// - Main content area
/// - Footer with help text
pub fn draw(_f: &mut Frame, _app: &App) {
    // Rendering is handled by the ratatui widget tree.
    // Each tab composes its own widgets and passes them to `f.render_widget()`.
    // This stub is called from the main event loop.
}
