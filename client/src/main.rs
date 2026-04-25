#![allow(dead_code)]
//! Axiom Community Platform CLI/TUI Client
//!
//! A secure terminal-native community client with:
//! - Challenge-response authentication with local key signing
//! - Private keys never leave the client
//! - Off-chain messaging and job coordination
//! - Role-based features (Member → CoreDev)
//! - Clean, intuitive TUI

use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    Terminal,
};
use std::error::Error;
use std::io;
use tracing::info;

mod api;
mod cli;
mod config;
mod error;
mod state;
mod ui;

use config::ClientConfig;
use ui::App;

/// CLI entry point
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize tracing
    init_tracing();

    print_experimental_banner();

    // Load configuration
    let config = ClientConfig::from_env()?;
    info!("Loaded client configuration");

    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();

    // Handle CLI mode vs. TUI mode
    if args.len() > 1 {
        // CLI mode for one-off commands
        handle_cli(&config, &args[1..]).await?;
    } else {
        // TUI mode for interactive use
        run_tui(&config).await?;
    }

    Ok(())
}

/// Run TUI interactive mode
async fn run_tui(config: &ClientConfig) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let mut app = App::new(config.clone());

    // Run the TUI
    let result = run_app(&mut terminal, &mut app).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(e) = result {
        eprintln!("Error: {}", e);
    }

    Ok(())
}

/// Main application loop for TUI
async fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<(), Box<dyn Error>> {
    loop {
        // Draw UI
        terminal.draw(|f| ui::draw(f, app))?;

        // Handle input
        if crossterm::event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => {
                        // Quit
                        return Ok(());
                    }
                    KeyCode::Tab => {
                        // Switch tab
                        app.next_tab();
                    }
                    KeyCode::BackTab => {
                        // Previous tab
                        app.prev_tab();
                    }
                    KeyCode::Up => {
                        app.previous_item();
                    }
                    KeyCode::Down => {
                        app.next_item();
                    }
                    KeyCode::Enter => {
                        app.select_item().await;
                    }
                    KeyCode::Esc => {
                        app.reset();
                    }
                    _ => {
                        // Pass other keys to app
                        app.handle_key(key);
                    }
                }
            }
        }
    }
}

/// Handle CLI mode (one-off commands)
async fn handle_cli(config: &ClientConfig, args: &[String]) -> Result<()> {
    let command = &args[0];

    match command.as_str() {
        "login" => {
            cli::login(config).await?;
        }
        "post" => {
            // axiom-community post <channel> <message>
            if args.len() < 3 {
                eprintln!("Usage: axiom-community post <channel> <message>");
                return Ok(());
            }
            cli::post(config, &args[1], &args[2]).await?;
        }
        "messages" => {
            // axiom-community messages <channel>
            if args.len() < 2 {
                eprintln!("Usage: axiom-community messages <channel>");
                return Ok(());
            }
            cli::list_messages(config, &args[1]).await?;
        }
        "jobs" => {
            cli::list_jobs(config).await?;
        }
        "create-job" => {
            if args.len() < 2 {
                eprintln!("Usage: axiom-community create-job <json-file>");
                return Ok(());
            }
            cli::create_job(config, &args[1]).await?;
        }
        "version" => {
            println!("Axiom Community Client v{}", env!("CARGO_PKG_VERSION"));
        }
        "help" => {
            print_help();
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            print_help();
        }
    }

    Ok(())
}

/// Print help message
fn print_help() {
    println!("Axiom Community Platform CLI");
    println!();
    println!("USAGE:");
    println!("    axiom-community [COMMAND] [ARGS]");
    println!();
    println!("COMMANDS:");
    println!("    login                 Start interactive TUI (default)");
    println!("    post <channel> <msg>  Post message to channel");
    println!("    messages <channel>    List messages in channel");
    println!("    jobs                  List available jobs");
    println!("    create-job <file>     Create new job from JSON");
    println!("    version               Show version");
    println!("    help                  Show this help");
    println!();
    println!("Running without arguments starts interactive TUI mode.");
}

/// Warn the operator that this binary is not part of the testnet release.
fn print_experimental_banner() {
    eprintln!(
        "WARNING: axiom-community client is EXPERIMENTAL and not part of \
         the v{} testnet release. The TUI is a skeleton and most features \
         are not yet wired. See docs/MODULES.md.",
        env!("CARGO_PKG_VERSION")
    );
}

/// Initialize tracing and logging
fn init_tracing() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("axiom_community_client=info")),
        )
        .with(
            fmt::layer()
                .with_writer(std::io::stderr)
                .with_target(true)
                .with_thread_ids(false)
                .with_line_number(false),
        )
        .init();

    info!("Client tracing initialized");
}
