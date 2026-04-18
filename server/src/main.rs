// The community platform defines many model/API structures and permission
// functions that are wired incrementally. Suppress dead_code warnings for
// fields/methods that are part of the API surface but not yet consumed.
#![allow(dead_code)]

//! Axiom Community Platform Server
//!
//! A secure, production-grade community platform with:
//! - Challenge-response authentication with ML-DSA-87 signatures
//! - Role-based access control (5 levels: Member → CoreDev)
//! - Rate limiting (per-IP, per-session, per-channel)
//! - Job coordination and dispute resolution
//! - Moderation and audit logging
//! - Off-chain messaging with on-chain identity

use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Router,
    middleware as axum_middleware,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;

mod auth;
mod config;
mod db;
mod error;
mod handlers;
mod middleware;
mod permissions;
mod rate_limit;
mod reputation;
mod state;

use config::Config;
use db::Database;
use state::AppState;

/// Application entry point
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    init_tracing();

    // Load configuration
    let config = Config::from_env()?;
    info!("Loaded configuration: {} environment", config.environment);

    // Initialize database
    let db = Database::new(&config).await?;
    // Redact credentials from database URL in log output
    let redacted_url = redact_db_url(&config.database_url);
    info!("Connected to database at {}", redacted_url);

    // Run migrations
    db.run_migrations().await?;
    info!("Migrations completed successfully");

    // Create application state
    let state = Arc::new(AppState::new(db, config.clone())?);

    // Build router
    let app = build_router(state);

    // Start server
    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Build Axum router with all routes
fn build_router(state: Arc<AppState>) -> Router {
    let protected_routes = Router::new()
        // User endpoints
        .route("/users/:address", get(handlers::users::get_user))
        .route("/users/:address/reputation", get(handlers::users::get_reputation))
        // Message endpoints
        .route("/channels/:channel/messages", get(handlers::messages::list_messages))
        .route("/channels/:channel/messages", post(handlers::messages::post_message))
        .route("/messages/:id", get(handlers::messages::get_message))
        // Job endpoints
        .route("/jobs", get(handlers::jobs::list_jobs))
        .route("/jobs", post(handlers::jobs::create_job))
        .route("/jobs/:id", get(handlers::jobs::get_job))
        .route("/jobs/:id/results", post(handlers::jobs::submit_result))
        // Dispute endpoints
        .route("/disputes", get(handlers::disputes::list_disputes))
        .route("/disputes", post(handlers::disputes::file_dispute))
        .route("/disputes/:id", get(handlers::disputes::get_dispute))
        // Moderation endpoints (requires Moderator+ role)
        .route("/moderation/actions", post(handlers::moderation::create_action))
        .route("/moderation/actions", get(handlers::moderation::list_actions))
        // Audit endpoints (requires CoreDev role)
        .route("/audit/logs", get(handlers::audit::list_audit_logs))
        // Role management endpoints (requires CoreDev role)
        .route("/roles/:address/grant/:role", post(handlers::roles::grant_role))
        .route("/roles/:address/revoke/:role", post(handlers::roles::revoke_role))
        .route("/roles/:address/ban", post(handlers::roles::ban_user))
        .route("/roles/:address/unban", post(handlers::roles::unban_user))
        // Axum executes layers in reverse order: last .layer() = outermost (runs first).
        // permission_middleware must run AFTER auth_middleware (needs UserContext),
        // so permission_middleware is added first (inner) and auth_middleware second (outer).
        .layer(
            axum_middleware::from_fn(
                crate::middleware::permissions::permission_middleware,
            )
        )
        .layer(
            axum_middleware::from_fn_with_state(
                state.clone(),
                crate::middleware::auth::auth_middleware,
            )
        )
        .with_state(state.clone());

    Router::new()
        // Health check (public)
        .route("/health", get(handlers::health::health_check))
        // Authentication endpoints (public)
        .route("/auth/challenge", post(handlers::auth::request_challenge))
        .route("/auth/verify", post(handlers::auth::verify_signature))
        .route("/auth/refresh", post(handlers::auth::refresh_token))
        .route("/auth/logout", post(handlers::auth::logout))
        // Protected routes with middleware
        .merge(protected_routes)
        // Global middleware (Axum reverse order: last = outermost = runs first)
        // Inner → outer: trace → CORS → body limit → security (IP ban + global rate limit) → HTTPS
        .layer(TraceLayer::new_for_http())
        .layer(build_cors_layer(&state.config))
        .layer(DefaultBodyLimit::max(1024 * 1024)) // 1MB max request body
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::security::security_middleware,
        ))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::security::https_enforcement_middleware,
        ))
        .with_state(state)
}

/// Redact credentials from a database URL for safe logging.
fn redact_db_url(url: &str) -> String {
    // postgres://user:password@host:port/db → postgres://***@host:port/db
    if let Some(at_pos) = url.find('@') {
        if let Some(scheme_end) = url.find("://") {
            return format!("{}://***{}", &url[..scheme_end], &url[at_pos..]);
        }
    }
    "***redacted***".to_string()
}

/// Build CORS layer from configuration — never permissive.
fn build_cors_layer(config: &config::Config) -> CorsLayer {
    use axum::http::{HeaderValue, Method};

    let allowed_methods = vec![Method::GET, Method::POST, Method::OPTIONS];
    let allowed_headers = vec![
        axum::http::header::AUTHORIZATION,
        axum::http::header::CONTENT_TYPE,
        axum::http::header::ACCEPT,
    ];

    if config.cors_allowed_origins.is_empty() {
        // Default: localhost-only (dev and staging)
        CorsLayer::new()
            .allow_origin(AllowOrigin::predicate(
                |origin: &HeaderValue, _| {
                    origin.as_bytes().starts_with(b"http://localhost")
                        || origin.as_bytes().starts_with(b"http://127.0.0.1")
                        || origin.as_bytes().starts_with(b"https://localhost")
                        || origin.as_bytes().starts_with(b"https://127.0.0.1")
                },
            ))
            .allow_methods(allowed_methods)
            .allow_headers(allowed_headers)
    } else {
        // Production: explicit origin list from CORS_ALLOWED_ORIGINS env var
        let origins: Vec<HeaderValue> = config
            .cors_allowed_origins
            .iter()
            .filter_map(|o| o.parse::<HeaderValue>().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods(allowed_methods)
            .allow_headers(allowed_headers)
    }
}

/// Initialize tracing and logging
fn init_tracing() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("axiom_community_server=info")),
        )
        .with(
            fmt::layer()
                .with_writer(std::io::stdout)
                .with_target(true)
                .with_thread_ids(true)
                .with_line_number(true),
        )
        .init();

    info!("Tracing initialized");
}
