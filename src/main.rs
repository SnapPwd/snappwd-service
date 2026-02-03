use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Router,
};
use redis::Client;
use std::env;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

mod db;
mod handlers;
mod models;

#[derive(Clone)]
pub struct AppState {
    pub redis: Arc<Client>,
    pub max_file_size_bytes: usize,
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    // Configurable max file size (MB) - default 2MB
    let max_file_size_mb: usize = env::var("MAX_FILE_SIZE_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2);
    let max_file_size_bytes = max_file_size_mb * 1024 * 1024;

    tracing::info!("Connecting to Redis at {}", redis_url);
    tracing::info!("Max file size configured to {} MB", max_file_size_mb);

    let client = match db::get_redis_client(&redis_url).await {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!("Failed to connect to Redis: {}", e);
            return;
        }
    };

    let state = AppState {
        redis: client,
        max_file_size_bytes,
    };

    // Calculate body limit safely (max_file_size_bytes * 1.5 for base64 + JSON overhead)
    // Or just be generous with the transport limit since we validate logically in the handler.
    // Let's go with 2x to be safe, minimum 10MB.
    let body_limit = std::cmp::max(10 * 1024 * 1024, max_file_size_bytes * 2);

    let app = Router::new()
        .route("/v1/secrets", post(handlers::create_secret))
        .route("/v1/secrets/:id", get(handlers::get_secret))
        .route("/v1/files", post(handlers::create_file))
        .route("/v1/files/:id", get(handlers::get_file))
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(state)
        .layer(CorsLayer::permissive()) // Allow all CORS for now, can be tightened
        .layer(TraceLayer::new_for_http());

    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
