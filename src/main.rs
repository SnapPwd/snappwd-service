use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Router,
};
use std::env;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tower_http::cors::CorsLayer;

mod db;
mod handlers;
mod models;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    
    tracing::info!("Connecting to Redis at {}", redis_url);
    
    let client = match db::get_redis_client(&redis_url).await {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!("Failed to connect to Redis: {}", e);
            return;
        }
    };

    let app = Router::new()
        .route("/api/v1/secrets", post(handlers::create_secret))
        .route("/api/v1/secrets/:id", get(handlers::get_secret))
        .route("/api/v1/files", post(handlers::create_file))
        .route("/api/v1/files/:id", get(handlers::get_file))
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024)) // 10MB limit for base64 overhead
        .with_state(client)
        .layer(CorsLayer::permissive()) // Allow all CORS for now, can be tightened
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
