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
mod notifications;
mod protection;

#[derive(Clone)]
pub struct AppState {
    pub notifier: Option<Arc<notifications::Notifier>>,
    pub redis: Arc<Client>,
    pub max_file_size_bytes: usize,
    pub protection: protection::Config,
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

    // Redis URLs may contain credentials; never include them in logs.
    tracing::info!("Initializing Redis client");
    tracing::info!("Max file size configured to {} MB", max_file_size_mb);

    let client = match db::get_redis_client(&redis_url).await {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!(error_kind = ?e.kind(), "Failed to initialize Redis client");
            return;
        }
    };

    let notifier = notifications::Notifier::from_env()
        .expect("Invalid SMTP configuration")
        .map(Arc::new);
    let state = AppState {
        notifier,
        redis: client,
        max_file_size_bytes,
        protection: protection::Config::from_env(),
    };

    let app = build_app(state);

    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .unwrap();
}

fn build_app(state: AppState) -> Router {
    // Allow base64 and JSON overhead for files; secrets have a separate limit.
    let body_limit = std::cmp::max(10 * 1024 * 1024, state.max_file_size_bytes * 2);

    write_routes()
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            protection::guard,
        ))
        .route("/openapi.yaml", get(handlers::openapi))
        .route("/v1/secrets/:id", get(handlers::get_secret))
        .route("/v1/files/:id", get(handlers::get_file))
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(state)
        .layer(CorsLayer::permissive()) // Allow all CORS for now, can be tightened
        .layer(TraceLayer::new_for_http())
}

#[cfg(test)]
mod notification_tests;

fn write_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/secrets",
            post(handlers::create_secret)
                .layer(DefaultBodyLimit::max(handlers::MAX_SECRET_BODY_BYTES)),
        )
        .route("/v1/files", post(handlers::create_file))
}
