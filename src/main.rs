use axum::{
    extract::DefaultBodyLimit,
    http::{header, HeaderValue, Method},
    routing::{get, post},
    Router,
};
use redis::Client;
use std::env;
use std::sync::Arc;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

/// Default CORS allow-list used when `CORS_ALLOWED_ORIGINS` is unset.
/// The hosted product works out of the box; self-hosters override via the env var.
const DEFAULT_ALLOWED_ORIGINS: &str = "https://snappwd.io";

/// Parsed result of the `CORS_ALLOWED_ORIGINS` configuration.
enum CorsOrigins {
    /// Explicit opt-in (`CORS_ALLOWED_ORIGINS=*`): allow any origin.
    Any,
    /// Fail-closed allow-list of exact origins.
    List(Vec<HeaderValue>),
}

/// Parse a comma-separated origin list. `*` is an explicit opt-in for "any
/// origin"; anything else becomes a fail-closed allow-list of exact origins.
/// Blank/invalid entries are dropped (an all-invalid list denies everything).
fn parse_cors_origins(raw: &str) -> CorsOrigins {
    if raw.trim() == "*" {
        return CorsOrigins::Any;
    }

    let origins = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| match HeaderValue::from_str(s) {
            Ok(v) => Some(v),
            Err(_) => {
                tracing::warn!("Ignoring invalid CORS origin: {}", s);
                None
            }
        })
        .collect();

    CorsOrigins::List(origins)
}

/// Build the CORS layer from `CORS_ALLOWED_ORIGINS`, scoped to the methods and
/// headers the API actually uses. Defaults to a fail-closed allow-list — never
/// permissive — so an operator who forgets to configure it does not silently
/// expose the API to every origin.
fn build_cors_layer() -> CorsLayer {
    let raw =
        env::var("CORS_ALLOWED_ORIGINS").unwrap_or_else(|_| DEFAULT_ALLOWED_ORIGINS.to_string());

    let base = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE]);

    match parse_cors_origins(&raw) {
        CorsOrigins::Any => {
            tracing::warn!(
                "CORS_ALLOWED_ORIGINS=* — allowing any origin. Not recommended for production."
            );
            base.allow_origin(AllowOrigin::any())
        }
        CorsOrigins::List(origins) => {
            tracing::info!("CORS allowed origins: {:?}", origins);
            base.allow_origin(AllowOrigin::list(origins))
        }
    }
}

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
        .route("/openapi.yaml", get(handlers::openapi))
        .route("/v1/secrets", post(handlers::create_secret))
        .route("/v1/secrets/:id", get(handlers::get_secret))
        .route("/v1/files", post(handlers::create_file))
        .route("/v1/files/:id", get(handlers::get_file))
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(state)
        .layer(build_cors_layer())
        .layer(TraceLayer::new_for_http());

    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(raw: &str) -> Vec<HeaderValue> {
        match parse_cors_origins(raw) {
            CorsOrigins::List(v) => v,
            CorsOrigins::Any => panic!("expected a list, got Any"),
        }
    }

    #[test]
    fn star_is_explicit_any() {
        assert!(matches!(parse_cors_origins("*"), CorsOrigins::Any));
        assert!(matches!(parse_cors_origins("  *  "), CorsOrigins::Any));
    }

    #[test]
    fn single_origin_parses() {
        assert_eq!(list("https://snappwd.io"), ["https://snappwd.io"]);
    }

    #[test]
    fn multiple_origins_are_trimmed_and_split() {
        assert_eq!(
            list("https://snappwd.io, https://www.snappwd.io"),
            ["https://snappwd.io", "https://www.snappwd.io"]
        );
    }

    #[test]
    fn blank_and_invalid_entries_are_dropped() {
        // Empty entries and a header value with a control char are skipped;
        // a fully empty/invalid config yields an empty (deny-all) list.
        assert_eq!(list("https://a.io, ,bad\norigin"), ["https://a.io"]);
        assert!(list("").is_empty());
        assert!(list("   ").is_empty());
    }
}
