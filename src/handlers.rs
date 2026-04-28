use crate::{
    db,
    models::{
        EncryptedSecretResponse, ErrorResponse, FilePeekResponse, FileRequest, FileResponse,
        GetFileParams, GetSecretParams, ReceiptStatusRequest, SecretPeekResponse, SecretRequest,
        SecretResponse,
    },
    AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};

const MIN_EXPIRATION_SECONDS: u64 = 60;
const MAX_EXPIRATION_SECONDS: u64 = 2592000; // 30 days
const RECEIPT_INVALID_ERROR: &str = "Invalid receipt credentials";

const OPENAPI_SPEC: &str = include_str!("../openapi.yaml");

pub async fn openapi() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/yaml")], OPENAPI_SPEC)
}

pub async fn create_secret(
    State(state): State<AppState>,
    Json(payload): Json<SecretRequest>,
) -> Result<Json<SecretResponse>, (StatusCode, Json<ErrorResponse>)> {
    if payload.expiration < MIN_EXPIRATION_SECONDS || payload.expiration > MAX_EXPIRATION_SECONDS {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid expiration time".to_string(),
            }),
        ));
    }

    match db::store_secret(
        &state.redis,
        payload.encrypted_secret,
        payload.expiration,
        payload.metadata,
    )
    .await
    {
        Ok(created) => Ok(Json(SecretResponse {
            secret_id: created.secret_id,
            receipt_id: created.receipt_id,
            receipt_token: created.receipt_token,
        })),
        Err(e) => {
            tracing::error!("Redis error: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                }),
            ))
        }
    }
}

pub async fn get_secret(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<GetSecretParams>,
) -> impl IntoResponse {
    if !id.starts_with("sp-") && !id.starts_with("sps-") && !id.starts_with("spf-") {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Secret not found"})),
        )
            .into_response();
    }

    if params.peek {
        // Peek mode: return metadata without burning the secret
        match db::peek_secret(&state.redis, &id).await {
            Ok(Some((stored, ttl))) => Json(SecretPeekResponse {
                created_at: stored.created_at,
                ttl_seconds: ttl,
                metadata: stored.metadata,
            })
            .into_response(),
            Ok(None) => (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Secret not found or already accessed".to_string(),
                }),
            )
                .into_response(),
            Err(e) => {
                tracing::error!("Redis error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Internal server error".to_string(),
                    }),
                )
                    .into_response()
            }
        }
    } else {
        // Burn mode: retrieve and delete
        match db::get_secret(&state.redis, &id).await {
            Ok(Some(secret)) => Json(EncryptedSecretResponse {
                encrypted_secret: secret,
            })
            .into_response(),
            Ok(None) => (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Secret not found or already accessed".to_string(),
                }),
            )
                .into_response(),
            Err(e) => {
                tracing::error!("Redis error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Internal server error".to_string(),
                    }),
                )
                    .into_response()
            }
        }
    }
}

fn with_no_store(mut response: axum::response::Response) -> axum::response::Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn receipt_invalid_response() -> axum::response::Response {
    with_no_store(
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: RECEIPT_INVALID_ERROR.to_string(),
            }),
        )
            .into_response(),
    )
}

fn receipt_server_error_response() -> axum::response::Response {
    with_no_store(
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
            .into_response(),
    )
}

pub async fn receipt_status(
    State(state): State<AppState>,
    Path(receipt_id): Path<String>,
    Json(payload): Json<ReceiptStatusRequest>,
) -> impl IntoResponse {
    if !receipt_id.starts_with("spr-") || payload.receipt_token.is_empty() {
        return receipt_invalid_response();
    }

    match db::get_receipt_status(&state.redis, &receipt_id, &payload.receipt_token).await {
        Ok(Some(status)) => with_no_store(Json(status).into_response()),
        Ok(None) => receipt_invalid_response(),
        Err(e) => {
            tracing::error!("Redis error: {}", e);
            receipt_server_error_response()
        }
    }
}

pub async fn create_file(
    State(state): State<AppState>,
    Json(payload): Json<FileRequest>,
) -> Result<Json<FileResponse>, (StatusCode, Json<ErrorResponse>)> {
    if payload.expiration < MIN_EXPIRATION_SECONDS || payload.expiration > MAX_EXPIRATION_SECONDS {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid expiration time".to_string(),
            }),
        ));
    }

    // Validate size (approximate from base64 length)
    // Base64 size = (n * 4 / 3) approximately.
    // payload.encrypted_data.len() > max_bytes * 4 / 3
    if payload.encrypted_data.len() > (state.max_file_size_bytes * 4 / 3 + 4) {
        // +4 padding safety
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "File too large (max {}MB)",
                    state.max_file_size_bytes / 1024 / 1024
                ),
            }),
        ));
    }

    match db::store_file(
        &state.redis,
        payload.metadata,
        payload.encrypted_data,
        payload.expiration,
    )
    .await
    {
        Ok(id) => Ok(Json(FileResponse { file_id: id })),
        Err(e) => {
            tracing::error!("Redis error: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                }),
            ))
        }
    }
}

pub async fn get_file(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<GetFileParams>,
) -> impl IntoResponse {
    if !id.starts_with("spf-") {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "File not found"})),
        )
            .into_response();
    }

    if params.peek {
        // Peek mode: return metadata without burning the file
        match db::peek_file(&state.redis, &id).await {
            Ok(Some((stored, ttl))) => Json(FilePeekResponse {
                created_at: stored.created_at,
                ttl_seconds: ttl,
                metadata: stored.metadata,
            })
            .into_response(),
            Ok(None) => (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "File not found or already accessed".to_string(),
                }),
            )
                .into_response(),
            Err(e) => {
                tracing::error!("Redis error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Internal server error".to_string(),
                    }),
                )
                    .into_response()
            }
        }
    } else {
        // Burn mode: retrieve and delete
        match db::get_file(&state.redis, &id).await {
            Ok(Some(file)) => Json(file).into_response(),
            Ok(None) => (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "File not found or already accessed".to_string(),
                }),
            )
                .into_response(),
            Err(e) => {
                tracing::error!("Redis error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Internal server error".to_string(),
                    }),
                )
                    .into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        extract::DefaultBodyLimit,
        http::{Request, StatusCode},
        routing::post,
        Router,
    };
    use redis::Client;
    use std::sync::Arc;
    use tower::ServiceExt; // for `oneshot`

    // Helper to create a dummy state
    fn dummy_state() -> AppState {
        AppState {
            redis: Arc::new(Client::open("redis://127.0.0.1/").unwrap()),
            max_file_size_bytes: 2 * 1024 * 1024,
        }
    }

    #[tokio::test]
    async fn test_create_secret_invalid_expiration_low() {
        let state = dummy_state();
        let app = Router::new()
            .route("/api/v1/secrets", post(create_secret))
            .with_state(state);

        let payload = r#"{"encryptedSecret": "test", "expiration": 10}"#; // Too low
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/secrets")
            .header("content-type", "application/json")
            .body(Body::from(payload))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_secret_invalid_expiration_high() {
        let state = dummy_state();
        let app = Router::new()
            .route("/api/v1/secrets", post(create_secret))
            .with_state(state);

        let payload = r#"{"encryptedSecret": "test", "expiration": 10000000}"#; // Too high
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/secrets")
            .header("content-type", "application/json")
            .body(Body::from(payload))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_file_too_large() {
        let state = dummy_state();
        let app = Router::new()
            .route("/api/v1/files", post(create_file))
            .layer(DefaultBodyLimit::max(10 * 1024 * 1024)) // Increase limit for test
            .with_state(state);

        // Create a large string (base64) > 2MB (approx 2.7MB chars)
        let large_data = "a".repeat(3_000_000);
        let payload = serde_json::json!({
            "metadata": {
                "originalFilename": "large.txt",
                "contentType": "text/plain",
                "iv": "iv"
            },
            "encryptedData": large_data,
            "expiration": 3600
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/files")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_file_invalid_id_returns_404() {
        use axum::routing::get;

        let state = dummy_state();
        let app = Router::new()
            .route("/api/v1/files/{id}", get(get_file))
            .with_state(state);

        // Invalid prefix (not spf-)
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/files/invalid-id")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_file_with_peek_param_invalid_id_returns_404() {
        use axum::routing::get;

        let state = dummy_state();
        let app = Router::new()
            .route("/api/v1/files/{id}", get(get_file))
            .with_state(state);

        // Invalid prefix with peek=true
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/files/invalid-id?peek=true")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_receipt_status_invalid_id_is_generic_no_store() {
        let state = dummy_state();
        let app = Router::new()
            .route("/api/v1/receipts/:receipt_id/status", post(receipt_status))
            .with_state(state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/receipts/not-a-receipt/status")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"receiptToken":"spt-token"}"#))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }

    #[tokio::test]
    async fn test_receipt_status_empty_token_is_generic_no_store() {
        let state = dummy_state();
        let app = Router::new()
            .route("/api/v1/receipts/:receipt_id/status", post(receipt_status))
            .with_state(state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/receipts/spr-receipt/status")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"receiptToken":""}"#))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }
}
