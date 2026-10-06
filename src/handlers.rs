use crate::{
    db,
    models::{
        EncryptedFileResponse, EncryptedSecretResponse, ErrorResponse, FilePeekResponse,
        FileRequest, FileResponse, GetFileParams, GetSecretParams, SecretPeekResponse,
        SecretRequest, SecretResponse,
    },
    AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};

// 1.5 MiB: matches the web app's bound on the base64-encoded ciphertext of a
// 1 MiB plaintext secret.
pub const MAX_SECRET_SIZE_BYTES: usize = 1024 * 1024 * 3 / 2;
pub const MAX_SECRET_BODY_BYTES: usize = 2 * 1024 * 1024;

const MIN_EXPIRATION_SECONDS: u64 = 60;
const MAX_EXPIRATION_SECONDS: u64 = 2592000; // 30 days

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

    if payload.encrypted_secret.len() > MAX_SECRET_SIZE_BYTES {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Secret too large (max {MAX_SECRET_SIZE_BYTES} UTF-8 bytes)"),
            }),
        ));
    }

    let sender_email = match crate::notifications::normalize_email(payload.sender_email) {
        Ok(email) => email,
        Err(()) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid notification email".to_string(),
                }),
            ))
        }
    };
    if sender_email.is_some() && state.notifier.is_none() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Email notifications are unavailable".to_string(),
            }),
        ));
    }

    match db::store_secret(
        &state.redis,
        payload.encrypted_secret,
        payload.expiration,
        payload.metadata,
        sender_email,
    )
    .await
    {
        Ok(id) => Ok(Json(SecretResponse { secret_id: id })),
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
    if !id.starts_with("sps-") {
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
            Ok(Some(secret)) => {
                if let (Some(email), Some(notifier)) = (&secret.sender_email, &state.notifier) {
                    if notifier.send(email, &id).await.is_err() {
                        tracing::warn!("Reveal notification delivery failed");
                    }
                }
                Json(EncryptedSecretResponse {
                    encrypted_secret: secret.encrypted_secret,
                })
                .into_response()
            }
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

    let sender_email = match crate::notifications::normalize_email(payload.sender_email) {
        Ok(email) => email,
        Err(()) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid notification email".to_string(),
                }),
            ))
        }
    };
    if sender_email.is_some() && state.notifier.is_none() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Email notifications are unavailable".to_string(),
            }),
        ));
    }

    match db::store_file(
        &state.redis,
        payload.metadata,
        payload.encrypted_data,
        payload.expiration,
        sender_email,
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
            Ok(Some(file)) => {
                if let (Some(email), Some(notifier)) = (&file.sender_email, &state.notifier) {
                    if notifier.send(email, &id).await.is_err() {
                        tracing::warn!("File reveal notification delivery failed");
                    }
                }
                Json(EncryptedFileResponse {
                    metadata: file.metadata,
                    encrypted_data: file.encrypted_data,
                    created_at: file.created_at,
                })
                .into_response()
            }
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
            notifier: None,
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
    async fn test_create_secret_size_limits() {
        // Exercise the production router, including its endpoint body limit.
        for encrypted_secret in [
            "a".repeat(MAX_SECRET_SIZE_BYTES + 1),
            "é".repeat(MAX_SECRET_SIZE_BYTES / 2 + 1),
        ] {
            let app = crate::build_app(dummy_state());
            let payload = serde_json::json!({
                "encryptedSecret": encrypted_secret, "expiration": 3600
            });
            let req = Request::builder()
                .method("POST")
                .uri("/v1/secrets")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap();
            let response = app.oneshot(req).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(error["error"]
                .as_str()
                .unwrap()
                .starts_with("Secret too large"));
        }
    }

    #[tokio::test]
    async fn test_create_secret_at_size_limit_not_rejected() {
        // The largest ciphertext the web app sends must pass both size checks;
        // without Redis the request then fails on storage instead.
        let app = crate::build_app(dummy_state());
        let payload = serde_json::json!({
            "encryptedSecret": "a".repeat(MAX_SECRET_SIZE_BYTES), "expiration": 3600
        });
        let req = Request::builder()
            .method("POST")
            .uri("/v1/secrets")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_ne!(response.status(), StatusCode::BAD_REQUEST);
        assert_ne!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_secret_body_limit_with_large_file_setting() {
        let mut state = dummy_state();
        state.max_file_size_bytes = 20 * 1024 * 1024;
        let app = crate::build_app(state);
        let req = Request::builder()
            .method("POST")
            .uri("/v1/secrets")
            .header("content-type", "application/json")
            .body(Body::from(" ".repeat(MAX_SECRET_BODY_BYTES + 1)))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
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
    async fn test_create_secret_rejects_oversized_metadata_before_storage() {
        let app = Router::new()
            .route("/v1/secrets", post(create_secret))
            .with_state(dummy_state());
        let payload = serde_json::json!({
            "encryptedSecret": "abc", "expiration": 3600,
            "metadata": {"note": "\0".repeat(700)}
        });
        let req = Request::builder()
            .method("POST")
            .uri("/v1/secrets")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}
