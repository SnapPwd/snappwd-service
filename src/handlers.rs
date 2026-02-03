use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use crate::{db, models::{self, SecretRequest, SecretResponse, EncryptedSecretResponse, FileRequest, FileResponse, StoredFile}, AppState};

const MIN_EXPIRATION_SECONDS: u64 = 60;
const MAX_EXPIRATION_SECONDS: u64 = 604800; // 7 days

pub async fn create_secret(
    State(state): State<AppState>,
    Json(payload): Json<SecretRequest>,
) -> Result<Json<SecretResponse>, (StatusCode, String)> {
    if payload.expiration < MIN_EXPIRATION_SECONDS || payload.expiration > MAX_EXPIRATION_SECONDS {
        return Err((StatusCode::BAD_REQUEST, "Invalid expiration time".to_string()));
    }

    match db::store_secret(&state.redis, payload.encrypted_secret, payload.expiration).await {
        Ok(id) => Ok(Json(SecretResponse { secret_id: id })),
        Err(e) => {
            tracing::error!("Redis error: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()))
        }
    }
}

pub async fn get_secret(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<EncryptedSecretResponse>, (StatusCode, String)> {
    if !id.starts_with("sp-") {
         return Err((StatusCode::NOT_FOUND, "Secret not found".to_string()));
    }

    match db::get_secret(&state.redis, &id).await {
        Ok(Some(secret)) => Ok(Json(EncryptedSecretResponse { encrypted_secret: secret })),
        Ok(None) => Err((StatusCode::NOT_FOUND, "Secret not found or already accessed".to_string())),
        Err(e) => {
            tracing::error!("Redis error: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()))
        }
    }
}

pub async fn create_file(
    State(state): State<AppState>,
    Json(payload): Json<FileRequest>,
) -> Result<Json<FileResponse>, (StatusCode, String)> {
    if payload.expiration < MIN_EXPIRATION_SECONDS || payload.expiration > MAX_EXPIRATION_SECONDS {
        return Err((StatusCode::BAD_REQUEST, "Invalid expiration time".to_string()));
    }
    
    // Validate size (approximate from base64 length)
    // Base64 size = (n * 4 / 3) approximately. 
    // payload.encrypted_data.len() > max_bytes * 4 / 3
    if payload.encrypted_data.len() > (state.max_file_size_bytes * 4 / 3 + 4) { // +4 padding safety
         return Err((StatusCode::BAD_REQUEST, format!("File too large (max {}MB)", state.max_file_size_bytes / 1024 / 1024)));
    }

    match db::store_file(&state.redis, payload.metadata, payload.encrypted_data, payload.expiration).await {
        Ok(id) => Ok(Json(FileResponse { file_id: id })),
        Err(e) => {
             tracing::error!("Redis error: {}", e);
             Err((StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()))
        }
    }
}

pub async fn get_file(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<StoredFile>, (StatusCode, String)> {
     if !id.starts_with("spf-") {
         return Err((StatusCode::NOT_FOUND, "File not found".to_string()));
    }

    match db::get_file(&state.redis, &id).await {
        Ok(Some(file)) => Ok(Json(file)),
        Ok(None) => Err((StatusCode::NOT_FOUND, "File not found or already accessed".to_string())),
        Err(e) => {
            tracing::error!("Redis error: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, extract::DefaultBodyLimit, http::{Request, StatusCode}, routing::post, Router};
    use tower::ServiceExt; // for `oneshot`
    use std::sync::Arc;
    use redis::Client;

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
}
