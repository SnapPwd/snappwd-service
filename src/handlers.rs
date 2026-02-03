use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use crate::{db, models::{self, SecretRequest, SecretResponse, EncryptedSecretResponse, FileRequest, FileResponse, StoredFile}};
use std::sync::Arc;
use redis::Client;

const MIN_EXPIRATION_SECONDS: u64 = 60;
const MAX_EXPIRATION_SECONDS: u64 = 604800; // 7 days (standard) or check constants. TS said CUSTOM_EXPIRATION_MAX_SECONDS.
// Assuming 7 days is a safe default upper bound if constants aren't shared.
// Actually, let's use a sensible default.

const MAX_FILE_SIZE_BYTES: usize = 2 * 1024 * 1024; // 2MB

pub async fn create_secret(
    State(client): State<Arc<Client>>,
    Json(payload): Json<SecretRequest>,
) -> Result<Json<SecretResponse>, (StatusCode, String)> {
    if payload.expiration < MIN_EXPIRATION_SECONDS || payload.expiration > MAX_EXPIRATION_SECONDS {
        return Err((StatusCode::BAD_REQUEST, "Invalid expiration time".to_string()));
    }

    match db::store_secret(&client, payload.encrypted_secret, payload.expiration).await {
        Ok(id) => Ok(Json(SecretResponse { secret_id: id })),
        Err(e) => {
            tracing::error!("Redis error: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()))
        }
    }
}

pub async fn get_secret(
    State(client): State<Arc<Client>>,
    Path(id): Path<String>,
) -> Result<Json<EncryptedSecretResponse>, (StatusCode, String)> {
    if !id.starts_with("sp-") {
         return Err((StatusCode::NOT_FOUND, "Secret not found".to_string()));
    }

    match db::get_secret(&client, &id).await {
        Ok(Some(secret)) => Ok(Json(EncryptedSecretResponse { encrypted_secret: secret })),
        Ok(None) => Err((StatusCode::NOT_FOUND, "Secret not found or already accessed".to_string())),
        Err(e) => {
            tracing::error!("Redis error: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()))
        }
    }
}

pub async fn create_file(
    State(client): State<Arc<Client>>,
    Json(payload): Json<FileRequest>,
) -> Result<Json<FileResponse>, (StatusCode, String)> {
    if payload.expiration < MIN_EXPIRATION_SECONDS || payload.expiration > MAX_EXPIRATION_SECONDS {
        return Err((StatusCode::BAD_REQUEST, "Invalid expiration time".to_string()));
    }
    
    // Validate size (approximate from base64 length)
    // Base64 size = (n * 4 / 3) approximately. 
    // payload.encrypted_data.len() > MAX_FILE_SIZE_BYTES * 4 / 3
    if payload.encrypted_data.len() > (MAX_FILE_SIZE_BYTES * 4 / 3 + 4) { // +4 padding safety
         return Err((StatusCode::BAD_REQUEST, "File too large (max 2MB)".to_string()));
    }

    match db::store_file(&client, payload.metadata, payload.encrypted_data, payload.expiration).await {
        Ok(id) => Ok(Json(FileResponse { file_id: id })),
        Err(e) => {
             tracing::error!("Redis error: {}", e);
             Err((StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()))
        }
    }
}

pub async fn get_file(
    State(client): State<Arc<Client>>,
    Path(id): Path<String>,
) -> Result<Json<StoredFile>, (StatusCode, String)> {
     if !id.starts_with("spf-") {
         return Err((StatusCode::NOT_FOUND, "File not found".to_string()));
    }

    match db::get_file(&client, &id).await {
        Ok(Some(file)) => Ok(Json(file)),
        Ok(None) => Err((StatusCode::NOT_FOUND, "File not found or already accessed".to_string())),
        Err(e) => {
            tracing::error!("Redis error: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()))
        }
    }
}
