use crate::models::{FileMetadata, StoredFile, StoredSecret};
use redis::{AsyncCommands, Client};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub async fn get_redis_client(redis_url: &str) -> Result<Client, redis::RedisError> {
    Client::open(redis_url)
}

fn generate_short_id() -> String {
    let uuid = Uuid::new_v4();
    bs58::encode(uuid.as_bytes()).into_string()
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub async fn store_secret(
    client: &Client,
    secret: String,
    expiration: u64,
    metadata: Option<serde_json::Value>,
) -> Result<String, redis::RedisError> {
    let mut conn = client.get_multiplexed_async_connection().await?;
    let id = format!("sps-{}", generate_short_id());

    let stored = StoredSecret {
        encrypted_secret: secret,
        created_at: current_timestamp(),
        metadata,
    };

    let json_val = serde_json::to_string(&stored).map_err(|e| {
        redis::RedisError::from((
            redis::ErrorKind::TypeError,
            "Serialization error",
            e.to_string(),
        ))
    })?;

    let _: () = conn.set_ex(&id, json_val, expiration).await?;

    Ok(id)
}

pub async fn get_secret(client: &Client, id: &str) -> Result<Option<String>, redis::RedisError> {
    let mut conn = client.get_multiplexed_async_connection().await?;

    let result: Option<String> = redis::cmd("GETDEL").arg(id).query_async(&mut conn).await?;

    match result {
        Some(json_str) => {
            // Try to parse as StoredSecret (new format)
            if let Ok(stored) = serde_json::from_str::<StoredSecret>(&json_str) {
                Ok(Some(stored.encrypted_secret))
            } else {
                // Legacy format: plain string
                Ok(Some(json_str))
            }
        }
        None => Ok(None),
    }
}

/// Peek at a secret without burning it. Returns (StoredSecret, ttl_seconds).
/// For legacy secrets (plain string), returns created_at=0 and metadata=None.
pub async fn peek_secret(
    client: &Client,
    id: &str,
) -> Result<Option<(StoredSecret, i64)>, redis::RedisError> {
    let mut conn = client.get_multiplexed_async_connection().await?;

    // Use GET (not GETDEL) to preserve the secret
    let result: Option<String> = conn.get(id).await?;

    match result {
        Some(json_str) => {
            // Get TTL
            let ttl: i64 = conn.ttl(id).await?;

            // Try to parse as StoredSecret (new format)
            if let Ok(stored) = serde_json::from_str::<StoredSecret>(&json_str) {
                Ok(Some((stored, ttl)))
            } else {
                // Legacy format: plain string - create a synthetic StoredSecret
                let legacy_stored = StoredSecret {
                    encrypted_secret: json_str,
                    created_at: 0,
                    metadata: None,
                };
                Ok(Some((legacy_stored, ttl)))
            }
        }
        None => Ok(None),
    }
}

pub async fn store_file(
    client: &Client,
    metadata: FileMetadata,
    encrypted_data: String,
    expiration: u64,
) -> Result<String, redis::RedisError> {
    let mut conn = client.get_multiplexed_async_connection().await?;
    let id = format!("spf-{}", generate_short_id());

    let stored_file = StoredFile {
        metadata,
        encrypted_data,
    };

    let json_val = serde_json::to_string(&stored_file).map_err(|e| {
        redis::RedisError::from((
            redis::ErrorKind::TypeError,
            "Serialization error",
            e.to_string(),
        ))
    })?;

    let _: () = conn.set_ex(&id, json_val, expiration).await?;

    Ok(id)
}

pub async fn get_file(client: &Client, id: &str) -> Result<Option<StoredFile>, redis::RedisError> {
    let mut conn = client.get_multiplexed_async_connection().await?;

    let result: Option<String> = redis::cmd("GETDEL").arg(id).query_async(&mut conn).await?;

    if let Some(json_str) = result {
        let stored_file: StoredFile = serde_json::from_str(&json_str).map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "Deserialization error",
                e.to_string(),
            ))
        })?;
        return Ok(Some(stored_file));
    }

    Ok(None)
}
