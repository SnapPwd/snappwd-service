use crate::models::{FileMetadata, StoredFile};
use redis::{AsyncCommands, Client};
use uuid::Uuid;

pub async fn get_redis_client(redis_url: &str) -> Result<Client, redis::RedisError> {
    Client::open(redis_url)
}

fn generate_short_id() -> String {
    let uuid = Uuid::new_v4();
    bs58::encode(uuid.as_bytes()).into_string()
}

pub async fn store_secret(
    client: &Client,
    secret: String,
    expiration: u64,
) -> Result<String, redis::RedisError> {
    let mut conn = client.get_multiplexed_async_connection().await?;
    let id = format!("sps-{}", generate_short_id());

    // Set with expiration (SETEX equivalent)
    let _: () = conn.set_ex(&id, secret, expiration).await?;

    Ok(id)
}

pub async fn get_secret(client: &Client, id: &str) -> Result<Option<String>, redis::RedisError> {
    let mut conn = client.get_multiplexed_async_connection().await?;

    // GETDEL is available in newer Redis versions. If not, we might need a Lua script or GET + DEL transaction.
    // The rust redis crate supports simple commands. checking if get_del exists.
    // It seems `redis::AsyncCommands` has `get_del` in newer versions.
    // If not, we can use `cmd("GETDEL").arg(id).query_async(&mut conn).await`

    // Using generic cmd for broad compatibility
    let result: Option<String> = redis::cmd("GETDEL")
        .arg(id)
        .query_async(&mut conn)
        .await
        .ok(); // Treat errors (like command not supported) as None for now, or fallback?
               // Actually, GETDEL was added in Redis 6.2. It should be standard.
               // But if it fails, let's try to propagate error.

    if result.is_some() {
        return Ok(result);
    }

    // If GETDEL returned null (None), it's already gone.
    // Wait, if command failed, result is None? No, query_async returns Result.
    // Let's retry properly.

    let result: Option<String> = redis::cmd("GETDEL").arg(id).query_async(&mut conn).await?;

    Ok(result)
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
