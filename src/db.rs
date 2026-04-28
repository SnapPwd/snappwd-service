use crate::models::{FileMetadata, ReceiptStatus, ReceiptStatusResponse, StoredFile, StoredSecret};
use redis::{AsyncCommands, Client};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub const RECEIPT_RETENTION_SECONDS: u64 = 24 * 60 * 60;

const RECEIPT_SECRET_INDEX_PREFIX: &str = "spr-secret:";

const REVEAL_SECRET_SCRIPT: &str = r#"
local secret_json = redis.call('GETDEL', KEYS[1])
if not secret_json then
  return {0, ''}
end

local receipt_id = redis.call('GET', KEYS[2])
if receipt_id then
  if redis.call('EXISTS', receipt_id) == 1 then
    redis.call('HSET', receipt_id, 'accessed_at', ARGV[1])
  end
  redis.call('DEL', KEYS[2])
end

return {1, secret_json}
"#;

#[derive(Debug)]
pub struct CreatedSecret {
    pub secret_id: String,
    pub receipt_id: String,
    pub receipt_token: String,
}

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

fn generate_receipt_id() -> String {
    format!("spr-{}", generate_short_id())
}

fn generate_receipt_token() -> String {
    format!("spt-{}", generate_short_id())
}

fn receipt_secret_index_key(secret_id: &str) -> String {
    format!("{}{}", RECEIPT_SECRET_INDEX_PREFIX, secret_id)
}

fn receipt_ttl_seconds(secret_expiration_seconds: u64) -> u64 {
    secret_expiration_seconds.saturating_add(RECEIPT_RETENTION_SECONDS)
}

fn receipt_token_hash(receipt_token: &str) -> String {
    let digest = Sha256::digest(receipt_token.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);

    for byte in digest {
        write!(&mut out, "{:02x}", byte).expect("writing to String cannot fail");
    }

    out
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let max_len = a.len().max(b.len());
    let mut diff = a.len() ^ b.len();

    for i in 0..max_len {
        let left = a.get(i).copied().unwrap_or_default();
        let right = b.get(i).copied().unwrap_or_default();
        diff |= (left ^ right) as usize;
    }

    diff == 0
}

fn receipt_status_from_parts(
    now: u64,
    secret_expires_at: u64,
    accessed_at: Option<u64>,
    secret_exists: bool,
) -> ReceiptStatus {
    if accessed_at.is_some() {
        ReceiptStatus::Accessed
    } else if now >= secret_expires_at || !secret_exists {
        ReceiptStatus::ExpiredUnavailable
    } else {
        ReceiptStatus::NotAccessed
    }
}

fn redis_type_error(message: &'static str, detail: impl ToString) -> redis::RedisError {
    redis::RedisError::from((redis::ErrorKind::TypeError, message, detail.to_string()))
}

fn parse_u64_field(
    fields: &HashMap<String, String>,
    field: &'static str,
) -> Result<Option<u64>, redis::RedisError> {
    fields
        .get(field)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|e| redis_type_error("Receipt field parse error", e))
        })
        .transpose()
}

pub async fn store_secret(
    client: &Client,
    secret: String,
    expiration: u64,
    metadata: Option<serde_json::Value>,
) -> Result<CreatedSecret, redis::RedisError> {
    let mut conn = client.get_multiplexed_async_connection().await?;
    let id = format!("sps-{}", generate_short_id());
    let receipt_id = generate_receipt_id();
    let receipt_token = generate_receipt_token();
    let receipt_token_hash = receipt_token_hash(&receipt_token);
    let now = current_timestamp();
    let secret_expires_at = now.saturating_add(expiration);
    let receipt_ttl = receipt_ttl_seconds(expiration);
    let retention_until = now.saturating_add(receipt_ttl);
    let receipt_index_key = receipt_secret_index_key(&id);

    let stored = StoredSecret {
        encrypted_secret: secret,
        created_at: now,
        metadata,
    };

    let json_val = serde_json::to_string(&stored).map_err(|e| {
        redis::RedisError::from((
            redis::ErrorKind::TypeError,
            "Serialization error",
            e.to_string(),
        ))
    })?;

    let mut pipe = redis::pipe();
    pipe.atomic()
        .cmd("SET")
        .arg(&id)
        .arg(&json_val)
        .arg("EX")
        .arg(expiration)
        .ignore()
        .cmd("HSET")
        .arg(&receipt_id)
        .arg("token_hash")
        .arg(&receipt_token_hash)
        .arg("secret_id")
        .arg(&id)
        .arg("created_at")
        .arg(now)
        .arg("secret_expires_at")
        .arg(secret_expires_at)
        .arg("retention_until")
        .arg(retention_until)
        .ignore()
        .cmd("EXPIRE")
        .arg(&receipt_id)
        .arg(receipt_ttl)
        .ignore()
        .cmd("SET")
        .arg(&receipt_index_key)
        .arg(&receipt_id)
        .arg("EX")
        .arg(expiration)
        .ignore();
    let _: () = pipe.query_async(&mut conn).await?;

    Ok(CreatedSecret {
        secret_id: id,
        receipt_id,
        receipt_token,
    })
}

pub async fn get_secret(client: &Client, id: &str) -> Result<Option<String>, redis::RedisError> {
    let mut conn = client.get_multiplexed_async_connection().await?;
    let receipt_index_key = receipt_secret_index_key(id);

    let (found, json_str): (i64, String) = redis::Script::new(REVEAL_SECRET_SCRIPT)
        .key(id)
        .key(receipt_index_key)
        .arg(current_timestamp())
        .invoke_async(&mut conn)
        .await?;

    if found == 0 {
        return Ok(None);
    }

    // Try to parse as StoredSecret (new format)
    if let Ok(stored) = serde_json::from_str::<StoredSecret>(&json_str) {
        Ok(Some(stored.encrypted_secret))
    } else {
        // Legacy format: plain string
        Ok(Some(json_str))
    }
}

pub async fn get_receipt_status(
    client: &Client,
    receipt_id: &str,
    receipt_token: &str,
) -> Result<Option<ReceiptStatusResponse>, redis::RedisError> {
    let mut conn = client.get_multiplexed_async_connection().await?;

    let fields: HashMap<String, String> = conn.hgetall(receipt_id).await?;
    if fields.is_empty() {
        return Ok(None);
    }

    let Some(stored_token_hash) = fields.get("token_hash") else {
        return Ok(None);
    };
    let supplied_token_hash = receipt_token_hash(receipt_token);
    if !constant_time_eq(stored_token_hash, &supplied_token_hash) {
        return Ok(None);
    }

    let Some(secret_id) = fields.get("secret_id") else {
        return Ok(None);
    };
    let Some(secret_expires_at) = parse_u64_field(&fields, "secret_expires_at")? else {
        return Ok(None);
    };
    let Some(retention_until) = parse_u64_field(&fields, "retention_until")? else {
        return Ok(None);
    };
    let accessed_at = parse_u64_field(&fields, "accessed_at")?;

    let now = current_timestamp();
    let secret_exists = if accessed_at.is_some() || now >= secret_expires_at {
        false
    } else {
        conn.exists(secret_id).await?
    };
    let status = receipt_status_from_parts(now, secret_expires_at, accessed_at, secret_exists);

    Ok(Some(ReceiptStatusResponse {
        receipt_id: receipt_id.to_string(),
        status,
        accessed_at,
        secret_expires_at,
        retention_until,
    }))
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
        created_at: current_timestamp(),
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

/// Peek at a file without burning it. Returns (StoredFile, ttl_seconds).
/// For legacy files without created_at, returns created_at=0.
pub async fn peek_file(
    client: &Client,
    id: &str,
) -> Result<Option<(StoredFile, i64)>, redis::RedisError> {
    let mut conn = client.get_multiplexed_async_connection().await?;

    // Use GET (not GETDEL) to preserve the file
    let result: Option<String> = conn.get(id).await?;

    match result {
        Some(json_str) => {
            // Get TTL
            let ttl: i64 = conn.ttl(id).await?;

            let stored: StoredFile = serde_json::from_str(&json_str).map_err(|e| {
                redis::RedisError::from((
                    redis::ErrorKind::TypeError,
                    "Deserialization error",
                    e.to_string(),
                ))
            })?;
            Ok(Some((stored, ttl)))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receipt_token_hash_does_not_store_raw_token() {
        let token = "spt-example-token";
        let hash = receipt_token_hash(token);

        assert_ne!(hash, token);
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, receipt_token_hash(token));
    }

    #[test]
    fn test_constant_time_eq_result() {
        assert!(constant_time_eq("abc123", "abc123"));
        assert!(!constant_time_eq("abc123", "abc124"));
        assert!(!constant_time_eq("abc123", "abc1234"));
    }

    #[test]
    fn test_receipt_ttl_retains_after_secret_expiration() {
        assert_eq!(receipt_ttl_seconds(3600), 3600 + RECEIPT_RETENTION_SECONDS);
    }

    #[test]
    fn test_receipt_status_state_rules() {
        assert_eq!(
            receipt_status_from_parts(100, 200, None, true),
            ReceiptStatus::NotAccessed
        );
        assert_eq!(
            receipt_status_from_parts(100, 200, Some(90), false),
            ReceiptStatus::Accessed
        );
        assert_eq!(
            receipt_status_from_parts(250, 200, None, false),
            ReceiptStatus::ExpiredUnavailable
        );
        assert_eq!(
            receipt_status_from_parts(100, 200, None, false),
            ReceiptStatus::ExpiredUnavailable
        );
    }

    #[test]
    fn test_reveal_script_marks_receipt_only_after_getdel_success() {
        let getdel_pos = REVEAL_SECRET_SCRIPT.find("GETDEL").unwrap();
        let hset_pos = REVEAL_SECRET_SCRIPT.find("HSET").unwrap();

        assert!(REVEAL_SECRET_SCRIPT.contains("if not secret_json then"));
        assert!(getdel_pos < hset_pos);
        assert!(REVEAL_SECRET_SCRIPT.contains("'accessed_at'"));
    }
}
