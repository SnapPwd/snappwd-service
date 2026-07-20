use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub const MAX_SECRET_METADATA_LABEL_BYTES: usize = 120;
pub const MAX_SECRET_METADATA_INTENDED_RECIPIENT_BYTES: usize = 254;
pub const MAX_SECRET_METADATA_NOTE_BYTES: usize = 1000;
pub const MAX_SECRET_METADATA_ROTATE_BY_BYTES: usize = 64;
pub const MAX_SECRET_METADATA_ROTATION_REASON_BYTES: usize = 240;
pub const MAX_SECRET_METADATA_SHARE_TYPE_BYTES: usize = 64;

#[derive(Serialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SecretMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intended_recipient: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotate_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub share_type: Option<String>,
}

impl SecretMetadata {
    fn from_value(value: Value) -> Result<Option<Self>, String> {
        let Value::Object(fields) = value else {
            return Err("metadata must be an object".to_string());
        };

        let mut metadata = Self::default();

        for (field, value) in fields {
            let Value::String(raw) = value else {
                return Err(format!("metadata.{field} must be a string"));
            };

            match field.as_str() {
                "label" => {
                    metadata.label = normalize_secret_metadata_field(
                        &field,
                        &raw,
                        MAX_SECRET_METADATA_LABEL_BYTES,
                    )?;
                }
                "intendedRecipient" => {
                    metadata.intended_recipient = normalize_secret_metadata_field(
                        &field,
                        &raw,
                        MAX_SECRET_METADATA_INTENDED_RECIPIENT_BYTES,
                    )?;
                }
                "note" => {
                    metadata.note = normalize_secret_metadata_field(
                        &field,
                        &raw,
                        MAX_SECRET_METADATA_NOTE_BYTES,
                    )?;
                }
                "rotateBy" => {
                    metadata.rotate_by = normalize_secret_metadata_field(
                        &field,
                        &raw,
                        MAX_SECRET_METADATA_ROTATE_BY_BYTES,
                    )?;
                }
                "rotationReason" => {
                    metadata.rotation_reason = normalize_secret_metadata_field(
                        &field,
                        &raw,
                        MAX_SECRET_METADATA_ROTATION_REASON_BYTES,
                    )?;
                }
                "shareType" => {
                    metadata.share_type = normalize_secret_metadata_field(
                        &field,
                        &raw,
                        MAX_SECRET_METADATA_SHARE_TYPE_BYTES,
                    )?;
                }
                _ => return Err(format!("metadata contains unknown field `{field}`")),
            }
        }

        if metadata.is_empty() {
            Ok(None)
        } else {
            Ok(Some(metadata))
        }
    }

    fn is_empty(&self) -> bool {
        self.label.is_none()
            && self.intended_recipient.is_none()
            && self.note.is_none()
            && self.rotate_by.is_none()
            && self.rotation_reason.is_none()
            && self.share_type.is_none()
    }
}

impl<'de> Deserialize<'de> for SecretMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        Self::from_value(value)
            .map_err(de::Error::custom)?
            .ok_or_else(|| de::Error::custom("metadata must include at least one non-empty field"))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum StoredSecretMetadata {
    Validated(SecretMetadata),
    Legacy(Value),
}

impl Serialize for StoredSecretMetadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Validated(metadata) => metadata.serialize(serializer),
            Self::Legacy(value) => value.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for StoredSecretMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Preserve stored metadata as-is on reads so legacy Redis records can be
        // returned by peek without revalidation or normalization.
        let value = Value::deserialize(deserializer)?;
        Ok(Self::Legacy(value))
    }
}

fn normalize_secret_metadata_field(
    field: &str,
    raw: &str,
    max_bytes: usize,
) -> Result<Option<String>, String> {
    let trimmed = raw.trim();

    if trimmed.is_empty() {
        return Ok(None);
    }

    if trimmed.len() > max_bytes {
        return Err(format!(
            "metadata.{field} must be at most {max_bytes} bytes"
        ));
    }

    Ok(Some(trimmed.to_string()))
}

fn deserialize_secret_metadata_option<'de, D>(
    deserializer: D,
) -> Result<Option<SecretMetadata>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;

    match value {
        Some(value) => SecretMetadata::from_value(value).map_err(de::Error::custom),
        None => Ok(None),
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SecretRequest {
    #[serde(rename = "encryptedSecret")]
    pub encrypted_secret: String,
    pub expiration: u64,
    #[serde(default, deserialize_with = "deserialize_secret_metadata_option")]
    pub metadata: Option<SecretMetadata>,
}

/// Internal storage format for secrets (JSON in Redis)
#[derive(Deserialize, Serialize, Debug)]
pub struct StoredSecret {
    #[serde(rename = "encryptedSecret")]
    pub encrypted_secret: String,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
    #[serde(default)]
    pub metadata: Option<StoredSecretMetadata>,
}

/// Query params for GET /v1/secrets/{id}
#[derive(Deserialize, Debug, Default)]
pub struct GetSecretParams {
    #[serde(default)]
    pub peek: bool,
}

/// Response for peek=true
#[derive(Serialize, Debug)]
pub struct SecretPeekResponse {
    #[serde(rename = "createdAt")]
    pub created_at: u64,
    #[serde(rename = "ttlSeconds")]
    pub ttl_seconds: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<StoredSecretMetadata>,
}

#[derive(Serialize, Debug)]
pub struct SecretResponse {
    #[serde(rename = "secretId")]
    pub secret_id: String,
}

#[derive(Serialize, Debug)]
pub struct EncryptedSecretResponse {
    #[serde(rename = "encryptedSecret")]
    pub encrypted_secret: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct FileMetadata {
    #[serde(rename = "originalFilename")]
    pub original_filename: String,
    #[serde(rename = "contentType")]
    pub content_type: String,
    pub iv: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct FileRequest {
    pub metadata: FileMetadata,
    #[serde(rename = "encryptedData")]
    pub encrypted_data: String, // Base64
    pub expiration: u64,
}

#[derive(Serialize, Debug)]
pub struct FileResponse {
    #[serde(rename = "fileId")]
    pub file_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StoredFile {
    pub metadata: FileMetadata,
    #[serde(rename = "encryptedData")]
    pub encrypted_data: String,
    #[serde(rename = "createdAt", default)]
    pub created_at: u64,
}

/// Query params for GET /v1/files/{id}
#[derive(Deserialize, Debug, Default)]
pub struct GetFileParams {
    #[serde(default)]
    pub peek: bool,
}

/// Response for file peek=true
#[derive(Serialize, Debug)]
pub struct FilePeekResponse {
    #[serde(rename = "createdAt")]
    pub created_at: u64,
    #[serde(rename = "ttlSeconds")]
    pub ttl_seconds: i64,
    pub metadata: FileMetadata,
}

#[derive(Serialize, Debug)]
pub struct ErrorResponse {
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_request_serialization() {
        let req = SecretRequest {
            encrypted_secret: "abc".to_string(),
            expiration: 3600,
            metadata: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            json,
            r#"{"encryptedSecret":"abc","expiration":3600,"metadata":null}"#
        );
    }

    #[test]
    fn test_secret_request_serialization_with_metadata() {
        let req = SecretRequest {
            encrypted_secret: "abc".to_string(),
            expiration: 3600,
            metadata: Some(SecretMetadata {
                label: Some("test".to_string()),
                ..SecretMetadata::default()
            }),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""encryptedSecret":"abc""#));
        assert!(json.contains(r#""expiration":3600"#));
        assert!(json.contains(r#""metadata":{"label":"test"}"#));
    }

    #[test]
    fn test_secret_request_deserialization() {
        let json = r#"{"encryptedSecret":"abc","expiration":3600}"#;
        let req: SecretRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.encrypted_secret, "abc");
        assert_eq!(req.expiration, 3600);
        assert!(req.metadata.is_none());
    }

    #[test]
    fn test_secret_request_deserialization_with_metadata() {
        let json = r#"{"encryptedSecret":"abc","expiration":3600,"metadata":{"label":"test"}}"#;
        let req: SecretRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.encrypted_secret, "abc");
        assert_eq!(req.expiration, 3600);
        assert!(req.metadata.is_some());
        assert_eq!(req.metadata.unwrap().label.as_deref(), Some("test"));
    }

    #[test]
    fn test_secret_request_deserialization_with_accepted_metadata() {
        let json = r#"{"encryptedSecret":"abc","expiration":3600,"metadata":{"label":" Deploy key ","intendedRecipient":" ops@example.com ","note":"Rotate after rollout","rotateBy":"2026-05-01","rotationReason":"staging cutover","shareType":"password"}}"#;
        let req: SecretRequest = serde_json::from_str(json).unwrap();
        let metadata = req.metadata.unwrap();

        assert_eq!(metadata.label.as_deref(), Some("Deploy key"));
        assert_eq!(
            metadata.intended_recipient.as_deref(),
            Some("ops@example.com")
        );
        assert_eq!(metadata.note.as_deref(), Some("Rotate after rollout"));
        assert_eq!(metadata.rotate_by.as_deref(), Some("2026-05-01"));
        assert_eq!(metadata.rotation_reason.as_deref(), Some("staging cutover"));
        assert_eq!(metadata.share_type.as_deref(), Some("password"));
    }

    #[test]
    fn test_secret_request_metadata_drops_empty_values() {
        let json = r#"{"encryptedSecret":"abc","expiration":3600,"metadata":{"label":"  ","note":" keep "}}"#;
        let req: SecretRequest = serde_json::from_str(json).unwrap();
        let metadata = req.metadata.unwrap();

        assert!(metadata.label.is_none());
        assert_eq!(metadata.note.as_deref(), Some("keep"));
    }

    #[test]
    fn test_secret_request_metadata_all_empty_becomes_none() {
        let json =
            r#"{"encryptedSecret":"abc","expiration":3600,"metadata":{"label":"  ","note":""}}"#;
        let req: SecretRequest = serde_json::from_str(json).unwrap();

        assert!(req.metadata.is_none());
    }

    #[test]
    fn test_secret_request_metadata_rejects_unknown_fields() {
        let json = r#"{"encryptedSecret":"abc","expiration":3600,"metadata":{"label":"test","owner":"ops"}}"#;
        let err = serde_json::from_str::<SecretRequest>(json).unwrap_err();

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn test_secret_request_metadata_rejects_non_string_fields() {
        let json = r#"{"encryptedSecret":"abc","expiration":3600,"metadata":{"label":123}}"#;
        let err = serde_json::from_str::<SecretRequest>(json).unwrap_err();

        assert!(err.to_string().contains("metadata.label must be a string"));
    }

    #[test]
    fn test_secret_request_metadata_rejects_max_length() {
        let label = "a".repeat(MAX_SECRET_METADATA_LABEL_BYTES + 1);
        let json = serde_json::json!({
            "encryptedSecret": "abc",
            "expiration": 3600,
            "metadata": {
                "label": label
            }
        });
        let err = serde_json::from_value::<SecretRequest>(json).unwrap_err();

        assert!(err.to_string().contains("metadata.label must be at most"));
    }

    #[test]
    fn test_stored_secret_serialization() {
        let stored = StoredSecret {
            encrypted_secret: "secret123".to_string(),
            created_at: 1706900000,
            metadata: Some(StoredSecretMetadata::Validated(SecretMetadata {
                label: Some("test".to_string()),
                ..SecretMetadata::default()
            })),
        };
        let json = serde_json::to_string(&stored).unwrap();
        assert!(json.contains(r#""encryptedSecret":"secret123""#));
        assert!(json.contains(r#""createdAt":1706900000"#));
        assert!(json.contains(r#""metadata":{"label":"test"}"#));
    }

    #[test]
    fn test_stored_secret_deserializes_legacy_metadata() {
        let json = r#"{"encryptedSecret":"secret123","createdAt":1706900000,"metadata":{"owner":"ops","label":123}}"#;
        let stored: StoredSecret = serde_json::from_str(json).unwrap();

        assert!(matches!(
            stored.metadata,
            Some(StoredSecretMetadata::Legacy(_))
        ));
    }

    #[test]
    fn test_get_secret_params_default() {
        let params: GetSecretParams = serde_json::from_str("{}").unwrap();
        assert!(!params.peek);
    }

    #[test]
    fn test_get_secret_params_peek_true() {
        let params: GetSecretParams = serde_json::from_str(r#"{"peek":true}"#).unwrap();
        assert!(params.peek);
    }

    #[test]
    fn test_secret_peek_response_serialization() {
        let resp = SecretPeekResponse {
            created_at: 1706900000,
            ttl_seconds: 298,
            metadata: Some(StoredSecretMetadata::Validated(SecretMetadata {
                label: Some("test".to_string()),
                ..SecretMetadata::default()
            })),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""createdAt":1706900000"#));
        assert!(json.contains(r#""ttlSeconds":298"#));
        assert!(json.contains(r#""metadata":{"label":"test"}"#));
    }

    #[test]
    fn test_secret_peek_response_no_metadata() {
        let resp = SecretPeekResponse {
            created_at: 1706900000,
            ttl_seconds: 298,
            metadata: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("metadata"));
    }

    #[test]
    fn test_file_request_serialization() {
        let req = FileRequest {
            metadata: FileMetadata {
                original_filename: "test.txt".to_string(),
                content_type: "text/plain".to_string(),
                iv: "iv123".to_string(),
            },
            encrypted_data: "data123".to_string(),
            expiration: 3600,
        };
        let json = serde_json::to_string(&req).unwrap();
        // Check for presence of fields rather than exact string due to order
        assert!(json.contains(r#""originalFilename":"test.txt""#));
        assert!(json.contains(r#""contentType":"text/plain""#));
        assert!(json.contains(r#""encryptedData":"data123""#));
    }

    #[test]
    fn test_get_file_params_default() {
        let params: GetFileParams = serde_json::from_str("{}").unwrap();
        assert!(!params.peek);
    }

    #[test]
    fn test_get_file_params_peek_true() {
        let params: GetFileParams = serde_json::from_str(r#"{"peek":true}"#).unwrap();
        assert!(params.peek);
    }

    #[test]
    fn test_file_peek_response_serialization() {
        let resp = FilePeekResponse {
            created_at: 1706900000,
            ttl_seconds: 298,
            metadata: FileMetadata {
                original_filename: "test.pdf".to_string(),
                content_type: "application/pdf".to_string(),
                iv: "abc123".to_string(),
            },
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""createdAt":1706900000"#));
        assert!(json.contains(r#""ttlSeconds":298"#));
        assert!(json.contains(r#""originalFilename":"test.pdf""#));
        assert!(json.contains(r#""contentType":"application/pdf""#));
    }

    #[test]
    fn test_stored_file_with_created_at() {
        let stored = StoredFile {
            metadata: FileMetadata {
                original_filename: "doc.txt".to_string(),
                content_type: "text/plain".to_string(),
                iv: "iv456".to_string(),
            },
            encrypted_data: "encrypted123".to_string(),
            created_at: 1706900000,
        };
        let json = serde_json::to_string(&stored).unwrap();
        assert!(json.contains(r#""createdAt":1706900000"#));
    }

    #[test]
    fn test_stored_file_deserialize_without_created_at_defaults_to_zero() {
        // Legacy files without createdAt should deserialize with created_at = 0
        let json = r#"{"metadata":{"originalFilename":"old.txt","contentType":"text/plain","iv":"iv"},"encryptedData":"data"}"#;
        let stored: StoredFile = serde_json::from_str(json).unwrap();
        assert_eq!(stored.created_at, 0);
    }
}
