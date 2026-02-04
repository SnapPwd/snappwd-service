use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct SecretRequest {
    #[serde(rename = "encryptedSecret")]
    pub encrypted_secret: String,
    pub expiration: u64,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Internal storage format for secrets (JSON in Redis)
#[derive(Deserialize, Serialize, Debug)]
pub struct StoredSecret {
    #[serde(rename = "encryptedSecret")]
    pub encrypted_secret: String,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
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
    pub metadata: Option<serde_json::Value>,
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
        assert_eq!(json, r#"{"encryptedSecret":"abc","expiration":3600,"metadata":null}"#);
    }

    #[test]
    fn test_secret_request_serialization_with_metadata() {
        let req = SecretRequest {
            encrypted_secret: "abc".to_string(),
            expiration: 3600,
            metadata: Some(serde_json::json!({"label": "test"})),
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
        assert_eq!(req.metadata.unwrap()["label"], "test");
    }

    #[test]
    fn test_stored_secret_serialization() {
        let stored = StoredSecret {
            encrypted_secret: "secret123".to_string(),
            created_at: 1706900000,
            metadata: Some(serde_json::json!({"label": "test"})),
        };
        let json = serde_json::to_string(&stored).unwrap();
        assert!(json.contains(r#""encryptedSecret":"secret123""#));
        assert!(json.contains(r#""createdAt":1706900000"#));
        assert!(json.contains(r#""metadata":{"label":"test"}"#));
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
            metadata: Some(serde_json::json!({"label": "test"})),
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
