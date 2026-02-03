use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct SecretRequest {
    #[serde(rename = "encryptedSecret")]
    pub encrypted_secret: String,
    pub expiration: u64,
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
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"encryptedSecret":"abc","expiration":3600}"#);
    }

    #[test]
    fn test_secret_request_deserialization() {
        let json = r#"{"encryptedSecret":"abc","expiration":3600}"#;
        let req: SecretRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.encrypted_secret, "abc");
        assert_eq!(req.expiration, 3600);
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
}
