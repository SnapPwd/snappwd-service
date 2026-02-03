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

#[derive(Deserialize, Debug)]
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
