//! Load the full configuration out of a storage backend.
//!
//! For deployments — notably AWS Lambda — where shipping the whole configuration
//! inline or as a file is awkward, the server is handed only a *bootstrap*: which
//! storage backend holds the configuration (as base64url JSON, small enough for
//! an environment variable) and the SHA-256 digest that both locates and
//! authenticates the document. The configuration itself is written to the storage
//! cache out of band — by deployment tooling — under a digest-derived key; ayane
//! reads it back through [`crate::storage::Storage::get_cache`], verifies the
//! digest, and parses it.

/// Load and verify the configuration document from a storage backend.
///
/// `storage_base64url` is the bootstrap [`crate::config::StorageConfig`] as
/// base64url (no padding) JSON; `digest` is the base64url (no padding) SHA-256 of
/// the configuration document, used both to derive the cache key and to
/// authenticate the bytes read back.
pub async fn load_config_from_storage(
    storage_base64url: &str,
    digest: &str,
) -> crate::error::Result<crate::config::Config> {
    let storage_config = decode_storage_config(storage_base64url)?;
    let storage = crate::storage::from_config(&storage_config).await?;
    load_config_from(storage.as_ref(), digest).await
}

/// Read, verify and parse the configuration from an already-built backend.
async fn load_config_from(
    storage: &dyn crate::storage::Storage,
    digest: &str,
) -> crate::error::Result<crate::config::Config> {
    let want = decode_digest(digest)?;
    let key = cache_key(&want);
    let bytes = storage.get_cache(&key).await?.ok_or_else(|| {
        crate::error::Error::Config(format!("configuration {key:?} not found in storage"))
    })?;

    use sha2::Digest as _;
    if sha2::Sha256::digest(&bytes)[..] != want[..] {
        return Err(crate::error::Error::Config(
            "stored configuration does not match the SHA-256 digest from AYANE_CONFIG_SHA256"
                .into(),
        ));
    }

    let text = String::from_utf8(bytes).map_err(|e| {
        crate::error::Error::Config(format!("stored configuration is not valid UTF-8: {e}"))
    })?;
    crate::config::Config::from_json(&text)
}

/// Cache key for the configuration document, namespaced by its canonical
/// base64url SHA-256 digest. Re-encoding from the decoded bytes makes the key
/// independent of any whitespace or alternate encoding in the source string.
fn cache_key(digest: &[u8; 32]) -> String {
    use base64::Engine;
    format!(
        "config:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    )
}

fn decode_storage_config(
    storage_base64url: &str,
) -> crate::error::Result<crate::config::StorageConfig> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(storage_base64url.trim())
        .map_err(|e| {
            crate::error::Error::Config(format!("invalid base64url bootstrap storage config: {e}"))
        })?;
    serde_json::from_slice(&bytes)
        .map_err(|e| crate::error::Error::Config(format!("invalid bootstrap storage config: {e}")))
}

fn decode_digest(digest: &str) -> crate::error::Result<[u8; 32]> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(digest.trim())
        .map_err(|e| {
            crate::error::Error::Config(format!("invalid base64url SHA-256 digest: {e}"))
        })?;
    <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| {
        crate::error::Error::Config(format!(
            "SHA-256 digest must be 32 bytes, got {}",
            raw.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    const CONFIG: &str = r#"{
        "ca": { "certificate": { "file": "ca.crt" }, "key": { "type": "file", "file": "ca.key" } }
    }"#;

    fn digest_b64url(bytes: &[u8]) -> String {
        use base64::Engine;
        use sha2::Digest as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(bytes))
    }

    use crate::storage::Storage as _;

    async fn seed(storage: &dyn crate::storage::Storage, bytes: &[u8]) -> String {
        let digest = digest_b64url(bytes);
        let key = super::cache_key(&super::decode_digest(&digest).unwrap());
        let expires_at = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
        storage
            .set_cache(&key, bytes.to_vec(), expires_at)
            .await
            .unwrap();
        digest
    }

    #[tokio::test]
    async fn loads_and_verifies_stored_config() {
        let storage = crate::storage::sqlite::SqliteStorage::open_in_memory().unwrap();
        let digest = seed(&storage, CONFIG.as_bytes()).await;

        let config = super::load_config_from(&storage, &digest)
            .await
            .expect("stored config loads");
        assert!(config.provisioners.is_empty());

        // A trailing newline on the digest (as an env var may carry) is tolerated.
        super::load_config_from(&storage, &format!("{digest}\n"))
            .await
            .expect("trailing newline tolerated");
    }

    #[tokio::test]
    async fn rejects_content_not_matching_digest() {
        let storage = crate::storage::sqlite::SqliteStorage::open_in_memory().unwrap();
        // Store under a digest of the original bytes, but with tampered content.
        let digest = digest_b64url(CONFIG.as_bytes());
        let key = super::cache_key(&super::decode_digest(&digest).unwrap());
        let expires_at = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
        storage
            .set_cache(&key, b"{}".to_vec(), expires_at)
            .await
            .unwrap();

        assert!(super::load_config_from(&storage, &digest).await.is_err());
    }

    #[tokio::test]
    async fn missing_entry_is_an_error() {
        let storage = crate::storage::sqlite::SqliteStorage::open_in_memory().unwrap();
        let digest = digest_b64url(CONFIG.as_bytes());
        assert!(super::load_config_from(&storage, &digest).await.is_err());
    }

    #[test]
    fn rejects_malformed_digest() {
        assert!(super::decode_digest("not base64!!!").is_err());
        // 48 bytes (SHA-384) is the wrong length for SHA-256.
        let sha384 = {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 48])
        };
        assert!(super::decode_digest(&sha384).is_err());
    }

    #[test]
    fn decodes_base64url_storage_config() {
        use base64::Engine;
        let json = r#"{ "type": "dynamodb", "table_name": "ayane" }"#;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        let storage = super::decode_storage_config(&encoded).expect("storage config decodes");
        assert!(matches!(
            storage,
            crate::config::StorageConfig::Dynamodb { .. }
        ));
    }
}
