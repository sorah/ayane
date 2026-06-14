//! Persistence for issued-certificate inventory, revocation records and the
//! anti-replay token denylist.
//!
//! Three concerns share one backend: a durable inventory of every certificate
//! the CA issues (the registry behind audit and certificate lookup), durable
//! revocation state (queried to decide whether a certificate may be renewed or
//! is revoked, and to assemble CRLs) and short-lived one-time token ids (`jti`)
//! used to reject replays. Backends: local SQLite (`:memory:` or a file) and AWS
//! DynamoDB (production).

pub mod dynamodb;
pub mod sqlite;

/// Build the configured storage backend.
///
/// SQLite opens locally; DynamoDB resolves a client from the shared AWS
/// configuration, loaded lazily on first use.
pub async fn from_config(
    cfg: &crate::config::StorageConfig,
) -> crate::error::Result<std::sync::Arc<dyn Storage>> {
    match cfg {
        crate::config::StorageConfig::Sqlite { path } => Ok(std::sync::Arc::new(
            crate::storage::sqlite::SqliteStorage::open(path)?,
        )
            as std::sync::Arc<dyn Storage>),
        crate::config::StorageConfig::Dynamodb { table_name, region } => {
            let client = crate::storage::dynamodb::client(region.as_deref()).await;
            Ok(
                std::sync::Arc::new(crate::storage::dynamodb::DynamoDbStorage::new(
                    client,
                    table_name.clone(),
                )) as std::sync::Arc<dyn Storage>,
            )
        }
    }
}

/// A record of one issued certificate, kept as a durable inventory of
/// everything the CA has produced.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CertificateRecord {
    /// Decimal serial number of the issued certificate.
    pub serial_number: String,
    /// Subject common name; empty for a SAN-only certificate.
    pub subject: String,
    /// Subject Alternative Names, as strings.
    pub sans: Vec<String>,
    /// RFC 3339 notBefore.
    pub not_before: String,
    /// RFC 3339 notAfter.
    pub not_after: String,
    /// RFC 3339 issuance timestamp.
    pub issued_at: String,
    /// Provisioner that authorized issuance, if any (absent for renew/rekey,
    /// which authenticate via DPoP rather than a provisioner token).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisioner: Option<String>,
    /// The issuing operation: `"sign"`, `"renew"` or `"rekey"`.
    pub operation: String,
    /// Full PEM of the issued leaf certificate.
    pub pem: String,
}

/// A recorded revocation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RevocationRecord {
    /// Decimal serial number of the revoked certificate.
    pub serial_number: String,
    /// RFC 5280 CRLReason code.
    pub reason_code: i32,
    /// Human-readable reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// RFC 3339 revocation timestamp.
    pub revoked_at: String,
    /// Provisioner that authorized the revocation, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisioner: Option<String>,
}

/// Issued-certificate inventory, revocation store and anti-replay denylist.
#[async_trait::async_trait]
pub trait Storage: Send + Sync {
    /// Record an issued certificate in the inventory. Serial numbers are unique
    /// per issuance (random 128-bit), so this is a plain insert; a pre-existing
    /// serial indicates a collision and is surfaced as an error.
    async fn record_certificate(&self, record: CertificateRecord) -> crate::error::Result<()>;

    /// Look up an issued certificate by serial number.
    async fn get_certificate(
        &self,
        serial_number: &str,
    ) -> crate::error::Result<Option<CertificateRecord>>;

    /// List all issued certificates. Order is unspecified.
    async fn list_certificates(&self) -> crate::error::Result<Vec<CertificateRecord>>;

    /// Record a revocation. Idempotent: revoking an already-revoked serial
    /// succeeds and keeps the original record.
    async fn revoke(&self, record: RevocationRecord) -> crate::error::Result<()>;

    /// Look up a revocation by serial number.
    async fn get_revocation(
        &self,
        serial_number: &str,
    ) -> crate::error::Result<Option<RevocationRecord>>;

    /// List all recorded revocations, e.g. to assemble a CRL. Order is
    /// unspecified.
    async fn list_revocations(&self) -> crate::error::Result<Vec<RevocationRecord>>;

    /// Atomically claim a one-time token id, with an expiry after which the
    /// claim may be reaped. Returns [`crate::error::Error::Conflict`] if the id
    /// was already claimed (a replay).
    async fn claim_token(
        &self,
        jti: &str,
        expires_at: std::time::SystemTime,
    ) -> crate::error::Result<()>;
}
