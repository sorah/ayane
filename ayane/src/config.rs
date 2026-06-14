//! JSON configuration schema.
//!
//! The configuration is plain data: it is parsed here and turned into live
//! providers by [`crate::builder::build_service`]. Keeping it data-only avoids a
//! dependency cycle between configuration and the provider modules.

/// Top-level configuration document.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The issuing certificate authority (cert + signing key + chain + roots).
    pub ca: CaConfig,
    /// Token-issuing provisioners.
    #[serde(default)]
    pub provisioners: Vec<ProvisionerConfig>,
    /// Named certificate templates.
    #[serde(default)]
    pub templates: std::collections::HashMap<String, crate::template::CertificateTemplate>,
    /// Name of the template used when a provisioner does not select one.
    #[serde(default)]
    pub default_template: Option<String>,
    /// Issuance webhooks (gating and enrichment).
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,
    /// Audit event destinations.
    #[serde(default)]
    pub events: Vec<EventConfig>,
    /// Revocation / anti-replay storage backend.
    #[serde(default)]
    pub storage: StorageConfig,
    /// HTTP server settings.
    #[serde(default)]
    pub server: ServerConfig,
}

impl Config {
    /// Parse a configuration document from JSON text.
    pub fn from_json(text: &str) -> crate::error::Result<Self> {
        serde_json::from_str(text)
            .map_err(|e| crate::error::Error::Config(format!("invalid configuration: {e}")))
    }

    /// Load a configuration document from a file path.
    pub fn from_path(path: &std::path::Path) -> crate::error::Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            crate::error::Error::Config(format!("read config {}: {e}", path.display()))
        })?;
        Self::from_json(&text)
    }
}

/// A PEM document sourced either from a file path or given inline. Modeled as an
/// enum so exactly one form is present: `{ "file": "..." }` or `{ "pem": "..." }`.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged)]
pub enum PemSource {
    /// Read PEM text from a file path.
    File {
        /// Path to a PEM file.
        file: String,
    },
    /// Inline PEM text.
    Inline {
        /// Inline PEM text.
        pem: String,
    },
}

impl PemSource {
    /// Resolve to PEM text.
    pub fn load(&self) -> crate::error::Result<String> {
        match self {
            PemSource::Inline { pem } => Ok(pem.clone()),
            PemSource::File { file } => std::fs::read_to_string(file)
                .map_err(|e| crate::error::Error::Config(format!("read PEM {file}: {e}"))),
        }
    }
}

/// The issuing certificate authority.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaConfig {
    /// The issuing (intermediate or root) certificate.
    pub certificate: PemSource,
    /// The signing key.
    pub key: KeyConfig,
    /// Additional chain certificates returned to clients (issuer up the chain).
    #[serde(default)]
    pub chain: Vec<PemSource>,
    /// Trusted root certificate(s) served at `/roots`.
    #[serde(default)]
    pub roots: Vec<PemSource>,
}

/// Signing-key backend.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KeyConfig {
    /// A local PEM private key.
    File {
        /// Path to the key file.
        #[serde(default)]
        file: Option<String>,
        /// Inline PEM key.
        #[serde(default)]
        pem: Option<String>,
        /// Signature algorithm override (RSA only); e.g. `"RSA_PKCS1_SHA256"`.
        #[serde(default)]
        algorithm: Option<String>,
    },
    /// An AWS KMS asymmetric key.
    Kms {
        /// KMS key id, ARN or alias.
        key_id: String,
        /// Signature algorithm, e.g. `"ECDSA_SHA256"`.
        algorithm: String,
        /// Optional region override.
        #[serde(default)]
        region: Option<String>,
    },
}

/// A token-issuing provisioner (JWK / JWT).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionerConfig {
    /// Provisioner name; must equal the token `iss` claim.
    pub name: String,
    /// Provisioner kind. Only `"jwk"` is supported.
    #[serde(rename = "type", default = "default_provisioner_type")]
    pub kind: String,
    /// The provisioner's public verification key, as a JWK.
    pub key: jsonwebtoken::jwk::Jwk,
    /// Accepted token `aud` values (in addition to the server's endpoint URLs).
    #[serde(default)]
    pub audiences: Vec<String>,
    /// Template name to use for certificates issued through this provisioner.
    #[serde(default)]
    pub template: Option<String>,
}

fn default_provisioner_type() -> String {
    "jwk".to_string()
}

/// A webhook definition. A single webhook may both authorize (deny) and enrich
/// an issuance from one response — there is no kind distinction.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    /// Unique webhook name.
    pub name: String,
    /// Where the webhook is invoked.
    pub target: WebhookTarget,
    /// Provisioner names this webhook applies to; empty means all.
    #[serde(default)]
    pub provisioners: Vec<String>,
    /// Per-call timeout.
    #[serde(default)]
    pub timeout: Option<crate::duration::ConfigDuration>,
}

/// Webhook transport.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WebhookTarget {
    /// An HTTPS endpoint, optionally HMAC-signed and/or bearer-authenticated.
    Http {
        /// Endpoint URL.
        url: String,
        /// Base64 HMAC-SHA256 secret; when set, requests carry a signature header.
        #[serde(default)]
        secret: Option<String>,
        /// Bearer token sent in `Authorization`.
        #[serde(default)]
        bearer_token: Option<String>,
    },
    /// An AWS Lambda function invoked synchronously.
    Lambda {
        /// Function name or ARN.
        function_name: String,
        /// Optional region override.
        #[serde(default)]
        region: Option<String>,
    },
}

/// An audit event destination.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventConfig {
    /// Write JSON lines to stdout.
    Stdout,
    /// Append JSON lines to a file.
    File {
        /// Output path.
        path: String,
    },
    /// Publish to AWS EventBridge.
    EventBridge {
        /// Target event bus (defaults to `default`).
        #[serde(default)]
        event_bus_name: Option<String>,
        /// Event `source` (defaults to `ayane`).
        #[serde(default)]
        source: Option<String>,
        /// Optional region override.
        #[serde(default)]
        region: Option<String>,
    },
}

/// Storage backend for revocation records and the anti-replay token denylist.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StorageConfig {
    /// A local SQLite database. `path` defaults to `:memory:`, an in-process
    /// non-durable database suitable for development and tests; a filesystem
    /// path makes it durable for single-node deployments. The legacy `memory`
    /// type is accepted as an alias for an in-memory SQLite database.
    #[serde(alias = "memory")]
    Sqlite {
        /// SQLite database path, or `:memory:` for an in-process database.
        #[serde(default = "default_sqlite_path")]
        path: String,
    },
    /// An AWS DynamoDB table.
    Dynamodb {
        /// Table name.
        table_name: String,
        /// Optional region override.
        #[serde(default)]
        region: Option<String>,
    },
}

fn default_sqlite_path() -> String {
    ":memory:".to_string()
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig::Sqlite {
            path: default_sqlite_path(),
        }
    }
}

/// HTTP server settings.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Listen address for the standalone server.
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Public base URL, used to validate token audiences and DPoP `htu`.
    #[serde(default)]
    pub external_url: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            listen: default_listen(),
            external_url: None,
        }
    }
}

fn default_listen() -> String {
    "0.0.0.0:9443".to_string()
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_example_config() {
        let text = include_str!("../../examples/ayane.example.json");
        let config = super::Config::from_json(text).expect("example config parses");
        assert_eq!(config.provisioners.len(), 1);
        assert_eq!(config.provisioners[0].name, "ci-issuer");
        assert!(config.templates.contains_key("server"));
        assert_eq!(config.webhooks.len(), 2);
        assert!(matches!(
            config.storage,
            super::StorageConfig::Dynamodb { .. }
        ));
        assert_eq!(
            config.server.external_url.as_deref(),
            Some("https://ca.example.com")
        );
    }

    #[test]
    fn minimal_config_uses_defaults() {
        let text = r#"{
            "ca": { "certificate": { "file": "ca.crt" }, "key": { "type": "file", "file": "ca.key" } }
        }"#;
        let config = super::Config::from_json(text).expect("minimal config parses");
        assert!(config.provisioners.is_empty());
        assert!(matches!(
            config.storage,
            super::StorageConfig::Sqlite { .. }
        ));
        assert_eq!(config.server.listen, "0.0.0.0:9443");
    }

    #[test]
    fn memory_storage_aliases_in_memory_sqlite() {
        let text = r#"{
            "ca": { "certificate": { "file": "ca.crt" }, "key": { "type": "file", "file": "ca.key" } },
            "storage": { "type": "memory" }
        }"#;
        let config = super::Config::from_json(text).expect("memory alias parses");
        assert!(matches!(
            config.storage,
            super::StorageConfig::Sqlite { path } if path == ":memory:"
        ));
    }

    #[test]
    fn pem_source_requires_exactly_one_form() {
        // Neither `file` nor `pem` is an error now (caught at parse time).
        let text = r#"{ "ca": { "certificate": {}, "key": { "type": "file", "file": "k" } } }"#;
        assert!(super::Config::from_json(text).is_err());
    }
}
