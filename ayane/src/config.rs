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
        let config: Self = serde_json::from_str(text)
            .map_err(|e| crate::error::Error::Config(format!("invalid configuration: {e}")))?;
        config.server.tls.validate()?;
        Ok(config)
    }

    /// Load a configuration document from a file path.
    pub fn from_path(path: &std::path::Path) -> crate::error::Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            crate::error::Error::Config(format!("read config {}: {e}", path.display()))
        })?;
        Self::from_json(&text)
    }

    /// Parse a configuration document from base64url (no padding) encoded JSON.
    ///
    /// Lets the whole configuration travel through a single environment variable
    /// instead of a file, which is convenient for deployments — such as AWS
    /// Lambda — where shipping a sidecar file is awkward.
    pub fn from_base64url(encoded: &str) -> crate::error::Result<Self> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded.trim())
            .map_err(|e| {
                crate::error::Error::Config(format!("invalid base64url configuration: {e}"))
            })?;
        let text = String::from_utf8(bytes).map_err(|e| {
            crate::error::Error::Config(format!("base64url configuration is not valid UTF-8: {e}"))
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
    /// Additional issuer-side certificates returned to clients, served verbatim
    /// after the issuing `certificate`. Normally the issuer's parents up the
    /// chain; may also carry a cross-signed intermediate (same subject/key,
    /// signed by an old root) so clients can build a path during a CA migration.
    #[serde(default)]
    pub chain: Vec<PemSource>,
    /// Trusted root certificate(s) served at `/roots`. List both old and new
    /// roots to keep either trusted across a root rotation.
    #[serde(default)]
    pub roots: Vec<PemSource>,
    /// Signature applied to the `GET /v1/roots` response.
    #[serde(default)]
    pub roots_signature: RootsSignatureConfig,
}

/// Settings for the RFC 9421 signature over the `GET /v1/roots` response.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RootsSignatureConfig {
    /// Lifetime of each signed roots artifact (`expires = created + ttl`). The
    /// server re-signs before expiry; clients reject once `now >= expires`.
    pub ttl: crate::duration::ConfigDuration,
}

impl Default for RootsSignatureConfig {
    fn default() -> Self {
        RootsSignatureConfig {
            ttl: default_roots_signature_ttl(),
        }
    }
}

fn default_roots_signature_ttl() -> crate::duration::ConfigDuration {
    crate::duration::ConfigDuration(std::time::Duration::from_secs(24 * 3600))
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
    AwsKms {
        /// KMS key id, ARN or alias.
        key_id: String,
        /// Signature algorithm, e.g. `"ECDSA_SHA256"`.
        algorithm: String,
        /// Optional region override.
        #[serde(default)]
        region: Option<String>,
    },
}

/// A token-issuing provisioner.
///
/// Fields shared by every provisioner type live here; the type-specific
/// verification configuration is carried by [`kind`](Self::kind), a flattened
/// enum discriminated by `type` (the same pattern as [`KeyConfig`] and
/// [`WebhookTarget`]).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ProvisionerConfig {
    /// Provisioner name; matched against the token `iss` (or, for `jwks`, the
    /// resolved issuer).
    pub name: String,
    /// Accepted token `aud` values (in addition to the server's endpoint URLs).
    #[serde(default)]
    pub audiences: Vec<String>,
    /// Template name to use for certificates issued through this provisioner.
    #[serde(default)]
    pub template: Option<String>,
    /// Whether a validated token alone authorizes issuance. Defaults by kind
    /// (`jwk` → `true`, `jwks` → `false`); an explicit value overrides. When the
    /// effective value is `false`, an authorize webhook must explicitly grant
    /// each request (see [`crate::webhook`]).
    #[serde(default)]
    pub authorized: Option<bool>,
    /// Type-specific verification configuration, discriminated by `type`.
    #[serde(flatten)]
    pub kind: ProvisionerKind,
}

/// Type-specific provisioner verification configuration.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProvisionerKind {
    /// A single static verification key, as a JWK. Tokens are trusted purely
    /// because they were signed by the matching private key.
    Jwk {
        /// The provisioner's public verification key.
        key: jsonwebtoken::jwk::Jwk,
    },
    /// A remote JSON Web Key Set fetched from a URL or discovered via OIDC.
    /// Used to validate tokens minted by an external issuer (e.g. a public OIDC
    /// provider); such tokens only *authenticate* — see [`authorized`].
    ///
    /// [`authorized`]: ProvisionerConfig::authorized
    Jwks {
        /// Where to fetch verification keys and which issuer to expect.
        jwks: JwksConfig,
    },
}

/// Configuration for a `jwks` provisioner: where to fetch verification keys and
/// which token issuer to expect.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwksConfig {
    /// URL of a JWK Set document. Mutually exclusive with
    /// [`openid_configuration_url`](Self::openid_configuration_url).
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// URL of an OpenID Connect discovery document
    /// (`.well-known/openid-configuration`); its `jwks_uri` is followed to the
    /// key set. Mutually exclusive with [`jwks_url`](Self::jwks_url).
    #[serde(default)]
    pub openid_configuration_url: Option<String>,
    /// The token `iss` value this provisioner accepts. When unset it is derived:
    /// for `openid_configuration_url`, by stripping the
    /// `/.well-known/openid-configuration` suffix; otherwise it falls back to the
    /// provisioner `name`.
    #[serde(default)]
    pub issuer: Option<String>,
}

/// The `.well-known` suffix an OIDC discovery URL appends to its issuer.
const OIDC_DISCOVERY_SUFFIX: &str = "/.well-known/openid-configuration";

impl ProvisionerConfig {
    /// The effective `authorized` value, resolving the kind-based default.
    pub fn effective_authorized(&self) -> bool {
        self.authorized
            .unwrap_or(matches!(self.kind, ProvisionerKind::Jwk { .. }))
    }
}

impl JwksConfig {
    /// The token issuer this provisioner expects (see [`issuer`](Self::issuer)).
    pub fn resolved_issuer(&self, name: &str) -> String {
        if let Some(issuer) = &self.issuer {
            return issuer.clone();
        }
        if let Some(url) = &self.openid_configuration_url
            && let Some(issuer) = url.strip_suffix(OIDC_DISCOVERY_SUFFIX)
        {
            return issuer.to_string();
        }
        name.to_string()
    }
}

/// Fail closed when an unauthorized provisioner has no webhook that could ever
/// grant it: such a provisioner can never issue, which is a misconfiguration.
pub fn validate_provisioner_authorization(cfg: &Config) -> crate::error::Result<()> {
    for provisioner in &cfg.provisioners {
        if provisioner.effective_authorized() {
            continue;
        }
        let has_webhook = cfg.webhooks.iter().any(|w| {
            w.provisioners.is_empty() || w.provisioners.iter().any(|p| p == &provisioner.name)
        });
        if !has_webhook {
            return Err(crate::error::Error::Config(format!(
                "provisioner {:?} is not authorized but no webhook applies to it",
                provisioner.name
            )));
        }
    }
    Ok(())
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
    /// Self-issued serving TLS for the standalone runtime. Enabled by default;
    /// ignored under AWS Lambda (TLS is terminated by the Function URL).
    #[serde(default)]
    pub tls: TlsConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            listen: default_listen(),
            external_url: None,
            tls: TlsConfig::default(),
        }
    }
}

fn default_listen() -> String {
    "0.0.0.0:9443".to_string()
}

/// Self-issued serving TLS settings.
///
/// When [`enabled`](Self::enabled) (the default), the standalone server mints a
/// leaf certificate from the configured CA, serves HTTPS with it, and renews it
/// in the background. The SAN set is resolved from [`dns_names`](Self::dns_names)
/// / [`ip_addresses`](Self::ip_addresses), else from `server.external_url`, else
/// a loopback fallback — see `crate::tls::resolve_sans`.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Serve HTTPS. When `false`, the standalone server serves plaintext HTTP
    /// (for deployments terminating TLS at a fronting proxy).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Explicit DNS SANs for the serving certificate.
    #[serde(default)]
    pub dns_names: Vec<String>,
    /// Explicit IP SANs for the serving certificate.
    #[serde(default)]
    pub ip_addresses: Vec<String>,
    /// Lifetime of each self-issued serving certificate.
    #[serde(default = "default_tls_validity")]
    pub validity: crate::duration::ConfigDuration,
    /// Re-issue this long before expiry. Defaults to one third of `validity`
    /// (so renewal happens at ~2/3 of the lifetime).
    #[serde(default)]
    pub renew_before: Option<crate::duration::ConfigDuration>,
    /// Maximum random amount subtracted from the renewal instant, to de-sync a
    /// fleet. Defaults to one twentieth of `validity`.
    #[serde(default)]
    pub renew_jitter: Option<crate::duration::ConfigDuration>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        TlsConfig {
            enabled: true,
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            validity: default_tls_validity(),
            renew_before: None,
            renew_jitter: None,
        }
    }
}

impl TlsConfig {
    /// The effective `renew_before`, defaulting to one third of `validity`.
    pub fn renew_before(&self) -> std::time::Duration {
        self.renew_before
            .map(crate::duration::ConfigDuration::get)
            .unwrap_or(self.validity.get() / 3)
    }

    /// The effective `renew_jitter`, defaulting to one twentieth of `validity`.
    pub fn renew_jitter(&self) -> std::time::Duration {
        self.renew_jitter
            .map(crate::duration::ConfigDuration::get)
            .unwrap_or(self.validity.get() / 20)
    }

    /// Reject configs that cannot be served, regardless of runtime. SAN
    /// resolution always yields a non-empty set, so there is no empty-SAN error.
    fn validate(&self) -> crate::error::Result<()> {
        for ip in &self.ip_addresses {
            ip.parse::<std::net::IpAddr>().map_err(|e| {
                crate::error::Error::Config(format!(
                    "server.tls.ip_addresses: invalid IP {ip:?}: {e}"
                ))
            })?;
        }
        if self.renew_before() >= self.validity.get() {
            return Err(crate::error::Error::Config(
                "server.tls.renew_before must be shorter than validity".into(),
            ));
        }
        Ok(())
    }
}

fn default_true() -> bool {
    true
}

fn default_tls_validity() -> crate::duration::ConfigDuration {
    crate::duration::ConfigDuration(std::time::Duration::from_secs(24 * 3600))
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_example_config() {
        let text = include_str!("../../examples/ayane.example.json");
        let config = super::Config::from_json(text).expect("example config parses");
        assert_eq!(config.provisioners.len(), 2);
        assert_eq!(config.provisioners[0].name, "ci-issuer");
        assert!(config.provisioners[0].effective_authorized());
        assert_eq!(config.provisioners[1].name, "github-actions");
        assert!(matches!(
            config.provisioners[1].kind,
            super::ProvisionerKind::Jwks { .. }
        ));
        // A jwks provisioner defaults to unauthorized and is gated by a webhook.
        assert!(!config.provisioners[1].effective_authorized());
        super::validate_provisioner_authorization(&config).expect("example is fail-closed clean");
        assert!(config.templates.contains_key("server"));
        assert_eq!(config.webhooks.len(), 3);
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
    fn parses_base64url_encoded_config() {
        use base64::Engine;
        let text = include_str!("../../examples/ayane.example.json");
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(text);
        let config = super::Config::from_base64url(&encoded).expect("base64url config parses");
        assert_eq!(config.provisioners.len(), 2);

        // A trailing newline (as an environment variable may carry) is tolerated.
        let config = super::Config::from_base64url(&format!("{encoded}\n"))
            .expect("trailing newline tolerated");
        assert_eq!(config.provisioners.len(), 2);
    }

    #[test]
    fn rejects_malformed_base64url_config() {
        assert!(super::Config::from_base64url("not base64!!!").is_err());
    }

    #[test]
    fn pem_source_requires_exactly_one_form() {
        // Neither `file` nor `pem` is an error now (caught at parse time).
        let text = r#"{ "ca": { "certificate": {}, "key": { "type": "file", "file": "k" } } }"#;
        assert!(super::Config::from_json(text).is_err());
    }

    const EC_JWK: &str = r#"{ "kty": "EC", "crv": "P-256", "alg": "ES256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" }"#;

    fn config_with(provisioners: &str, webhooks: &str) -> super::Config {
        let text = format!(
            r#"{{
                "ca": {{ "certificate": {{ "file": "ca.crt" }}, "key": {{ "type": "file", "file": "ca.key" }} }},
                "provisioners": {provisioners},
                "webhooks": {webhooks}
            }}"#
        );
        super::Config::from_json(&text).expect("config parses")
    }

    #[test]
    fn jwk_provisioner_defaults_to_authorized() {
        let provisioners = format!(r#"[{{ "name": "p", "type": "jwk", "key": {EC_JWK} }}]"#);
        let config = config_with(&provisioners, "[]");
        assert!(matches!(
            config.provisioners[0].kind,
            super::ProvisionerKind::Jwk { .. }
        ));
        assert!(config.provisioners[0].effective_authorized());
    }

    #[test]
    fn authorized_flag_overrides_kind_default() {
        let provisioners =
            format!(r#"[{{ "name": "p", "type": "jwk", "authorized": false, "key": {EC_JWK} }}]"#);
        let config = config_with(&provisioners, "[]");
        assert!(!config.provisioners[0].effective_authorized());
    }

    #[test]
    fn unauthorized_provisioner_requires_an_applicable_webhook() {
        let provisioners =
            format!(r#"[{{ "name": "p", "type": "jwk", "authorized": false, "key": {EC_JWK} }}]"#);

        let no_webhook = config_with(&provisioners, "[]");
        assert!(super::validate_provisioner_authorization(&no_webhook).is_err());

        let scoped = r#"[{ "name": "gate", "provisioners": ["p"],
            "target": { "type": "http", "url": "https://h.example/hook" } }]"#;
        assert!(
            super::validate_provisioner_authorization(&config_with(&provisioners, scoped)).is_ok()
        );

        // A webhook that applies to all provisioners (empty list) also qualifies.
        let all = r#"[{ "name": "gate",
            "target": { "type": "http", "url": "https://h.example/hook" } }]"#;
        assert!(
            super::validate_provisioner_authorization(&config_with(&provisioners, all)).is_ok()
        );

        // A webhook scoped to a different provisioner does not.
        let other = r#"[{ "name": "gate", "provisioners": ["other"],
            "target": { "type": "http", "url": "https://h.example/hook" } }]"#;
        assert!(
            super::validate_provisioner_authorization(&config_with(&provisioners, other)).is_err()
        );
    }

    #[test]
    fn authorized_provisioner_needs_no_webhook() {
        let provisioners = format!(r#"[{{ "name": "p", "type": "jwk", "key": {EC_JWK} }}]"#);
        let config = config_with(&provisioners, "[]");
        assert!(super::validate_provisioner_authorization(&config).is_ok());
    }
}
