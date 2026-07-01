//! JWKS-based [`Authorizer`](crate::authorizer::Authorizer) implementation.
//!
//! A `jwks` provisioner validates tokens minted by an external issuer whose
//! verification keys are published as a JSON Web Key Set — fetched directly from
//! a `jwks_url`, or discovered from an OpenID Connect
//! `.well-known/openid-configuration` document. Keys are cached in-process and
//! refetched on demand (on staleness or an unknown `kid`, so key rotation is
//! picked up without a restart).
//!
//! Such tokens only *authenticate* the caller; a `jwks` provisioner defaults to
//! `authorized = false`, so an authorize webhook must grant each request. As
//! with `jwk`, the accepted algorithm is pinned to the key type by
//! [`crate::authorizer::validate_signed`].

/// Where a key set is fetched from.
enum JwksLocation {
    /// A JWK Set document URL.
    Direct(String),
    /// An OIDC discovery document URL; its `jwks_uri` is followed to the keys.
    Oidc(String),
}

/// A cached JWK Set with the freshness window derived from the fetch.
struct CachedKeyset {
    keys: Vec<jsonwebtoken::jwk::Jwk>,
    fetched_at: std::time::Instant,
    ttl: std::time::Duration,
}

impl CachedKeyset {
    fn fresh(&self) -> bool {
        self.fetched_at.elapsed() < self.ttl
    }
}

/// A remote key set with an in-process cache.
pub struct JwksSource {
    issuer: String,
    location: JwksLocation,
    client: reqwest::Client,
    memo: tokio::sync::RwLock<Option<CachedKeyset>>,
    /// Serializes refetches so concurrent callers share one network round-trip.
    single_flight: tokio::sync::Mutex<()>,
    /// Lower bound between refetches; bounds the cost of unknown-`kid` tokens.
    min_refetch: std::time::Duration,
}

/// Minimal view of an OIDC discovery document.
#[derive(serde::Deserialize)]
struct OidcDiscovery {
    issuer: String,
    jwks_uri: String,
}

/// Default key-set lifetime when the response carries no usable `Cache-Control`.
const DEFAULT_TTL: std::time::Duration = std::time::Duration::from_secs(3600);
/// Clamp bounds for a `Cache-Control: max-age` derived lifetime.
const MIN_TTL: std::time::Duration = std::time::Duration::from_secs(300);
const MAX_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

impl JwksSource {
    fn new(
        issuer: String,
        jwks: &crate::config::JwksConfig,
        client: reqwest::Client,
        name: &str,
    ) -> crate::error::Result<Self> {
        let location = match (&jwks.jwks_url, &jwks.openid_configuration_url) {
            (Some(url), None) => {
                require_secure_url(url, name)?;
                JwksLocation::Direct(url.clone())
            }
            (None, Some(url)) => {
                require_secure_url(url, name)?;
                JwksLocation::Oidc(url.clone())
            }
            (Some(_), Some(_)) => {
                return Err(crate::error::Error::Config(format!(
                    "provisioner {name:?}: set only one of `jwks_url` / `openid_configuration_url`"
                )));
            }
            (None, None) => {
                return Err(crate::error::Error::Config(format!(
                    "provisioner {name:?}: `jwks` requires `jwks_url` or `openid_configuration_url`"
                )));
            }
        };
        Ok(JwksSource {
            issuer,
            location,
            client,
            memo: tokio::sync::RwLock::new(None),
            single_flight: tokio::sync::Mutex::new(()),
            min_refetch: std::time::Duration::from_secs(60),
        })
    }

    /// Resolve the pinned key for a token bearing the given `kid`. Serves from
    /// cache when possible, refetching on staleness or a `kid` miss (rotation).
    async fn resolve(
        &self,
        kid: Option<&str>,
    ) -> crate::error::Result<crate::authorizer::SigningKey> {
        // Fast path: a fresh cache that already contains the key.
        if let Some(cached) = self.memo.read().await.as_ref()
            && cached.fresh()
            && let Some(jwk) = select_key(&cached.keys, kid)
        {
            return self.to_signing_key(&jwk);
        }
        // Stale, empty, or missing the key: refresh once and retry.
        self.refresh().await?;
        let guard = self.memo.read().await;
        let cached = guard.as_ref().ok_or_else(|| {
            crate::error::Error::Internal("JWKS cache empty after refresh".into())
        })?;
        let jwk = select_key(&cached.keys, kid).ok_or_else(|| {
            crate::error::Error::Unauthorized(format!("no verification key for kid {kid:?}"))
        })?;
        self.to_signing_key(&jwk)
    }

    async fn refresh(&self) -> crate::error::Result<()> {
        let _flight = self.single_flight.lock().await;
        // A concurrent caller may have refreshed while we waited; also rate-limit
        // so unknown-`kid` tokens cannot force unbounded refetches.
        if let Some(cached) = self.memo.read().await.as_ref()
            && cached.fetched_at.elapsed() < self.min_refetch
        {
            return Ok(());
        }
        let (keys, ttl) = self.fetch().await?;
        *self.memo.write().await = Some(CachedKeyset {
            keys,
            fetched_at: std::time::Instant::now(),
            ttl,
        });
        Ok(())
    }

    async fn fetch(
        &self,
    ) -> crate::error::Result<(Vec<jsonwebtoken::jwk::Jwk>, std::time::Duration)> {
        let jwks_url = match &self.location {
            JwksLocation::Direct(url) => std::borrow::Cow::Borrowed(url.as_str()),
            JwksLocation::Oidc(discovery) => {
                let resp = self.client.get(discovery).send().await.map_err(|e| {
                    crate::error::Error::Internal(format!("fetch OIDC discovery {discovery}: {e}"))
                })?;
                if !resp.status().is_success() {
                    return Err(crate::error::Error::Internal(format!(
                        "OIDC discovery {discovery} returned HTTP {}",
                        resp.status()
                    )));
                }
                let doc: OidcDiscovery = resp.json().await.map_err(|e| {
                    crate::error::Error::Internal(format!("parse OIDC discovery {discovery}: {e}"))
                })?;
                if doc.issuer != self.issuer {
                    return Err(crate::error::Error::Internal(format!(
                        "OIDC issuer mismatch: discovery declares {:?}, configured {:?}",
                        doc.issuer, self.issuer
                    )));
                }
                if !is_secure_url(&doc.jwks_uri) {
                    return Err(crate::error::Error::Internal(format!(
                        "OIDC jwks_uri {:?} is not https",
                        doc.jwks_uri
                    )));
                }
                std::borrow::Cow::Owned(doc.jwks_uri)
            }
        };

        let resp = self
            .client
            .get(jwks_url.as_ref())
            .send()
            .await
            .map_err(|e| crate::error::Error::Internal(format!("fetch JWKS {jwks_url}: {e}")))?;
        if !resp.status().is_success() {
            return Err(crate::error::Error::Internal(format!(
                "JWKS {jwks_url} returned HTTP {}",
                resp.status()
            )));
        }
        let ttl = cache_control_ttl(resp.headers());
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| crate::error::Error::Internal(format!("read JWKS {jwks_url}: {e}")))?;
        let set: jsonwebtoken::jwk::JwkSet = serde_json::from_slice(&bytes)
            .map_err(|e| crate::error::Error::Internal(format!("parse JWKS {jwks_url}: {e}")))?;
        Ok((set.keys, ttl))
    }

    fn to_signing_key(
        &self,
        jwk: &jsonwebtoken::jwk::Jwk,
    ) -> crate::error::Result<crate::authorizer::SigningKey> {
        crate::authorizer::signing_key_from_jwk(jwk).map_err(|e| {
            crate::error::Error::Unauthorized(format!("provisioner issuer {:?}: {e}", self.issuer))
        })
    }
}

struct JwksEntry {
    name: String,
    issuer: String,
    audiences: Vec<String>,
    template: Option<String>,
    authorized: bool,
    source: JwksSource,
}

/// An [`Authorizer`](crate::authorizer::Authorizer) over `jwks` provisioners.
pub struct JwksAuthorizer {
    entries: Vec<JwksEntry>,
    leeway_secs: u64,
}

impl JwksAuthorizer {
    /// Build from provisioner configuration, keeping only `jwks` provisioners.
    pub fn from_configs(
        configs: &[crate::config::ProvisionerConfig],
    ) -> crate::error::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| crate::error::Error::Config(format!("jwks http client: {e}")))?;
        let mut entries = Vec::new();
        for cfg in configs {
            let jwks = match &cfg.kind {
                crate::config::ProvisionerKind::Jwks { jwks } => jwks,
                crate::config::ProvisionerKind::Jwk { .. } => continue,
            };
            if cfg.audiences.is_empty() {
                return Err(crate::error::Error::Config(format!(
                    "provisioner {:?}: `jwks` requires a non-empty `audiences`",
                    cfg.name
                )));
            }
            let issuer = jwks.resolved_issuer(&cfg.name);
            let source = JwksSource::new(issuer.clone(), jwks, client.clone(), &cfg.name)?;
            entries.push(JwksEntry {
                name: cfg.name.clone(),
                issuer,
                audiences: cfg.audiences.clone(),
                template: cfg.template.clone(),
                authorized: cfg.effective_authorized(),
                source,
            });
        }
        Ok(JwksAuthorizer {
            entries,
            leeway_secs: 60,
        })
    }

    fn find(&self, issuer: &str) -> Option<&JwksEntry> {
        self.entries.iter().find(|e| e.issuer == issuer)
    }

    /// The issuers this authorizer handles, for the
    /// [`Authorizers`](crate::authorizer::Authorizers) router.
    pub fn issuers(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.issuer.clone()).collect()
    }
}

#[async_trait::async_trait]
impl crate::authorizer::Authorizer for JwksAuthorizer {
    async fn validate(
        &self,
        token: &str,
        audience: &str,
    ) -> crate::error::Result<crate::authorizer::ValidatedToken> {
        let issuer = crate::authorizer::unverified_issuer(token)?;
        let entry = self.find(&issuer).ok_or_else(|| {
            crate::error::Error::Unauthorized(format!("unknown provisioner {issuer:?}"))
        })?;
        let header = jsonwebtoken::decode_header(token).map_err(|e| {
            crate::error::Error::Unauthorized(format!("malformed token header: {e}"))
        })?;
        let key = entry.source.resolve(header.kid.as_deref()).await?;

        let (claims, replay_id) = crate::authorizer::validate_signed(
            token,
            audience,
            &entry.issuer,
            &entry.audiences,
            &key,
            self.leeway_secs,
        )?;
        Ok(crate::authorizer::ValidatedToken {
            provisioner: entry.name.clone(),
            claims,
            template: entry.template.clone(),
            authorized: entry.authorized,
            replay_id,
        })
    }

    fn provisioners(&self) -> Vec<ayane_protocol::ProvisionerInfo> {
        self.entries
            .iter()
            .map(|e| ayane_protocol::ProvisionerInfo {
                name: e.name.clone(),
                kind: "jwks".to_string(),
                audiences: e.audiences.clone(),
                authorized: e.authorized,
            })
            .collect()
    }
}

/// Pick the verification key for a token: by `kid` when the header carries one,
/// otherwise the sole key (a key set with several keys and no `kid` is
/// ambiguous and rejected).
fn select_key(
    keys: &[jsonwebtoken::jwk::Jwk],
    kid: Option<&str>,
) -> Option<jsonwebtoken::jwk::Jwk> {
    match kid {
        Some(kid) => keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid))
            .cloned(),
        None => match keys {
            [only] => Some(only.clone()),
            _ => None,
        },
    }
}

/// Whether a URL may be fetched: https anywhere, or http to a loopback host (a
/// local IdP or a test server).
fn is_secure_url(url: &str) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    for prefix in ["http://127.0.0.1", "http://localhost", "http://[::1]"] {
        if let Some(rest) = url.strip_prefix(prefix)
            && (rest.is_empty() || rest.starts_with(':') || rest.starts_with('/'))
        {
            return true;
        }
    }
    false
}

fn require_secure_url(url: &str, name: &str) -> crate::error::Result<()> {
    if is_secure_url(url) {
        Ok(())
    } else {
        Err(crate::error::Error::Config(format!(
            "provisioner {name:?}: {url:?} must be https (http is allowed only for loopback)"
        )))
    }
}

/// Derive a cache lifetime from a `Cache-Control: max-age`, clamped to a sane
/// window; falls back to [`DEFAULT_TTL`] when absent or unparseable.
fn cache_control_ttl(headers: &reqwest::header::HeaderMap) -> std::time::Duration {
    let Some(value) = headers
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
    else {
        return DEFAULT_TTL;
    };
    for directive in value.split(',') {
        let directive = directive.trim();
        if let Some(seconds) = directive.strip_prefix("max-age=")
            && let Ok(seconds) = seconds.parse::<u64>()
        {
            return std::time::Duration::from_secs(seconds).clamp(MIN_TTL, MAX_TTL);
        }
    }
    DEFAULT_TTL
}

#[cfg(test)]
mod tests {
    fn jwk_with_kid(kid: Option<&str>) -> jsonwebtoken::jwk::Jwk {
        let mut value = serde_json::json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        });
        if let Some(kid) = kid {
            value["kid"] = serde_json::Value::String(kid.to_string());
        }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn select_key_matches_by_kid() {
        let keys = vec![jwk_with_kid(Some("a")), jwk_with_kid(Some("b"))];
        assert!(super::select_key(&keys, Some("b")).is_some());
        assert!(super::select_key(&keys, Some("missing")).is_none());
    }

    #[test]
    fn select_key_without_kid_requires_single_key() {
        let one = vec![jwk_with_kid(None)];
        assert!(super::select_key(&one, None).is_some());

        let many = vec![jwk_with_kid(Some("a")), jwk_with_kid(Some("b"))];
        assert!(super::select_key(&many, None).is_none());
    }

    #[test]
    fn is_secure_url_allows_https_and_loopback() {
        assert!(super::is_secure_url("https://idp.example.com/keys"));
        assert!(super::is_secure_url("http://127.0.0.1:8080/keys"));
        assert!(super::is_secure_url("http://localhost/keys"));
        assert!(!super::is_secure_url("http://idp.example.com/keys"));
    }

    fn jwks_config(
        jwks_url: Option<&str>,
        oidc_url: Option<&str>,
        issuer: Option<&str>,
    ) -> crate::config::ProvisionerConfig {
        crate::config::ProvisionerConfig {
            name: "gh".to_string(),
            audiences: vec!["https://ca.example.com".to_string()],
            template: None,
            authorized: None,
            kind: crate::config::ProvisionerKind::Jwks {
                jwks: crate::config::JwksConfig {
                    jwks_url: jwks_url.map(str::to_string),
                    openid_configuration_url: oidc_url.map(str::to_string),
                    issuer: issuer.map(str::to_string),
                },
            },
        }
    }

    #[test]
    fn from_configs_accepts_either_url_form() {
        assert!(
            super::JwksAuthorizer::from_configs(&[jwks_config(
                Some("https://idp.example.com/keys"),
                None,
                Some("https://idp.example.com"),
            )])
            .is_ok()
        );
        assert!(
            super::JwksAuthorizer::from_configs(&[jwks_config(
                None,
                Some(
                    "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
                ),
                None,
            )])
            .is_ok()
        );
    }

    #[test]
    fn from_configs_rejects_invalid_combinations() {
        // Both URL forms set.
        assert!(
            super::JwksAuthorizer::from_configs(&[jwks_config(
                Some("https://idp.example.com/keys"),
                Some("https://idp.example.com/.well-known/openid-configuration"),
                None,
            )])
            .is_err()
        );
        // Neither URL form set.
        assert!(super::JwksAuthorizer::from_configs(&[jwks_config(None, None, None)]).is_err());
        // Non-https URL.
        assert!(
            super::JwksAuthorizer::from_configs(&[jwks_config(
                Some("http://idp.example.com/keys"),
                None,
                Some("https://idp.example.com"),
            )])
            .is_err()
        );
    }

    #[test]
    fn from_configs_requires_audiences() {
        let mut cfg = jwks_config(
            Some("https://idp.example.com/keys"),
            None,
            Some("https://idp.example.com"),
        );
        cfg.audiences.clear();
        assert!(super::JwksAuthorizer::from_configs(&[cfg]).is_err());
    }

    #[test]
    fn oidc_issuer_is_derived_from_discovery_url() {
        let cfg = jwks_config(
            None,
            Some("https://token.actions.githubusercontent.com/.well-known/openid-configuration"),
            None,
        );
        let authorizer = super::JwksAuthorizer::from_configs(&[cfg]).unwrap();
        assert_eq!(
            authorizer.issuers(),
            vec!["https://token.actions.githubusercontent.com".to_string()]
        );
    }
}
