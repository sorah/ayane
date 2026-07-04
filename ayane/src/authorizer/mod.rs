//! Token authorization: validates the externally-provided JWT that authorizes
//! an issuance or revocation.
//!
//! The authorizer is intentionally storage-free: it proves a token is
//! authentic and well-formed and returns its claims. One-time (anti-replay)
//! enforcement of the `jti` is performed by [`crate::service`] against
//! [`crate::storage`], using the [`jti`](ayane_protocol::OttClaims::jti) this
//! returns.

mod jwk;
mod jwks;

/// A token that has passed signature and registered-claim validation.
pub struct ValidatedToken {
    /// The provisioner that issued (and verified) the token.
    pub provisioner: String,
    /// The decoded claims.
    pub claims: ayane_protocol::OttClaims,
    /// Template name override carried by the provisioner, if any.
    pub template: Option<String>,
    /// Whether the provisioner authorizes issuance on its own. When `false`, an
    /// authorize webhook must explicitly grant the request.
    pub authorized: bool,
    /// Anti-replay identifier: the token's `jti` when present, otherwise a value
    /// derived from the token so one-time enforcement still applies.
    pub replay_id: String,
}

/// Validates issuance/revocation tokens.
#[async_trait::async_trait]
pub trait Authorizer: Send + Sync {
    /// Validate `token`, requiring its `aud` claim to match `audience` (one of
    /// the server's accepted audiences for the operation). Returns the decoded,
    /// verified claims. Does **not** enforce one-time use.
    async fn validate(&self, token: &str, audience: &str) -> crate::error::Result<ValidatedToken>;

    /// Public, non-secret description of configured provisioners.
    fn provisioners(&self) -> Vec<ayane_protocol::ProvisionerInfo>;
}

/// The normalized result of authenticating a presented token.
pub(crate) struct VerifiedToken {
    /// Decoded, verified claims.
    pub claims: ayane_protocol::OttClaims,
    /// Anti-replay identifier (the token's `jti`, or a value derived from it).
    pub replay_id: String,
}

/// Non-secret description of a verifier, for `GET /v1/provisioners`.
pub(crate) struct VerifierInfo {
    /// Scheme name, e.g. `"jwk"` or `"jwks"`.
    pub kind: &'static str,
    /// Accepted token audiences.
    pub audiences: Vec<String>,
}

/// Scheme-specific verification of a presented bearer token. One implementation
/// per authentication scheme (a static JWK, a remote JWKS, ...). This layer only
/// *authenticates* the token and extracts its claims — authorization (the
/// `authorized` flag and webhook gating) is applied by [`ProvisionerAuthorizer`]
/// and [`crate::service`], not here.
#[async_trait::async_trait]
pub(crate) trait TokenVerifier: Send + Sync {
    /// Unauthenticated pre-check used to route a token to its provisioner (for
    /// JWT schemes, the unverified `iss`). Must not depend on the signature.
    fn matches(&self, token: &str) -> bool;

    /// Authenticate `token`, binding it to `audience`, and return its claims.
    async fn verify(&self, token: &str, audience: &str) -> crate::error::Result<VerifiedToken>;

    /// Non-secret description for public listing.
    fn describe(&self) -> VerifierInfo;
}

/// A configured provisioner: CA-level policy (name, template, whether a verified
/// token alone authorizes issuance) plus the scheme-specific [`TokenVerifier`]
/// that authenticates its tokens.
struct Provisioner {
    name: String,
    template: Option<String>,
    authorized: bool,
    verifier: Box<dyn TokenVerifier>,
}

/// An [`Authorizer`] over a flat set of provisioners. A token is routed to the
/// first provisioner whose verifier claims it, then verified. The set is small,
/// so a linear scan is used.
pub struct ProvisionerAuthorizer {
    provisioners: Vec<Provisioner>,
}

impl ProvisionerAuthorizer {
    /// Build every provisioner from configuration.
    pub fn from_configs(
        configs: &[crate::config::ProvisionerConfig],
    ) -> crate::error::Result<Self> {
        // One shared HTTP client for every jwks provisioner, built only when one
        // exists so a key-only deployment never loads the HTTP stack.
        let http = if configs
            .iter()
            .any(|c| matches!(c.kind, crate::config::ProvisionerKind::Jwks { .. }))
        {
            Some(jwks::http_client()?)
        } else {
            None
        };

        let mut seen_issuers = std::collections::HashSet::new();
        let mut provisioners = Vec::with_capacity(configs.len());
        for cfg in configs {
            let issuer = cfg.expected_issuer();
            if !seen_issuers.insert(issuer.clone()) {
                return Err(crate::error::Error::Config(format!(
                    "provisioner issuer {issuer:?} is claimed by more than one provisioner"
                )));
            }
            let verifier: Box<dyn TokenVerifier> = match &cfg.kind {
                crate::config::ProvisionerKind::Jwk { key } => {
                    Box::new(jwk::JwkVerifier::new(cfg, key)?)
                }
                crate::config::ProvisionerKind::Jwks { jwks } => {
                    let client = http
                        .clone()
                        .expect("http client is built when a jwks provisioner exists");
                    Box::new(jwks::JwksVerifier::new(cfg, jwks, client)?)
                }
            };
            provisioners.push(Provisioner {
                name: cfg.name.clone(),
                template: cfg.template.clone(),
                authorized: cfg.effective_authorized(),
                verifier,
            });
        }
        Ok(ProvisionerAuthorizer { provisioners })
    }
}

#[async_trait::async_trait]
impl Authorizer for ProvisionerAuthorizer {
    async fn validate(&self, token: &str, audience: &str) -> crate::error::Result<ValidatedToken> {
        let provisioner = self
            .provisioners
            .iter()
            .find(|p| p.verifier.matches(token))
            .ok_or_else(|| {
                let issuer = unverified_issuer(token).unwrap_or_else(|_| "<unknown>".to_string());
                crate::error::Error::Unauthorized(format!("unknown provisioner {issuer:?}"))
            })?;
        let verified = provisioner.verifier.verify(token, audience).await?;
        Ok(ValidatedToken {
            provisioner: provisioner.name.clone(),
            claims: verified.claims,
            template: provisioner.template.clone(),
            authorized: provisioner.authorized,
            replay_id: verified.replay_id,
        })
    }

    fn provisioners(&self) -> Vec<ayane_protocol::ProvisionerInfo> {
        self.provisioners
            .iter()
            .map(|p| {
                let info = p.verifier.describe();
                ayane_protocol::ProvisionerInfo {
                    name: p.name.clone(),
                    kind: info.kind.to_string(),
                    audiences: info.audiences,
                    authorized: p.authorized,
                }
            })
            .collect()
    }
}

/// A verification key paired with the single JWS algorithm permitted for it. The
/// algorithm is pinned by the key type, closing the algorithm-confusion class of
/// attacks (the token header's `alg` is never trusted).
pub(crate) struct SigningKey {
    pub decoding_key: jsonwebtoken::DecodingKey,
    pub algorithm: jsonwebtoken::Algorithm,
}

/// Build a [`SigningKey`] from a JWK, deriving the pinned algorithm from the key
/// type. Returns a human-readable message on failure so callers can wrap it in
/// the error kind appropriate to their context (config vs. runtime).
pub(crate) fn signing_key_from_jwk(
    jwk: &jsonwebtoken::jwk::Jwk,
) -> std::result::Result<SigningKey, String> {
    let decoding_key =
        jsonwebtoken::DecodingKey::from_jwk(jwk).map_err(|e| format!("invalid JWK: {e}"))?;
    let algorithm =
        algorithm_from_jwk(jwk).ok_or_else(|| "cannot determine algorithm from JWK".to_string())?;
    Ok(SigningKey {
        decoding_key,
        algorithm,
    })
}

/// Map a JWK to the single JWT algorithm permitted for it.
pub(crate) fn algorithm_from_jwk(jwk: &jsonwebtoken::jwk::Jwk) -> Option<jsonwebtoken::Algorithm> {
    match &jwk.algorithm {
        jsonwebtoken::jwk::AlgorithmParameters::EllipticCurve(ec) => match ec.curve {
            jsonwebtoken::jwk::EllipticCurve::P256 => Some(jsonwebtoken::Algorithm::ES256),
            jsonwebtoken::jwk::EllipticCurve::P384 => Some(jsonwebtoken::Algorithm::ES384),
            _ => None,
        },
        jsonwebtoken::jwk::AlgorithmParameters::RSA(_) => {
            // Honor an explicit RSA algorithm hint; otherwise default to RS256.
            match jwk.common.key_algorithm {
                Some(jsonwebtoken::jwk::KeyAlgorithm::RS384) => {
                    Some(jsonwebtoken::Algorithm::RS384)
                }
                Some(jsonwebtoken::jwk::KeyAlgorithm::RS512) => {
                    Some(jsonwebtoken::Algorithm::RS512)
                }
                Some(jsonwebtoken::jwk::KeyAlgorithm::PS256) => {
                    Some(jsonwebtoken::Algorithm::PS256)
                }
                Some(jsonwebtoken::jwk::KeyAlgorithm::PS384) => {
                    Some(jsonwebtoken::Algorithm::PS384)
                }
                Some(jsonwebtoken::jwk::KeyAlgorithm::PS512) => {
                    Some(jsonwebtoken::Algorithm::PS512)
                }
                _ => Some(jsonwebtoken::Algorithm::RS256),
            }
        }
        jsonwebtoken::jwk::AlgorithmParameters::OctetKeyPair(okp) => match okp.curve {
            jsonwebtoken::jwk::EllipticCurve::Ed25519 => Some(jsonwebtoken::Algorithm::EdDSA),
            _ => None,
        },
        _ => None,
    }
}

/// Read the `iss` claim without verifying the signature, to select the
/// provisioner whose key should verify the token.
pub(crate) fn unverified_issuer(token: &str) -> crate::error::Result<String> {
    use base64::Engine;
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| crate::error::Error::Unauthorized("malformed token".into()))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| crate::error::Error::Unauthorized("malformed token payload".into()))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| crate::error::Error::Unauthorized("malformed token payload".into()))?;
    value
        .get("iss")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| crate::error::Error::Unauthorized("token missing iss claim".into()))
}

/// Derive a stable anti-replay identifier for a token that carries no `jti`.
/// Hashing the whole signed token yields a value unique to that credential.
fn replay_id_from_token(token: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(token.as_bytes()))
}

/// Verify a token's signature and registered claims against a resolved key, and
/// return its claims plus the anti-replay id. Shared by every [`Authorizer`]
/// implementation so signature/claim policy lives in exactly one place.
///
/// `nbf` is validated when present but not required: public OIDC issuers do not
/// always emit it. The accepted algorithm is pinned by `key`, not the header.
pub(crate) fn validate_signed(
    token: &str,
    audience: &str,
    issuer: &str,
    audiences: &[String],
    key: &SigningKey,
    leeway_secs: u64,
) -> crate::error::Result<(ayane_protocol::OttClaims, String)> {
    let mut validation = jsonwebtoken::Validation::new(key.algorithm);
    validation.set_issuer(&[issuer]);
    // Bind the token to the request endpoint by default: require `aud` to equal
    // the per-endpoint `audience` (the request URL). A non-empty provisioner
    // audience list opts into a fixed allowlist instead.
    if audiences.is_empty() {
        validation.set_audience(&[audience]);
    } else {
        let audiences: Vec<&str> = audiences.iter().map(String::as_str).collect();
        validation.set_audience(&audiences);
    }
    validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
    validation.validate_nbf = true;
    validation.validate_aud = true;
    validation.leeway = leeway_secs;

    let data =
        jsonwebtoken::decode::<ayane_protocol::OttClaims>(token, &key.decoding_key, &validation)
            .map_err(|e| {
                crate::error::Error::Unauthorized(format!("token validation failed: {e}"))
            })?;
    let replay_id = data
        .claims
        .jti
        .clone()
        .unwrap_or_else(|| replay_id_from_token(token));
    Ok((data.claims, replay_id))
}
