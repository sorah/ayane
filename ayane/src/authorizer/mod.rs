//! Token authorization: validates the externally-provided JWT that authorizes
//! an issuance or revocation.
//!
//! The authorizer is intentionally storage-free: it proves a token is
//! authentic and well-formed and returns its claims. One-time (anti-replay)
//! enforcement of the `jti` is performed by [`crate::service`] against
//! [`crate::storage`], using the [`jti`](ayane_protocol::OttClaims::jti) this
//! returns.

pub mod jwks;
pub mod jwt;

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

/// Dispatches token validation to the sub-authorizer that owns the token's
/// issuer. The provider set is small, so a linear scan is used rather than a map.
pub struct Authorizers {
    providers: Vec<(Vec<String>, std::sync::Arc<dyn Authorizer>)>,
}

impl Authorizers {
    /// Assemble a router over `(issuers, authorizer)` pairs. An issuer claimed by
    /// more than one provider is a configuration error.
    pub fn new(
        providers: Vec<(Vec<String>, std::sync::Arc<dyn Authorizer>)>,
    ) -> crate::error::Result<Self> {
        let mut seen = std::collections::HashSet::new();
        for (issuers, _) in &providers {
            for issuer in issuers {
                if !seen.insert(issuer.clone()) {
                    return Err(crate::error::Error::Config(format!(
                        "provisioner issuer {issuer:?} is claimed by more than one provisioner"
                    )));
                }
            }
        }
        Ok(Authorizers { providers })
    }
}

#[async_trait::async_trait]
impl Authorizer for Authorizers {
    async fn validate(&self, token: &str, audience: &str) -> crate::error::Result<ValidatedToken> {
        let issuer = unverified_issuer(token)?;
        for (issuers, provider) in &self.providers {
            if issuers.iter().any(|i| i == &issuer) {
                return provider.validate(token, audience).await;
            }
        }
        Err(crate::error::Error::Unauthorized(format!(
            "unknown provisioner {issuer:?}"
        )))
    }

    fn provisioners(&self) -> Vec<ayane_protocol::ProvisionerInfo> {
        self.providers
            .iter()
            .flat_map(|(_, provider)| provider.provisioners())
            .collect()
    }
}
