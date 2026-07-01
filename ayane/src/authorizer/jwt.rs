//! JWT/JWK-based [`Authorizer`](crate::authorizer::Authorizer) implementation.
//!
//! Each provisioner is a name plus a public JWK. A token is matched to a
//! provisioner by its `iss` claim, then verified with that provisioner's key.
//! The accepted algorithm is pinned to the one implied by the JWK, which closes
//! the JWT algorithm-confusion class of attacks (an attacker cannot downgrade an
//! EC verification key to HMAC, etc.).

struct ProvisionerEntry {
    name: String,
    decoding_key: jsonwebtoken::DecodingKey,
    algorithm: jsonwebtoken::Algorithm,
    audiences: Vec<String>,
    template: Option<String>,
    authorized: bool,
}

/// An [`Authorizer`](crate::authorizer::Authorizer) over a fixed set of JWK
/// provisioners.
pub struct JwtAuthorizer {
    provisioners: Vec<ProvisionerEntry>,
    leeway_secs: u64,
}

impl JwtAuthorizer {
    /// Build from provisioner configuration.
    pub fn from_configs(
        configs: &[crate::config::ProvisionerConfig],
    ) -> crate::error::Result<Self> {
        let mut provisioners = Vec::with_capacity(configs.len());
        for cfg in configs {
            let crate::config::ProvisionerKind::Jwk { key } = &cfg.kind;
            let decoding_key = jsonwebtoken::DecodingKey::from_jwk(key).map_err(|e| {
                crate::error::Error::Config(format!("provisioner {:?}: invalid JWK: {e}", cfg.name))
            })?;
            let algorithm = algorithm_from_jwk(key).ok_or_else(|| {
                crate::error::Error::Config(format!(
                    "provisioner {:?}: cannot determine algorithm from JWK",
                    cfg.name
                ))
            })?;
            provisioners.push(ProvisionerEntry {
                name: cfg.name.clone(),
                decoding_key,
                algorithm,
                audiences: cfg.audiences.clone(),
                template: cfg.template.clone(),
                authorized: cfg.effective_authorized(),
            });
        }
        Ok(JwtAuthorizer {
            provisioners,
            leeway_secs: 60,
        })
    }

    fn find(&self, issuer: &str) -> Option<&ProvisionerEntry> {
        self.provisioners.iter().find(|p| p.name == issuer)
    }
}

/// Map a JWK to the single JWT algorithm permitted for it.
fn algorithm_from_jwk(jwk: &jsonwebtoken::jwk::Jwk) -> Option<jsonwebtoken::Algorithm> {
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

/// Derive a stable anti-replay identifier for a token that carries no `jti`.
/// Hashing the whole signed token yields a value unique to that credential.
fn replay_id_from_token(token: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(token.as_bytes()))
}

/// Read the `iss` claim without verifying the signature, to select the
/// provisioner whose key should verify the token.
fn unverified_issuer(token: &str) -> crate::error::Result<String> {
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

#[async_trait::async_trait]
impl crate::authorizer::Authorizer for JwtAuthorizer {
    async fn validate(
        &self,
        token: &str,
        audience: &str,
    ) -> crate::error::Result<crate::authorizer::ValidatedToken> {
        let issuer = unverified_issuer(token)?;
        let entry = self.find(&issuer).ok_or_else(|| {
            crate::error::Error::Unauthorized(format!("unknown provisioner {issuer:?}"))
        })?;

        let mut validation = jsonwebtoken::Validation::new(entry.algorithm);
        validation.set_issuer(&[entry.name.as_str()]);
        // Bind the token to the request endpoint by default: require `aud` to
        // equal the per-endpoint `audience` (the request URL). An explicit,
        // non-empty provisioner audience list opts into a fixed allowlist
        // instead (the operator is then responsible for endpoint scoping).
        if entry.audiences.is_empty() {
            validation.set_audience(&[audience]);
        } else {
            let audiences: Vec<&str> = entry.audiences.iter().map(String::as_str).collect();
            validation.set_audience(&audiences);
        }
        // `nbf` is validated when present but not required: public OIDC issuers
        // do not always emit it.
        validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
        validation.validate_nbf = true;
        validation.validate_aud = true;
        validation.leeway = self.leeway_secs;

        let data = jsonwebtoken::decode::<ayane_protocol::OttClaims>(
            token,
            &entry.decoding_key,
            &validation,
        )
        .map_err(|e| crate::error::Error::Unauthorized(format!("token validation failed: {e}")))?;

        let replay_id = data
            .claims
            .jti
            .clone()
            .unwrap_or_else(|| replay_id_from_token(token));
        Ok(crate::authorizer::ValidatedToken {
            provisioner: entry.name.clone(),
            claims: data.claims,
            template: entry.template.clone(),
            authorized: entry.authorized,
            replay_id,
        })
    }

    fn provisioners(&self) -> Vec<ayane_protocol::ProvisionerInfo> {
        self.provisioners
            .iter()
            .map(|p| ayane_protocol::ProvisionerInfo {
                name: p.name.clone(),
                kind: "jwk".to_string(),
                audiences: p.audiences.clone(),
                authorized: p.authorized,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::authorizer::Authorizer;

    fn b64url(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    struct Fixture {
        authorizer: super::JwtAuthorizer,
        encoding_key: jsonwebtoken::EncodingKey,
    }

    fn fixture() -> Fixture {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::pkcs8::EncodePrivateKey;

        let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let pkcs8 = secret.to_pkcs8_pem(der::pem::LineEnding::LF).unwrap();
        let encoding_key = jsonwebtoken::EncodingKey::from_ec_pem(pkcs8.as_bytes()).unwrap();

        let point = secret.public_key().to_encoded_point(false);
        let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": b64url(point.x().unwrap()),
            "y": b64url(point.y().unwrap()),
            "use": "sig",
            "alg": "ES256",
        }))
        .unwrap();

        let cfg = crate::config::ProvisionerConfig {
            name: "prov1".to_string(),
            audiences: Vec::new(),
            template: None,
            authorized: None,
            kind: crate::config::ProvisionerKind::Jwk { key: jwk },
        };
        Fixture {
            authorizer: super::JwtAuthorizer::from_configs(&[cfg]).unwrap(),
            encoding_key,
        }
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn make_token(fx: &Fixture, claims: &ayane_protocol::OttClaims) -> String {
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        jsonwebtoken::encode(&header, claims, &fx.encoding_key).unwrap()
    }

    fn base_claims() -> ayane_protocol::OttClaims {
        let t = now();
        ayane_protocol::OttClaims {
            iss: "prov1".into(),
            aud: "https://ca.example/v1/sign".into(),
            sub: "host.example".into(),
            sans: vec!["host.example".into()],
            iat: t,
            nbf: t - 10,
            exp: t + 300,
            jti: Some("jti-1".into()),
            cnf: None,
        }
    }

    #[tokio::test]
    async fn accepts_valid_token() {
        let fx = fixture();
        let token = make_token(&fx, &base_claims());
        let validated = fx
            .authorizer
            .validate(&token, "https://ca.example/v1/sign")
            .await
            .unwrap();
        assert_eq!(validated.provisioner, "prov1");
        assert_eq!(validated.claims.sub, "host.example");
    }

    #[tokio::test]
    async fn rejects_wrong_audience() {
        let fx = fixture();
        let token = make_token(&fx, &base_claims());
        assert!(
            fx.authorizer
                .validate(&token, "https://ca.example/v1/renew")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn rejects_expired_token() {
        let fx = fixture();
        let mut claims = base_claims();
        claims.exp = now() - 3600;
        claims.nbf = now() - 7200;
        claims.iat = now() - 7200;
        let token = make_token(&fx, &claims);
        assert!(
            fx.authorizer
                .validate(&token, "https://ca.example/v1/sign")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn rejects_unknown_issuer() {
        let fx = fixture();
        let mut claims = base_claims();
        claims.iss = "someone-else".into();
        let token = make_token(&fx, &claims);
        assert!(
            fx.authorizer
                .validate(&token, "https://ca.example/v1/sign")
                .await
                .is_err()
        );
    }
}
