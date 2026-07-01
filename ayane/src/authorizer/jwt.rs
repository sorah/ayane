//! JWK-based [`Authorizer`](crate::authorizer::Authorizer) implementation.
//!
//! Each provisioner is a name plus a static public JWK. A token is matched to a
//! provisioner by its `iss` claim, then verified with that provisioner's key.
//! Signature and claim policy live in [`crate::authorizer::validate_signed`],
//! which pins the accepted algorithm to the JWK's key type — closing the JWT
//! algorithm-confusion class of attacks.

struct ProvisionerEntry {
    name: String,
    key: crate::authorizer::SigningKey,
    audiences: Vec<String>,
    template: Option<String>,
    authorized: bool,
}

/// An [`Authorizer`](crate::authorizer::Authorizer) over a fixed set of `jwk`
/// provisioners. `jwks` provisioners are handled by
/// [`JwksAuthorizer`](crate::authorizer::jwks::JwksAuthorizer).
pub struct JwkAuthorizer {
    provisioners: Vec<ProvisionerEntry>,
    leeway_secs: u64,
}

impl JwkAuthorizer {
    /// Build from provisioner configuration, keeping only `jwk` provisioners.
    pub fn from_configs(
        configs: &[crate::config::ProvisionerConfig],
    ) -> crate::error::Result<Self> {
        let mut provisioners = Vec::new();
        for cfg in configs {
            let key = match &cfg.kind {
                crate::config::ProvisionerKind::Jwk { key } => key,
                crate::config::ProvisionerKind::Jwks { .. } => continue,
            };
            let key = crate::authorizer::signing_key_from_jwk(key).map_err(|e| {
                crate::error::Error::Config(format!("provisioner {:?}: {e}", cfg.name))
            })?;
            provisioners.push(ProvisionerEntry {
                name: cfg.name.clone(),
                key,
                audiences: cfg.audiences.clone(),
                template: cfg.template.clone(),
                authorized: cfg.effective_authorized(),
            });
        }
        Ok(JwkAuthorizer {
            provisioners,
            leeway_secs: 60,
        })
    }

    fn find(&self, issuer: &str) -> Option<&ProvisionerEntry> {
        self.provisioners.iter().find(|p| p.name == issuer)
    }

    /// The issuers (provisioner names) this authorizer handles, for the
    /// [`Authorizers`](crate::authorizer::Authorizers) router.
    pub fn issuers(&self) -> Vec<String> {
        self.provisioners.iter().map(|p| p.name.clone()).collect()
    }
}

#[async_trait::async_trait]
impl crate::authorizer::Authorizer for JwkAuthorizer {
    async fn validate(
        &self,
        token: &str,
        audience: &str,
    ) -> crate::error::Result<crate::authorizer::ValidatedToken> {
        let issuer = crate::authorizer::unverified_issuer(token)?;
        let entry = self.find(&issuer).ok_or_else(|| {
            crate::error::Error::Unauthorized(format!("unknown provisioner {issuer:?}"))
        })?;

        let (claims, replay_id) = crate::authorizer::validate_signed(
            token,
            audience,
            &entry.name,
            &entry.audiences,
            &entry.key,
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
        authorizer: super::JwkAuthorizer,
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
            authorizer: super::JwkAuthorizer::from_configs(&[cfg]).unwrap(),
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
