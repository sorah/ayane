//! Static-JWK [`TokenVerifier`](crate::authorizer::TokenVerifier).
//!
//! A provisioner that holds a single public JWK and verifies tokens whose `iss`
//! equals its name. Signature and claim policy live in
//! [`crate::authorizer::validate_signed`], which pins the accepted algorithm to
//! the JWK's key type — closing the JWT algorithm-confusion class of attacks.

/// Verifies tokens signed by a single, statically-configured JWK.
pub(crate) struct JwkVerifier {
    issuer: String,
    audiences: Vec<String>,
    key: crate::authorizer::SigningKey,
    leeway_secs: u64,
}

impl JwkVerifier {
    pub(crate) fn new(
        cfg: &crate::config::ProvisionerConfig,
        key: &jsonwebtoken::jwk::Jwk,
    ) -> crate::error::Result<Self> {
        let key = crate::authorizer::signing_key_from_jwk(key)
            .map_err(|e| crate::error::Error::Config(format!("provisioner {:?}: {e}", cfg.name)))?;
        Ok(JwkVerifier {
            issuer: cfg.name.clone(),
            audiences: cfg.audiences.clone(),
            key,
            leeway_secs: 60,
        })
    }
}

#[async_trait::async_trait]
impl crate::authorizer::TokenVerifier for JwkVerifier {
    fn matches(&self, token: &str) -> bool {
        crate::authorizer::unverified_issuer(token).ok().as_deref() == Some(self.issuer.as_str())
    }

    async fn verify(
        &self,
        token: &str,
        audience: &str,
    ) -> crate::error::Result<crate::authorizer::VerifiedToken> {
        let (claims, replay_id) = crate::authorizer::validate_signed(
            token,
            audience,
            &self.issuer,
            &self.audiences,
            &self.key,
            self.leeway_secs,
        )?;
        Ok(crate::authorizer::VerifiedToken { claims, replay_id })
    }

    fn describe(&self) -> crate::authorizer::VerifierInfo {
        crate::authorizer::VerifierInfo {
            kind: "jwk",
            audiences: self.audiences.clone(),
        }
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
        authorizer: crate::authorizer::ProvisionerAuthorizer,
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
            authorizer: crate::authorizer::ProvisionerAuthorizer::from_configs(&[cfg]).unwrap(),
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
