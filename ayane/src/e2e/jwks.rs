//! End-to-end sign flow for a `jwks` (OIDC) provisioner, driven by a loopback
//! OpenID Connect discovery + JWKS server. Exercises OIDC-shaped tokens (URL
//! `iss`, non-DNS `sub`, no `sans`, no `jti`) which only authenticate: issuance
//! must be granted by an authorize webhook, which also sets the real subject and
//! SANs.

use super::*;

const OIDC_AUDIENCE: &str = "ayane-ca";
const KID: &str = "test-key-1";

/// A webhook that returns a fixed response, standing in for an authorize policy.
struct FixedWebhook(crate::webhook::WebhookResponse);

#[async_trait::async_trait]
impl crate::webhook::WebhookProvider for FixedWebhook {
    fn name(&self) -> &str {
        "authorize"
    }
    fn applies_to(&self, _provisioner: Option<&str>) -> bool {
        true
    }
    async fn call(
        &self,
        _request: &crate::webhook::WebhookRequest,
    ) -> crate::error::Result<crate::webhook::WebhookResponse> {
        Ok(self.0.clone())
    }
}

/// Serve OIDC discovery + JWKS from a loopback address; returns the issuer base.
async fn start_oidc_server(jwk: serde_json::Value) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let discovery = std::sync::Arc::new(serde_json::json!({
        "issuer": base,
        "jwks_uri": format!("{base}/jwks"),
    }));
    let jwks = std::sync::Arc::new(serde_json::json!({ "keys": [jwk] }));
    let app = axum::Router::new()
        .route(
            "/.well-known/openid-configuration",
            axum::routing::get(move || {
                let discovery = discovery.clone();
                async move { axum::Json((*discovery).clone()) }
            }),
        )
        .route(
            "/jwks",
            axum::routing::get(move || {
                let jwks = jwks.clone();
                async move { axum::Json((*jwks).clone()) }
            }),
        );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    base
}

fn oidc_jwk_json(secret: &p256::SecretKey) -> serde_json::Value {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let point = secret.public_key().to_encoded_point(false);
    serde_json::json!({
        "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": KID,
        "x": b64url(point.x().unwrap()),
        "y": b64url(point.y().unwrap()),
    })
}

/// Mint an OIDC-shaped token: URL `iss`, a non-DNS `sub`, no `sans`, no `jti`,
/// and a `kid` header selecting the published key.
fn oidc_token(secret: &p256::SecretKey, issuer: &str, subject: &str) -> String {
    use p256::pkcs8::EncodePrivateKey;
    let pem = secret.to_pkcs8_pem(der::pem::LineEnding::LF).unwrap();
    let encoding_key = jsonwebtoken::EncodingKey::from_ec_pem(pem.as_bytes()).unwrap();
    let now = unix_now();
    let claims = ayane_protocol::OttClaims {
        iss: issuer.to_string(),
        aud: OIDC_AUDIENCE.to_string(),
        sub: subject.to_string(),
        sans: Vec::new(),
        iat: now,
        nbf: now - 5,
        exp: now + 300,
        jti: None,
        cnf: None,
    };
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(KID.to_string());
    jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap()
}

async fn setup(
    issuer_base: &str,
    webhooks: Vec<std::sync::Arc<dyn crate::webhook::WebhookProvider>>,
) -> (
    crate::service::Service,
    std::sync::Arc<dyn crate::storage::Storage>,
) {
    let ca = crate::testca::ec_p256().await;
    let authority = std::sync::Arc::new(
        crate::ca::CertificateAuthority::new(
            ca.key.clone(),
            &ca.ca_cert_pem,
            vec![ca.ca_cert_pem.clone()],
            vec![ca.ca_cert_pem.clone()],
        )
        .unwrap(),
    );

    let provisioner = crate::config::ProvisionerConfig {
        name: "github".to_string(),
        audiences: vec![OIDC_AUDIENCE.to_string()],
        template: None,
        authorized: None,
        kind: crate::config::ProvisionerKind::Jwks {
            jwks: crate::config::JwksConfig {
                jwks_url: None,
                openid_configuration_url: Some(format!(
                    "{issuer_base}/.well-known/openid-configuration"
                )),
                issuer: None,
            },
        },
    };
    let authorizer = std::sync::Arc::new(
        crate::authorizer::jwks::JwksAuthorizer::from_configs(&[provisioner]).unwrap(),
    );
    let storage: std::sync::Arc<dyn crate::storage::Storage> =
        std::sync::Arc::new(crate::storage::sqlite::SqliteStorage::open_in_memory().unwrap());

    let service = crate::service::Service::new(crate::service::ServiceParts {
        authorizer,
        ca: authority,
        storage: storage.clone(),
        webhooks,
        events: Vec::new(),
        templates: std::collections::HashMap::new(),
        default_template_name: None,
        roots_signature_ttl: std::time::Duration::from_secs(3600),
        external_url: None,
    });
    (service, storage)
}

fn sign_request(leaf: &p256::SecretKey, token: String) -> ayane_protocol::SignRequest {
    ayane_protocol::SignRequest {
        // The CSR subject/SANs are unconstrained for an unauthorized provisioner;
        // the webhook decides the real identity.
        csr: make_csr(leaf, "app.example.com", &["app.example.com"]),
        token,
        not_before: None,
        not_after: None,
    }
}

#[tokio::test]
async fn oidc_token_denied_without_authorize_webhook() {
    let provisioner_secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let base = start_oidc_server(oidc_jwk_json(&provisioner_secret)).await;
    // A silent webhook authenticates but does not authorize.
    let webhook = std::sync::Arc::new(FixedWebhook(crate::webhook::WebhookResponse::default()));
    let (service, _storage) = setup(&base, vec![webhook]).await;

    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let token = oidc_token(
        &provisioner_secret,
        &base,
        "repo:acme/app:ref:refs/heads/main",
    );
    let err = service
        .sign(sign_request(&leaf, token), SIGN_URL, None)
        .await;
    assert!(matches!(err, Err(crate::error::Error::Forbidden(_))));
}

#[tokio::test]
async fn oidc_token_issues_when_webhook_authorizes() {
    let provisioner_secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let base = start_oidc_server(oidc_jwk_json(&provisioner_secret)).await;
    // The authorize webhook grants the request and maps the OIDC identity onto a
    // real certificate subject and SAN.
    let webhook = std::sync::Arc::new(FixedWebhook(crate::webhook::WebhookResponse {
        allow: Some(true),
        subject_common_name: Some("app.example.com".to_string()),
        sans: Some(vec![crate::san::San::parse("app.example.com")]),
        ..Default::default()
    }));
    let (service, storage) = setup(&base, vec![webhook]).await;

    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let token = oidc_token(
        &provisioner_secret,
        &base,
        "repo:acme/app:ref:refs/heads/main",
    );
    let issued = service
        .sign(sign_request(&leaf, token), SIGN_URL, None)
        .await
        .expect("issues once the webhook authorizes");

    let cert = crate::x509::certificate_from_pem(&issued.certificate).unwrap();
    assert!(
        cert_san_strings(&cert).contains(&"app.example.com".to_string()),
        "webhook-supplied SAN is present on the issued certificate"
    );
    let record = storage
        .get_certificate(&issued.serial_number)
        .await
        .unwrap()
        .expect("issuance is recorded");
    assert_eq!(record.provisioner.as_deref(), Some("github"));
}
