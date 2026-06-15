//! End-to-end lifecycle tests over the assembled [`Service`](crate::service::Service):
//! issue → renew (DPoP) → revoke (DPoP), plus anti-replay and SAN policy.
//!
//! These exercise the real request path with an ephemeral CA, a JWK provisioner
//! and in-memory storage — the same code paths the HTTP layer drives.

use der::{Decode, Encode, EncodePem};

const SIGN_URL: &str = "https://ca.test/v1/sign";
const RENEW_URL: &str = "https://ca.test/v1/renew";
const REVOKE_URL: &str = "https://ca.test/v1/revoke";

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn rand_jti() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

struct Harness {
    service: crate::service::Service,
    provisioner_pem: String,
    storage: std::sync::Arc<dyn crate::storage::Storage>,
}

async fn setup() -> Harness {
    setup_with_webhooks(Vec::new()).await
}

async fn setup_with_webhooks(
    webhooks: Vec<std::sync::Arc<dyn crate::webhook::WebhookProvider>>,
) -> Harness {
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

    let provisioner_secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let provisioner_pem = {
        use p256::pkcs8::EncodePrivateKey;
        provisioner_secret
            .to_pkcs8_pem(der::pem::LineEnding::LF)
            .unwrap()
            .to_string()
    };
    let jwk = jwk_from_secret(&provisioner_secret);
    let provisioner = crate::config::ProvisionerConfig {
        name: "prov1".to_string(),
        kind: "jwk".to_string(),
        key: jwk,
        audiences: Vec::new(),
        template: None,
    };
    let authorizer = std::sync::Arc::new(
        crate::authorizer::jwt::JwtAuthorizer::from_configs(&[provisioner]).unwrap(),
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
    });
    Harness {
        service,
        provisioner_pem,
        storage,
    }
}

fn jwk_from_secret(secret: &p256::SecretKey) -> jsonwebtoken::jwk::Jwk {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let point = secret.public_key().to_encoded_point(false);
    serde_json::from_value(serde_json::json!({
        "kty": "EC", "crv": "P-256",
        "x": b64url(point.x().unwrap()),
        "y": b64url(point.y().unwrap()),
        "alg": "ES256",
    }))
    .unwrap()
}

fn make_token(provisioner_pem: &str, audience: &str, subject: &str, sans: &[&str]) -> String {
    let encoding_key = jsonwebtoken::EncodingKey::from_ec_pem(provisioner_pem.as_bytes()).unwrap();
    let now = unix_now();
    let claims = ayane_protocol::OttClaims {
        iss: "prov1".to_string(),
        aud: audience.to_string(),
        sub: subject.to_string(),
        sans: sans.iter().map(|s| s.to_string()).collect(),
        iat: now,
        nbf: now - 5,
        exp: now + 300,
        jti: rand_jti(),
        cnf: None,
    };
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256),
        &claims,
        &encoding_key,
    )
    .unwrap()
}

fn make_csr(leaf: &p256::SecretKey, common_name: &str, sans: &[&str]) -> String {
    use const_oid::AssociatedOid;
    use signature::Signer;

    let signing = p256::ecdsa::SigningKey::from(leaf.clone());
    let spki = {
        use spki::EncodePublicKey;
        spki::SubjectPublicKeyInfoOwned::from_der(
            signing
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        )
        .unwrap()
    };
    let subject = crate::x509::name_with_common_name(common_name).unwrap();

    let general_names: Vec<_> = sans
        .iter()
        .map(|s| {
            x509_cert::ext::pkix::name::GeneralName::try_from(&crate::san::San::parse(s)).unwrap()
        })
        .collect();
    let san = x509_cert::ext::pkix::SubjectAltName(general_names);
    let extension = x509_cert::ext::Extension {
        extn_id: x509_cert::ext::pkix::SubjectAltName::OID,
        critical: false,
        extn_value: der::asn1::OctetString::new(san.to_der().unwrap()).unwrap(),
    };
    let ext_req = x509_cert::request::ExtensionReq(vec![extension]);
    let attribute = x509_cert::attr::Attribute {
        oid: x509_cert::request::ExtensionReq::OID,
        values: der::asn1::SetOfVec::try_from(vec![
            der::Any::from_der(&ext_req.to_der().unwrap()).unwrap(),
        ])
        .unwrap(),
    };
    let info = x509_cert::request::CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject,
        public_key: spki,
        attributes: der::asn1::SetOfVec::try_from(vec![attribute]).unwrap(),
    };
    let info_der = info.to_der().unwrap();
    let sig: p256::ecdsa::Signature = signing.sign(&info_der);
    let csr = x509_cert::request::CertReq {
        info,
        algorithm: crate::crypto::SignatureAlgorithm::EcdsaSha256
            .algorithm_identifier()
            .unwrap(),
        signature: der::asn1::BitString::from_bytes(&sig.to_der().to_bytes()).unwrap(),
    };
    csr.to_pem(der::pem::LineEnding::LF).unwrap()
}

fn make_dpop(leaf: &p256::SecretKey, htu: &str) -> String {
    use p256::pkcs8::EncodePrivateKey;
    let pem = leaf.to_pkcs8_pem(der::pem::LineEnding::LF).unwrap();
    let encoding_key = jsonwebtoken::EncodingKey::from_ec_pem(pem.as_bytes()).unwrap();
    let now = unix_now();
    let claims = ayane_protocol::DpopClaims {
        htm: "POST".to_string(),
        htu: htu.to_string(),
        iat: now,
        jti: rand_jti(),
        nonce: None,
    };
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.typ = Some("dpop+jwt".to_string());
    jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap()
}

#[tokio::test]
async fn full_lifecycle_sign_renew_revoke() {
    let h = setup().await;
    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);

    // Issue.
    let csr = make_csr(&leaf, "host.example", &["host.example"]);
    let token = make_token(
        &h.provisioner_pem,
        SIGN_URL,
        "host.example",
        &["host.example"],
    );
    let issued = h
        .service
        .sign(
            ayane_protocol::SignRequest {
                csr,
                token,
                not_before: None,
                not_after: None,
            },
            SIGN_URL,
            None,
        )
        .await
        .expect("issue succeeds");
    let original_serial = issued.serial_number.clone();
    assert!(!issued.chain.is_empty());
    // Use a full chain bundle (leaf + issuer) to exercise multi-block PEM parsing.
    let cert_pem = {
        let mut bundle = issued.certificate.clone();
        for c in &issued.chain {
            bundle.push_str(c);
        }
        bundle
    };

    // Renew (same key) via DPoP.
    let dpop = make_dpop(&leaf, RENEW_URL);
    let renewed = h
        .service
        .renew(
            ayane_protocol::RenewRequest {
                certificate: cert_pem.clone(),
            },
            Some(&dpop),
            RENEW_URL,
            None,
        )
        .await
        .expect("renew succeeds");
    assert_ne!(renewed.serial_number, original_serial);

    // Self-revoke the original certificate via DPoP.
    let dpop_revoke = make_dpop(&leaf, REVOKE_URL);
    let revoked = h
        .service
        .revoke(
            ayane_protocol::RevokeRequest {
                serial_number: original_serial.clone(),
                reason: Some("superseded".to_string()),
                reason_code: Some(4),
                token: None,
                certificate: Some(cert_pem.clone()),
            },
            Some(&dpop_revoke),
            REVOKE_URL,
            None,
        )
        .await
        .expect("revoke succeeds");
    assert_eq!(revoked.status, "revoked");

    // Renewing the now-revoked certificate must fail.
    let dpop_again = make_dpop(&leaf, RENEW_URL);
    let err = h
        .service
        .renew(
            ayane_protocol::RenewRequest {
                certificate: cert_pem,
            },
            Some(&dpop_again),
            RENEW_URL,
            None,
        )
        .await;
    assert!(matches!(err, Err(crate::error::Error::Forbidden(_))));
}

#[tokio::test]
async fn issued_certificates_are_recorded() {
    let h = setup().await;
    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);

    let csr = make_csr(&leaf, "host.example", &["host.example"]);
    let token = make_token(
        &h.provisioner_pem,
        SIGN_URL,
        "host.example",
        &["host.example"],
    );
    let issued = h
        .service
        .sign(
            ayane_protocol::SignRequest {
                csr,
                token,
                not_before: None,
                not_after: None,
            },
            SIGN_URL,
            None,
        )
        .await
        .expect("issue succeeds");

    // The signed certificate is in the inventory with its metadata and PEM.
    let record = h
        .storage
        .get_certificate(&issued.serial_number)
        .await
        .unwrap()
        .expect("issuance is recorded");
    assert_eq!(record.subject, "host.example");
    assert_eq!(record.sans, vec!["host.example".to_string()]);
    assert_eq!(record.operation, "sign");
    assert_eq!(record.provisioner.as_deref(), Some("prov1"));
    assert_eq!(record.pem, issued.certificate);

    // Renewal records a second, distinct entry tagged as a renew.
    let renewed = h
        .service
        .renew(
            ayane_protocol::RenewRequest {
                certificate: issued.certificate.clone(),
            },
            Some(&make_dpop(&leaf, RENEW_URL)),
            RENEW_URL,
            None,
        )
        .await
        .expect("renew succeeds");
    let renew_record = h
        .storage
        .get_certificate(&renewed.serial_number)
        .await
        .unwrap()
        .expect("renewal is recorded");
    assert_eq!(renew_record.operation, "renew");
    assert_eq!(renew_record.provisioner, None);
    // Issue and renew produced two distinct inventory entries.
    assert_ne!(issued.serial_number, renewed.serial_number);
}

#[tokio::test]
async fn token_replay_is_rejected() {
    let h = setup().await;
    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let csr = make_csr(&leaf, "host.example", &["host.example"]);
    let token = make_token(
        &h.provisioner_pem,
        SIGN_URL,
        "host.example",
        &["host.example"],
    );

    let req = || ayane_protocol::SignRequest {
        csr: csr.clone(),
        token: token.clone(),
        not_before: None,
        not_after: None,
    };
    h.service.sign(req(), SIGN_URL, None).await.unwrap();
    // Same token (same jti) a second time is a replay.
    let err = h.service.sign(req(), SIGN_URL, None).await;
    assert!(matches!(err, Err(crate::error::Error::Unauthorized(_))));
}

#[tokio::test]
async fn san_not_permitted_is_rejected() {
    let h = setup().await;
    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
    // CSR asks for evil.example, but the token only permits host.example.
    let csr = make_csr(&leaf, "host.example", &["host.example", "evil.example"]);
    let token = make_token(
        &h.provisioner_pem,
        SIGN_URL,
        "host.example",
        &["host.example"],
    );
    let err = h
        .service
        .sign(
            ayane_protocol::SignRequest {
                csr,
                token,
                not_before: None,
                not_after: None,
            },
            SIGN_URL,
            None,
        )
        .await;
    assert!(matches!(err, Err(crate::error::Error::Forbidden(_))));
}

#[tokio::test]
async fn token_survives_pre_issue_rejection() {
    let h = setup().await;
    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let token = make_token(
        &h.provisioner_pem,
        SIGN_URL,
        "host.example",
        &["host.example"],
    );

    // First attempt requests a disallowed SAN and is rejected BEFORE the token
    // is consumed.
    let bad = h
        .service
        .sign(
            ayane_protocol::SignRequest {
                csr: make_csr(&leaf, "host.example", &["host.example", "evil.example"]),
                token: token.clone(),
                not_before: None,
                not_after: None,
            },
            SIGN_URL,
            None,
        )
        .await;
    assert!(matches!(bad, Err(crate::error::Error::Forbidden(_))));

    // The same token still works for a compliant request.
    let ok = h
        .service
        .sign(
            ayane_protocol::SignRequest {
                csr: make_csr(&leaf, "host.example", &["host.example"]),
                token,
                not_before: None,
                not_after: None,
            },
            SIGN_URL,
            None,
        )
        .await;
    assert!(ok.is_ok());
}

#[tokio::test]
async fn renewal_preserves_original_eku() {
    use const_oid::AssociatedOid;
    use der::Decode;

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
    let provisioner_secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let provisioner_pem = {
        use p256::pkcs8::EncodePrivateKey;
        provisioner_secret
            .to_pkcs8_pem(der::pem::LineEnding::LF)
            .unwrap()
            .to_string()
    };
    let provisioner = crate::config::ProvisionerConfig {
        name: "prov1".to_string(),
        kind: "jwk".to_string(),
        key: jwk_from_secret(&provisioner_secret),
        audiences: Vec::new(),
        template: Some("client".to_string()),
    };
    let authorizer = std::sync::Arc::new(
        crate::authorizer::jwt::JwtAuthorizer::from_configs(&[provisioner]).unwrap(),
    );

    let mut templates = std::collections::HashMap::new();
    templates.insert(
        "client".to_string(),
        crate::template::CertificateTemplate {
            extended_key_usage: vec![crate::template::ExtKeyUsageName::ClientAuth],
            ..Default::default()
        },
    );
    templates.insert(
        "server".to_string(),
        crate::template::CertificateTemplate::default(),
    );
    let service = crate::service::Service::new(crate::service::ServiceParts {
        authorizer,
        ca: authority,
        storage: std::sync::Arc::new(
            crate::storage::sqlite::SqliteStorage::open_in_memory().unwrap(),
        ),
        webhooks: Vec::new(),
        events: Vec::new(),
        templates,
        // Default differs from the issuing template, to prove renewal does not
        // fall back to it.
        default_template_name: Some("server".to_string()),
    });

    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let issued = service
        .sign(
            ayane_protocol::SignRequest {
                csr: make_csr(&leaf, "client.example", &["client.example"]),
                token: make_token(
                    &provisioner_pem,
                    SIGN_URL,
                    "client.example",
                    &["client.example"],
                ),
                not_before: None,
                not_after: None,
            },
            SIGN_URL,
            None,
        )
        .await
        .unwrap();

    let renewed = service
        .renew(
            ayane_protocol::RenewRequest {
                certificate: issued.certificate.clone(),
            },
            Some(&make_dpop(&leaf, RENEW_URL)),
            RENEW_URL,
            None,
        )
        .await
        .unwrap();

    // The renewed certificate must carry clientAuth (preserved), not the
    // default template's serverAuth.
    let cert = crate::x509::certificate_from_pem(&renewed.certificate).unwrap();
    let mut ekus = Vec::new();
    for ext in cert.tbs_certificate.extensions.as_ref().unwrap() {
        if ext.extn_id == x509_cert::ext::pkix::ExtendedKeyUsage::OID {
            let eku = x509_cert::ext::pkix::ExtendedKeyUsage::from_der(ext.extn_value.as_bytes())
                .unwrap();
            ekus = eku.0;
        }
    }
    assert!(ekus.contains(&const_oid::db::rfc5280::ID_KP_CLIENT_AUTH));
    assert!(!ekus.contains(&const_oid::db::rfc5280::ID_KP_SERVER_AUTH));
}

#[tokio::test]
async fn wrong_audience_token_is_rejected() {
    let h = setup().await;
    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let csr = make_csr(&leaf, "host.example", &["host.example"]);
    // Token audience targets a different endpoint than the request URL.
    let token = make_token(
        &h.provisioner_pem,
        "https://ca.test/v1/renew",
        "host.example",
        &["host.example"],
    );
    let err = h
        .service
        .sign(
            ayane_protocol::SignRequest {
                csr,
                token,
                not_before: None,
                not_after: None,
            },
            SIGN_URL,
            None,
        )
        .await;
    assert!(matches!(err, Err(crate::error::Error::Unauthorized(_))));
}

/// A webhook that records the last request and replays a fixed sequence of
/// responses (clamping to the last once exhausted).
struct TestWebhook {
    responses: Vec<crate::webhook::WebhookResponse>,
    calls: std::sync::atomic::AtomicUsize,
    last_request: std::sync::Mutex<Option<crate::webhook::WebhookRequest>>,
}

impl TestWebhook {
    fn new(responses: Vec<crate::webhook::WebhookResponse>) -> std::sync::Arc<TestWebhook> {
        std::sync::Arc::new(TestWebhook {
            responses,
            calls: std::sync::atomic::AtomicUsize::new(0),
            last_request: std::sync::Mutex::new(None),
        })
    }

    fn call_count(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn last_request(&self) -> crate::webhook::WebhookRequest {
        self.last_request
            .lock()
            .unwrap()
            .clone()
            .expect("webhook was called")
    }
}

#[async_trait::async_trait]
impl crate::webhook::WebhookProvider for TestWebhook {
    fn name(&self) -> &str {
        "test"
    }

    fn applies_to(&self, _provisioner: Option<&str>) -> bool {
        true
    }

    async fn call(
        &self,
        request: &crate::webhook::WebhookRequest,
    ) -> crate::error::Result<crate::webhook::WebhookResponse> {
        *self.last_request.lock().unwrap() = Some(request.clone());
        let index = self
            .calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .min(self.responses.len() - 1);
        Ok(self.responses[index].clone())
    }
}

fn cert_not_after_unix(cert: &x509_cert::Certificate) -> i64 {
    cert.tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs() as i64
}

fn cert_san_strings(cert: &x509_cert::Certificate) -> Vec<String> {
    use const_oid::AssociatedOid;
    let mut out = Vec::new();
    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts {
            if ext.extn_id == x509_cert::ext::pkix::SubjectAltName::OID {
                let san = x509_cert::ext::pkix::SubjectAltName::from_der(ext.extn_value.as_bytes())
                    .unwrap();
                for gn in san.0.iter() {
                    if let Ok(s) = crate::san::San::try_from(gn) {
                        out.push(s.to_string());
                    }
                }
            }
        }
    }
    out
}

#[tokio::test]
async fn webhook_enriches_sign_with_additional_san() {
    let webhook = TestWebhook::new(vec![crate::webhook::WebhookResponse {
        additional_sans: vec![crate::san::San::parse("extra.example")],
        ..Default::default()
    }]);
    let webhooks: Vec<std::sync::Arc<dyn crate::webhook::WebhookProvider>> = vec![webhook.clone()];
    let h = setup_with_webhooks(webhooks).await;
    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let issued = h
        .service
        .sign(
            ayane_protocol::SignRequest {
                csr: make_csr(&leaf, "host.example", &["host.example"]),
                token: make_token(
                    &h.provisioner_pem,
                    SIGN_URL,
                    "host.example",
                    &["host.example"],
                ),
                not_before: None,
                not_after: None,
            },
            SIGN_URL,
            None,
        )
        .await
        .expect("issue succeeds");

    let cert = crate::x509::certificate_from_pem(&issued.certificate).unwrap();
    let sans = cert_san_strings(&cert);
    assert!(sans.contains(&"host.example".to_string()));
    assert!(sans.contains(&"extra.example".to_string()));

    let request = webhook.last_request();
    assert_eq!(request.operation, crate::webhook::Operation::Sign);
    assert!(request.csr_der.is_some());
    assert!(request.previous_certificate_der.is_none());
}

#[tokio::test]
async fn webhook_denial_does_not_burn_token() {
    // Deny on the first call, permit on the second.
    let webhook = TestWebhook::new(vec![
        crate::webhook::WebhookResponse {
            allow: Some(false),
            deny_reason: Some("denied by policy".to_string()),
            ..Default::default()
        },
        crate::webhook::WebhookResponse::default(),
    ]);
    let webhooks: Vec<std::sync::Arc<dyn crate::webhook::WebhookProvider>> = vec![webhook.clone()];
    let h = setup_with_webhooks(webhooks).await;
    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let csr = make_csr(&leaf, "host.example", &["host.example"]);
    let token = make_token(
        &h.provisioner_pem,
        SIGN_URL,
        "host.example",
        &["host.example"],
    );
    let request = || ayane_protocol::SignRequest {
        csr: csr.clone(),
        token: token.clone(),
        not_before: None,
        not_after: None,
    };

    let err = h.service.sign(request(), SIGN_URL, None).await;
    assert!(matches!(err, Err(crate::error::Error::Forbidden(_))));

    // The denied attempt never claimed the one-time token, so retrying with the
    // same token succeeds once the webhook permits.
    let issued = h.service.sign(request(), SIGN_URL, None).await;
    assert!(issued.is_ok(), "token must survive a webhook denial");
    assert_eq!(webhook.call_count(), 2);
}

#[tokio::test]
async fn webhook_runs_on_renew_with_previous_certificate() {
    let webhook = TestWebhook::new(vec![crate::webhook::WebhookResponse::default()]);
    let webhooks: Vec<std::sync::Arc<dyn crate::webhook::WebhookProvider>> = vec![webhook.clone()];
    let h = setup_with_webhooks(webhooks).await;
    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let issued = h
        .service
        .sign(
            ayane_protocol::SignRequest {
                csr: make_csr(&leaf, "host.example", &["host.example"]),
                token: make_token(
                    &h.provisioner_pem,
                    SIGN_URL,
                    "host.example",
                    &["host.example"],
                ),
                not_before: None,
                not_after: None,
            },
            SIGN_URL,
            None,
        )
        .await
        .expect("issue succeeds");

    let renewed = h
        .service
        .renew(
            ayane_protocol::RenewRequest {
                certificate: issued.certificate.clone(),
            },
            Some(&make_dpop(&leaf, RENEW_URL)),
            RENEW_URL,
            None,
        )
        .await
        .expect("renew succeeds");
    assert_ne!(renewed.serial_number, issued.serial_number);

    // The webhook fired on both sign and renew; the renew call carried the
    // previous certificate and no CSR.
    assert_eq!(webhook.call_count(), 2);
    let request = webhook.last_request();
    assert_eq!(request.operation, crate::webhook::Operation::Renew);
    assert!(request.previous_certificate_der.is_some());
    assert!(request.csr_der.is_none());
}

#[tokio::test]
async fn webhook_cannot_extend_sign_past_template_max() {
    // The webhook demands a year-long certificate; the fallback template caps
    // validity at 24h, so issuance must re-clamp notAfter to the template max.
    let webhook = TestWebhook::new(vec![crate::webhook::WebhookResponse {
        not_after: Some(chrono::Utc::now() + chrono::Duration::days(365)),
        ..Default::default()
    }]);
    let webhooks: Vec<std::sync::Arc<dyn crate::webhook::WebhookProvider>> = vec![webhook.clone()];
    let h = setup_with_webhooks(webhooks).await;
    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let issued = h
        .service
        .sign(
            ayane_protocol::SignRequest {
                csr: make_csr(&leaf, "host.example", &["host.example"]),
                token: make_token(
                    &h.provisioner_pem,
                    SIGN_URL,
                    "host.example",
                    &["host.example"],
                ),
                not_before: None,
                not_after: None,
            },
            SIGN_URL,
            None,
        )
        .await
        .expect("issue succeeds");

    // Without the clamp the cert would last ~365 days; the 24h max + 60s
    // backdate ceiling keeps it far below a generous one-day-plus bound.
    let cert = crate::x509::certificate_from_pem(&issued.certificate).unwrap();
    assert!(
        cert_not_after_unix(&cert) <= unix_now() + 24 * 3600 + 120,
        "webhook notAfter must be clamped to the template max_validity"
    );
}

#[tokio::test]
async fn webhook_cannot_extend_renewal_past_original_lifetime() {
    // On reissue there is no template to clamp against; a webhook must not be
    // able to extend the renewed certificate beyond the previous lifetime.
    let webhook = TestWebhook::new(vec![
        crate::webhook::WebhookResponse::default(),
        crate::webhook::WebhookResponse {
            not_after: Some(chrono::Utc::now() + chrono::Duration::days(365)),
            ..Default::default()
        },
    ]);
    let webhooks: Vec<std::sync::Arc<dyn crate::webhook::WebhookProvider>> = vec![webhook.clone()];
    let h = setup_with_webhooks(webhooks).await;
    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let issued = h
        .service
        .sign(
            ayane_protocol::SignRequest {
                csr: make_csr(&leaf, "host.example", &["host.example"]),
                token: make_token(
                    &h.provisioner_pem,
                    SIGN_URL,
                    "host.example",
                    &["host.example"],
                ),
                not_before: None,
                not_after: None,
            },
            SIGN_URL,
            None,
        )
        .await
        .expect("issue succeeds");

    let renewed = h
        .service
        .renew(
            ayane_protocol::RenewRequest {
                certificate: issued.certificate.clone(),
            },
            Some(&make_dpop(&leaf, RENEW_URL)),
            RENEW_URL,
            None,
        )
        .await
        .expect("renew succeeds");

    let cert = crate::x509::certificate_from_pem(&renewed.certificate).unwrap();
    assert!(
        cert_not_after_unix(&cert) <= unix_now() + 24 * 3600 + 120,
        "webhook notAfter must be clamped to the original certificate lifetime"
    );
}
