//! End-to-end tests over the assembled [`Service`](crate::service::Service),
//! split by endpoint: [`sign`], [`renew`], [`roots`], [`webhooks`], and the
//! cross-endpoint [`lifecycle`].
//!
//! These exercise the real request path with an ephemeral CA, a JWK provisioner
//! and in-memory storage — the same code paths the HTTP layer drives. The shared
//! harness and request builders live here; each submodule holds the tests for
//! one endpoint.

mod jwks;
mod lifecycle;
mod renew;
mod roots;
mod sign;
mod webhooks;

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
    setup_with_webhooks_authorized(None, webhooks).await
}

async fn setup_with_webhooks_authorized(
    authorized: Option<bool>,
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
        audiences: Vec::new(),
        template: None,
        authorized,
        kind: crate::config::ProvisionerKind::Jwk { key: jwk },
    };
    let authorizer = std::sync::Arc::new(
        crate::authorizer::jwt::JwkAuthorizer::from_configs(&[provisioner]).unwrap(),
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
    Harness {
        service,
        provisioner_pem,
        storage,
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
    use der::Decode;
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
        jti: Some(rand_jti()),
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
