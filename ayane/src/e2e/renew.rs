//! `POST /v1/renew`: DPoP-authenticated reissue and policy preservation.

use super::*;

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
        audiences: Vec::new(),
        template: Some("client".to_string()),
        authorized: None,
        kind: crate::config::ProvisionerKind::Jwk {
            key: jwk_from_secret(&provisioner_secret),
        },
    };
    let authorizer = std::sync::Arc::new(
        crate::authorizer::ProvisionerAuthorizer::from_configs(&[provisioner]).unwrap(),
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
        roots_signature_ttl: std::time::Duration::from_secs(3600),
        external_url: None,
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
