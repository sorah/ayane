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
        hooks: Vec::new(),
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

    // A default issuance is renewable, so it carries no non-renewable marker.
    let issued_cert = crate::x509::certificate_from_pem(&issued.certificate).unwrap();
    assert!(!crate::x509::is_marked_non_renewable(&issued_cert));

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
async fn non_renewable_token_blocks_renew_and_rekey() {
    let h = setup().await;
    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let issued = h
        .service
        .sign(
            ayane_protocol::SignRequest {
                csr: make_csr(&leaf, "host.example", &["host.example"]),
                token: make_token_non_renewable(
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

    // The certificate self-describes as non-renewable: the marker extension is
    // present and non-critical.
    let cert = crate::x509::certificate_from_pem(&issued.certificate).unwrap();
    assert!(crate::x509::is_marked_non_renewable(&cert));
    let marker = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .unwrap()
        .iter()
        .find(|e| e.extn_id == crate::x509::NON_RENEWABLE_OID)
        .expect("non-renewable marker present");
    assert!(!marker.critical, "marker must be non-critical");

    // Renewal of a non-renewable certificate is rejected.
    let renew = h
        .service
        .renew(
            ayane_protocol::RenewRequest {
                certificate: issued.certificate.clone(),
            },
            Some(&make_dpop(&leaf, RENEW_URL)),
            RENEW_URL,
            None,
        )
        .await;
    assert!(
        matches!(renew, Err(crate::error::Error::Forbidden(_))),
        "non-renewable certificate must not renew"
    );

    // Rekey (also a reissue) is rejected on the same grounds.
    let new_leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let rekey = h
        .service
        .rekey(
            ayane_protocol::RekeyRequest {
                certificate: issued.certificate.clone(),
                csr: make_csr(&new_leaf, "host.example", &["host.example"]),
            },
            Some(&make_dpop(&leaf, "https://ca.test/v1/rekey")),
            "https://ca.test/v1/rekey",
            None,
        )
        .await;
    assert!(
        matches!(rekey, Err(crate::error::Error::Forbidden(_))),
        "non-renewable certificate must not rekey"
    );
}

#[tokio::test]
async fn hook_marks_certificate_non_renewable() {
    // A hook that returns `renew: false` makes the issued certificate
    // non-renewable even though the token permitted renewal.
    let hook = super::hooks::TestHook::new(vec![crate::hook::HookResponse {
        renew: Some(false),
        ..Default::default()
    }]);
    let hooks: Vec<std::sync::Arc<dyn crate::hook::HookProvider>> = vec![hook.clone()];
    let h = setup_with_hooks(hooks).await;
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

    let renew = h
        .service
        .renew(
            ayane_protocol::RenewRequest {
                certificate: issued.certificate.clone(),
            },
            Some(&make_dpop(&leaf, RENEW_URL)),
            RENEW_URL,
            None,
        )
        .await;
    assert!(
        matches!(renew, Err(crate::error::Error::Forbidden(_))),
        "hook-disabled renewal must be rejected"
    );
}
