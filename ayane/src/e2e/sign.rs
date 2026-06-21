//! `POST /v1/sign`: issuance, inventory recording, SAN policy, and token replay.

use super::*;

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
