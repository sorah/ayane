//! The full issue → renew → revoke lifecycle across endpoints.

use super::*;

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
