//! `GET /v1/roots`: the signed roots response and its caching.

use super::*;

#[tokio::test]
async fn signed_roots_is_verifiable_and_cached() {
    use signature::Verifier;

    let h = setup().await;
    let signed = h.service.signed_roots().await.expect("sign roots");

    // The body is the roots JSON, and Content-Digest (SHA-384) covers it exactly.
    let want_digest: [u8; 48] = {
        use sha2::Digest;
        sha2::Sha384::digest(&signed.body).into()
    };
    assert_eq!(
        ayane_protocol::httpsig::parse_content_digest(&signed.content_digest).unwrap(),
        want_digest
    );

    // Signature-Key references the signer chain and pins the leaf thumbprint.
    let (x5u, x5t) =
        ayane_protocol::httpsig::parse_signature_key_x509(&signed.signature_key).unwrap();
    assert_eq!(x5u, ayane_protocol::httpsig::SIGNER_CHAIN_PATH);
    let leaf = crate::x509::certificate_from_pem(&h.service.signer_chain_pem()).unwrap();
    let leaf_digest: [u8; 32] = {
        use der::Encode;
        use sha2::Digest;
        sha2::Sha256::digest(leaf.to_der().unwrap()).into()
    };
    assert_eq!(x5t, ayane_protocol::httpsig::x5t_from_digest(&leaf_digest));

    // Reconstruct the signature base and verify the signature with the signer
    // (CA) public key — exactly what the client will do.
    let params = ayane_protocol::httpsig::parse_roots_sig_params(&signed.signature_input).unwrap();
    assert_eq!(params.alg, "ecdsa-p256-sha256");
    let base = ayane_protocol::httpsig::roots_signature_base(
        200,
        ayane_protocol::httpsig::ROOTS_CONTENT_TYPE,
        &signed.content_digest,
        &signed.signature_key,
        &params,
    );
    let raw = ayane_protocol::httpsig::parse_signature_header(&signed.signature).unwrap();
    let verifying = {
        use spki::DecodePublicKey;
        let spki_der = {
            use der::Encode;
            leaf.tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap()
        };
        p256::ecdsa::VerifyingKey::from_public_key_der(&spki_der).unwrap()
    };
    let sig = p256::ecdsa::Signature::from_slice(&raw).unwrap();
    verifying
        .verify(base.as_bytes(), &sig)
        .expect("roots signature verifies under the CA key");

    // A second call reuses the cached signature (same created/signature).
    let again = h.service.signed_roots().await.unwrap();
    assert_eq!(again.signature, signed.signature);
    assert_eq!(again.signature_input, signed.signature_input);
}
