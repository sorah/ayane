//! Verify the RFC 9421 signature on a `GET /v1/roots` response against a pinned
//! trusted root bundle.
//!
//! The CA signs the roots response with its issuing key; this proves the bundle
//! came from our PKI even when TLS is terminated by a third-party certificate.
//! Verification is fail-closed: the body digest must match, the signature must be
//! fresh and valid under the signer (issuing) certificate referenced by `x5u`
//! (with its leaf pinned by the signed `x5t`), and that signer certificate must
//! chain to a certificate in the pinned `--root` bundle. The signature-base
//! construction is shared with the server via [`ayane_protocol::httpsig`].

use der::{Decode, Encode};

/// Clock-skew leeway for the signature `created` instant, matching the OTT/DPoP
/// convention.
const SKEW: u64 = 60;

/// The header values pulled off the `GET /v1/roots` response.
pub(crate) struct ResponseHeaders {
    pub content_digest: String,
    pub signature_input: String,
    pub signature: String,
    pub signature_key: String,
}

/// Verify the signed roots response.
///
/// `signer_chain_pem` is the chain already fetched from the response's `x5u`
/// (the caller enforces same-origin); `known_roots_pem` is the pinned `--root`
/// bundle. `now` is the verification instant in epoch seconds.
pub(crate) fn verify_roots_response(
    body: &[u8],
    headers: &ResponseHeaders,
    signer_chain_pem: &[u8],
    known_roots_pem: &[u8],
    now: u64,
) -> anyhow::Result<()> {
    // 1. Body digest must match Content-Digest.
    let want_digest = sha384(body);
    let got_digest = ayane_protocol::httpsig::parse_content_digest(&headers.content_digest)?;
    if got_digest != want_digest {
        anyhow::bail!("roots response Content-Digest does not match the body");
    }

    // 2. Freshness.
    let params = ayane_protocol::httpsig::parse_roots_sig_params(&headers.signature_input)?;
    if now >= params.expires {
        anyhow::bail!("roots signature has expired");
    }
    if params.created > now + SKEW {
        anyhow::bail!("roots signature is dated in the future");
    }

    // 3. Signer chain and the signed leaf thumbprint.
    let (_x5u, x5t) = ayane_protocol::httpsig::parse_signature_key_x509(&headers.signature_key)?;
    let chain = parse_certificates(signer_chain_pem)?;
    let leaf = chain
        .first()
        .ok_or_else(|| anyhow::anyhow!("signer chain is empty"))?;
    let leaf_thumbprint = ayane_protocol::httpsig::x5t_from_digest(&sha256(&leaf.to_der()?));
    if leaf_thumbprint != x5t {
        anyhow::bail!("signer chain leaf does not match the signed x5t thumbprint");
    }

    // 4. Verify the signature under the leaf's public key.
    let base = ayane_protocol::httpsig::roots_signature_base(
        200,
        ayane_protocol::httpsig::ROOTS_CONTENT_TYPE,
        &headers.content_digest,
        &headers.signature_key,
        &params,
    );
    let signature = ayane_protocol::httpsig::parse_signature_header(&headers.signature)?;
    let leaf_spki = leaf.tbs_certificate.subject_public_key_info.to_der()?;
    verify_rfc9421_signature(&params.alg, &leaf_spki, base.as_bytes(), &signature)?;

    // 5. Anchor the signer chain in the pinned root bundle.
    let known = parse_certificates(known_roots_pem)?;
    if known.is_empty() {
        anyhow::bail!("pinned root bundle contains no certificates");
    }
    anchor_to_known(&chain, &known)?;

    Ok(())
}

/// Verify that the signer chain links up to a certificate in `known`.
fn anchor_to_known(
    chain: &[x509_cert::Certificate],
    known: &[x509_cert::Certificate],
) -> anyhow::Result<()> {
    // Each presented cert must be signed by the next one.
    for pair in chain.windows(2) {
        let parent_spki = pair[1].tbs_certificate.subject_public_key_info.to_der()?;
        verify_x509_signature(&pair[0], &parent_spki)
            .map_err(|e| anyhow::anyhow!("signer chain link is not valid: {e}"))?;
    }

    // The top of the presented chain must be a known root, or be issued by one.
    let top = chain
        .last()
        .ok_or_else(|| anyhow::anyhow!("signer chain is empty"))?;
    let top_der = top.to_der()?;
    let top_issuer = top.tbs_certificate.issuer.to_der()?;
    for k in known {
        if k.to_der()? == top_der {
            return Ok(());
        }
        if k.tbs_certificate.subject.to_der()? == top_issuer {
            let k_spki = k.tbs_certificate.subject_public_key_info.to_der()?;
            if verify_x509_signature(top, &k_spki).is_ok() {
                return Ok(());
            }
        }
    }
    anyhow::bail!("signer chain does not anchor to the pinned root bundle")
}

/// Verify an RFC 9421 message signature (`raw` over `msg`) using the public key
/// in `spki_der`, dispatching on the `alg` token.
fn verify_rfc9421_signature(
    alg: &str,
    spki_der: &[u8],
    msg: &[u8],
    raw: &[u8],
) -> anyhow::Result<()> {
    use signature::Verifier;
    use spki::DecodePublicKey;

    let bad = |e: &dyn std::fmt::Display| anyhow::anyhow!("roots signature is invalid: {e}");
    match alg {
        "ecdsa-p256-sha256" => {
            let vk = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der)?;
            let sig = p256::ecdsa::Signature::from_slice(raw).map_err(|e| bad(&e))?;
            vk.verify(msg, &sig).map_err(|e| bad(&e))
        }
        "ecdsa-p384-sha384" => {
            let vk = p384::ecdsa::VerifyingKey::from_public_key_der(spki_der)?;
            let sig = p384::ecdsa::Signature::from_slice(raw).map_err(|e| bad(&e))?;
            vk.verify(msg, &sig).map_err(|e| bad(&e))
        }
        "rsa-v1_5-sha256" => verify_rsa::<sha2::Sha256>(spki_der, msg, raw),
        "rsa-v1_5-sha384" => verify_rsa::<sha2::Sha384>(spki_der, msg, raw),
        "rsa-v1_5-sha512" => verify_rsa::<sha2::Sha512>(spki_der, msg, raw),
        other => anyhow::bail!("unsupported roots signature algorithm {other:?}"),
    }
}

fn verify_rsa<D>(spki_der: &[u8], msg: &[u8], raw: &[u8]) -> anyhow::Result<()>
where
    D: digest::Digest + const_oid::AssociatedOid,
{
    use signature::Verifier;
    use spki::DecodePublicKey;
    let pubkey = rsa::RsaPublicKey::from_public_key_der(spki_der)?;
    let vk = rsa::pkcs1v15::VerifyingKey::<D>::new(pubkey);
    let sig = rsa::pkcs1v15::Signature::try_from(raw)
        .map_err(|e| anyhow::anyhow!("roots signature is invalid: {e}"))?;
    vk.verify(msg, &sig)
        .map_err(|e| anyhow::anyhow!("roots signature is invalid: {e}"))
}

/// Verify that `cert`'s X.509 signature validates under `parent_spki_der`,
/// dispatching on the certificate's `signatureAlgorithm` (DER ECDSA / PKCS#1).
fn verify_x509_signature(
    cert: &x509_cert::Certificate,
    parent_spki_der: &[u8],
) -> anyhow::Result<()> {
    use signature::Verifier;
    use spki::DecodePublicKey;

    let tbs = cert.tbs_certificate.to_der()?;
    let sig = cert.signature.raw_bytes();
    let oid = cert.signature_algorithm.oid;
    let bad = |e: &dyn std::fmt::Display| anyhow::anyhow!("signature verification failed: {e}");

    if oid == const_oid::db::rfc5912::ECDSA_WITH_SHA_256 {
        let vk = p256::ecdsa::VerifyingKey::from_public_key_der(parent_spki_der)?;
        let sig = p256::ecdsa::Signature::from_der(sig).map_err(|e| bad(&e))?;
        vk.verify(&tbs, &sig).map_err(|e| bad(&e))
    } else if oid == const_oid::db::rfc5912::ECDSA_WITH_SHA_384 {
        let vk = p384::ecdsa::VerifyingKey::from_public_key_der(parent_spki_der)?;
        let sig = p384::ecdsa::Signature::from_der(sig).map_err(|e| bad(&e))?;
        vk.verify(&tbs, &sig).map_err(|e| bad(&e))
    } else if oid == const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION {
        verify_rsa::<sha2::Sha256>(parent_spki_der, &tbs, sig)
    } else if oid == const_oid::db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION {
        verify_rsa::<sha2::Sha384>(parent_spki_der, &tbs, sig)
    } else if oid == const_oid::db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION {
        verify_rsa::<sha2::Sha512>(parent_spki_der, &tbs, sig)
    } else {
        anyhow::bail!("unsupported certificate signature algorithm: {oid}")
    }
}

/// Parse every `CERTIFICATE` block from a PEM bundle into DER certificates.
fn parse_certificates(pem_bytes: &[u8]) -> anyhow::Result<Vec<x509_cert::Certificate>> {
    let mut out = Vec::new();
    for block in pem::parse_many(pem_bytes)? {
        if block.tag() == "CERTIFICATE" {
            out.push(x509_cert::Certificate::from_der(block.contents())?);
        }
    }
    Ok(out)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

fn sha384(bytes: &[u8]) -> [u8; 48] {
    use sha2::Digest;
    sha2::Sha384::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use der::EncodePem;

    /// A self-signed P-256 CA: its signing key and certificate. Acting as both
    /// the signer leaf and the trust anchor (single-tier) keeps the fixture small.
    fn self_signed_ca() -> (p256::ecdsa::SigningKey, x509_cert::Certificate) {
        use std::str::FromStr;
        let signing = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let spki = {
            use der::Decode;
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
        let builder = x509_cert::builder::CertificateBuilder::new(
            x509_cert::builder::Profile::Root,
            x509_cert::serial_number::SerialNumber::from(1u32),
            x509_cert::time::Validity::from_now(std::time::Duration::from_secs(3600)).unwrap(),
            x509_cert::name::Name::from_str("CN=ayane-test-ca").unwrap(),
            spki,
            &signing,
        )
        .unwrap();
        use x509_cert::builder::Builder;
        let cert = builder.build::<p256::ecdsa::DerSignature>().unwrap();
        (signing, cert)
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Sign `body` as the CA would, returning the response headers.
    fn sign_response(
        signing: &p256::ecdsa::SigningKey,
        cert: &x509_cert::Certificate,
        body: &[u8],
        created: u64,
        expires: u64,
    ) -> super::ResponseHeaders {
        use der::Encode;
        let content_digest = ayane_protocol::httpsig::content_digest_header(&super::sha384(body));
        let x5t = ayane_protocol::httpsig::x5t_from_digest(&super::sha256(&cert.to_der().unwrap()));
        let signature_key = ayane_protocol::httpsig::signature_key_x509(
            ayane_protocol::httpsig::SIGNER_CHAIN_PATH,
            &x5t,
        );
        let params = ayane_protocol::httpsig::RootsSigParams {
            created,
            expires,
            alg: "ecdsa-p256-sha256".to_string(),
        };
        let base = ayane_protocol::httpsig::roots_signature_base(
            200,
            ayane_protocol::httpsig::ROOTS_CONTENT_TYPE,
            &content_digest,
            &signature_key,
            &params,
        );
        let sig = <p256::ecdsa::SigningKey as signature::Signer<p256::ecdsa::Signature>>::sign(
            signing,
            base.as_bytes(),
        );
        super::ResponseHeaders {
            content_digest,
            signature_input: ayane_protocol::httpsig::signature_input_value(&params),
            signature: ayane_protocol::httpsig::signature_header_value(&sig.to_bytes()),
            signature_key,
        }
    }

    fn pem_of(cert: &x509_cert::Certificate) -> String {
        cert.to_pem(der::pem::LineEnding::LF).unwrap()
    }

    #[test]
    fn accepts_a_valid_signed_response() {
        let (signing, cert) = self_signed_ca();
        let body = br#"{"certificates":["root-pem"]}"#;
        let headers = sign_response(&signing, &cert, body, now(), now() + 600);
        let chain = pem_of(&cert);
        super::verify_roots_response(body, &headers, chain.as_bytes(), chain.as_bytes(), now())
            .expect("valid response verifies");
    }

    #[test]
    fn rejects_tampered_body() {
        let (signing, cert) = self_signed_ca();
        let headers = sign_response(&signing, &cert, b"original", now(), now() + 600);
        let chain = pem_of(&cert);
        // A different body no longer matches Content-Digest.
        assert!(
            super::verify_roots_response(
                b"tampered",
                &headers,
                chain.as_bytes(),
                chain.as_bytes(),
                now()
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_expired_signature() {
        let (signing, cert) = self_signed_ca();
        let body = b"body";
        let headers = sign_response(&signing, &cert, body, now() - 1200, now() - 600);
        let chain = pem_of(&cert);
        assert!(
            super::verify_roots_response(body, &headers, chain.as_bytes(), chain.as_bytes(), now())
                .is_err()
        );
    }

    #[test]
    fn rejects_unanchored_signer() {
        let (signing, cert) = self_signed_ca();
        let body = b"body";
        let headers = sign_response(&signing, &cert, body, now(), now() + 600);
        let chain = pem_of(&cert);
        // A different, unrelated CA is the only pinned root.
        let (_other_key, other) = self_signed_ca();
        let other_root = pem_of(&other);
        assert!(
            super::verify_roots_response(
                body,
                &headers,
                chain.as_bytes(),
                other_root.as_bytes(),
                now()
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_wrong_x5t() {
        let (signing, cert) = self_signed_ca();
        let body = b"body";
        let mut headers = sign_response(&signing, &cert, body, now(), now() + 600);
        // Swap in a Signature-Key whose x5t does not match the leaf.
        headers.signature_key = ayane_protocol::httpsig::signature_key_x509(
            ayane_protocol::httpsig::SIGNER_CHAIN_PATH,
            "not-the-leaf-thumbprint",
        );
        let chain = pem_of(&cert);
        assert!(
            super::verify_roots_response(body, &headers, chain.as_bytes(), chain.as_bytes(), now())
                .is_err()
        );
    }
}
