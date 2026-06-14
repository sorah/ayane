//! Server-side verification of RFC 9449 DPoP proofs.
//!
//! A renewal/rekey/self-revocation request proves possession of an existing
//! certificate's private key by presenting a DPoP proof JWT signed by that key.
//! Rather than trusting the public key embedded in the proof header, ayane
//! verifies the proof's signature directly against the presented certificate's
//! public key — so a valid proof is itself evidence the caller holds the
//! certificate's key. The proof is additionally bound to the HTTP method/URI and
//! is single-use via its `jti`.

use der::Encode;

/// A verified DPoP proof.
pub struct VerifiedProof {
    /// The proof's unique id, for one-time enforcement.
    pub jti: String,
    /// The proof's issued-at instant.
    pub issued_at: std::time::SystemTime,
}

/// Build a JWT decoding key and its pinned algorithm from a certificate's
/// `SubjectPublicKeyInfo`.
fn decoding_key_from_spki(
    spki: &spki::SubjectPublicKeyInfoOwned,
) -> crate::error::Result<(jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm)> {
    let spki_der = spki.to_der()?;
    let pem = pem::encode(&pem::Pem::new("PUBLIC KEY", spki_der));

    if spki.algorithm.oid == const_oid::db::rfc5912::ID_EC_PUBLIC_KEY {
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<const_oid::ObjectIdentifier>().ok());
        let alg = match curve {
            Some(c) if c == const_oid::db::rfc5912::SECP_256_R_1 => jsonwebtoken::Algorithm::ES256,
            Some(c) if c == const_oid::db::rfc5912::SECP_384_R_1 => jsonwebtoken::Algorithm::ES384,
            _ => {
                return Err(crate::error::Error::BadRequest(
                    "unsupported EC curve in certificate for DPoP".into(),
                ));
            }
        };
        let key = jsonwebtoken::DecodingKey::from_ec_pem(pem.as_bytes())
            .map_err(|e| crate::error::Error::Internal(format!("DPoP EC key: {e}")))?;
        Ok((key, alg))
    } else if spki.algorithm.oid == const_oid::db::rfc5912::RSA_ENCRYPTION {
        let key = jsonwebtoken::DecodingKey::from_rsa_pem(pem.as_bytes())
            .map_err(|e| crate::error::Error::Internal(format!("DPoP RSA key: {e}")))?;
        Ok((key, jsonwebtoken::Algorithm::RS256))
    } else {
        Err(crate::error::Error::BadRequest(
            "unsupported certificate key type for DPoP".into(),
        ))
    }
}

/// Verify a DPoP `proof` against `cert`'s public key, binding it to the request
/// method/URI and enforcing freshness.
///
/// `max_age` is how old the proof's `iat` may be; a small future skew is also
/// tolerated. Returns the proof `jti` (for replay rejection) on success.
pub fn verify(
    proof: &str,
    cert: &x509_cert::Certificate,
    expected_method: &str,
    expected_uri: &str,
    max_age: std::time::Duration,
    now: std::time::SystemTime,
) -> crate::error::Result<VerifiedProof> {
    let header = jsonwebtoken::decode_header(proof)
        .map_err(|e| crate::error::Error::Unauthorized(format!("invalid DPoP header: {e}")))?;
    if header.typ.as_deref() != Some(ayane_protocol::dpop::DPOP_TYP) {
        return Err(crate::error::Error::Unauthorized(
            "DPoP proof has wrong typ (expected dpop+jwt)".into(),
        ));
    }

    let (decoding_key, algorithm) =
        decoding_key_from_spki(&cert.tbs_certificate.subject_public_key_info)?;
    if header.alg != algorithm {
        return Err(crate::error::Error::Unauthorized(
            "DPoP proof algorithm does not match the certificate key".into(),
        ));
    }

    let mut validation = jsonwebtoken::Validation::new(algorithm);
    validation.required_spec_claims = std::collections::HashSet::new();
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    let data =
        jsonwebtoken::decode::<ayane_protocol::DpopClaims>(proof, &decoding_key, &validation)
            .map_err(|e| {
                crate::error::Error::Unauthorized(format!("DPoP proof signature invalid: {e}"))
            })?;
    let claims = data.claims;

    if !claims.htm.eq_ignore_ascii_case(expected_method) {
        return Err(crate::error::Error::Unauthorized(format!(
            "DPoP htm {:?} does not match {expected_method:?}",
            claims.htm
        )));
    }
    if claims.htu != expected_uri {
        return Err(crate::error::Error::Unauthorized(format!(
            "DPoP htu {:?} does not match {expected_uri:?}",
            claims.htu
        )));
    }

    let iat = std::time::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(claims.iat.max(0) as u64))
        .ok_or_else(|| crate::error::Error::Unauthorized("DPoP iat out of range".into()))?;
    let skew = std::time::Duration::from_secs(60);
    if iat > now + skew {
        return Err(crate::error::Error::Unauthorized(
            "DPoP proof issued in the future".into(),
        ));
    }
    if let Ok(age) = now.duration_since(iat)
        && age > max_age
    {
        return Err(crate::error::Error::Unauthorized(
            "DPoP proof is stale".into(),
        ));
    }

    Ok(VerifiedProof {
        jti: claims.jti,
        issued_at: iat,
    })
}

#[cfg(test)]
mod tests {
    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    async fn make_cert_and_proof(
        htm: &str,
        htu: &str,
        iat: i64,
    ) -> (x509_cert::Certificate, String) {
        use p256::pkcs8::EncodePrivateKey;

        // Leaf key whose cert we issue from the test CA.
        let leaf_secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let leaf_pem = leaf_secret.to_pkcs8_pem(der::pem::LineEnding::LF).unwrap();
        let leaf_spki = {
            use der::Decode;
            use spki::EncodePublicKey;
            spki::SubjectPublicKeyInfoOwned::from_der(
                leaf_secret
                    .public_key()
                    .to_public_key_der()
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap()
        };

        let ca = crate::testca::ec_p256().await;
        let authority = crate::ca::CertificateAuthority::new(
            ca.key.clone(),
            &ca.ca_cert_pem,
            vec![ca.ca_cert_pem.clone()],
            vec![ca.ca_cert_pem.clone()],
        )
        .unwrap();
        let template = crate::template::CertificateTemplate::default();
        let n = std::time::SystemTime::now();
        let issued = authority
            .issue(crate::ca::IssueParams {
                common_name: "leaf.example".into(),
                sans: vec![crate::san::San::Dns("leaf.example".into())],
                public_key: leaf_spki,
                not_before: n,
                not_after: n + std::time::Duration::from_secs(3600),
                template: &template,
                key_usage_override: None,
                extended_key_usage_override: None,
                additional_extensions: Vec::new(),
            })
            .await
            .unwrap();

        // DPoP proof signed by the leaf key.
        let encoding_key = jsonwebtoken::EncodingKey::from_ec_pem(leaf_pem.as_bytes()).unwrap();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.typ = Some("dpop+jwt".to_string());
        let claims = ayane_protocol::DpopClaims {
            htm: htm.to_string(),
            htu: htu.to_string(),
            iat,
            jti: "proof-1".to_string(),
            nonce: None,
        };
        let proof = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();
        (issued.certificate, proof)
    }

    #[tokio::test]
    async fn accepts_fresh_bound_proof() {
        let (cert, proof) =
            make_cert_and_proof("POST", "https://ca.example/v1/renew", now_secs()).await;
        let v = super::verify(
            &proof,
            &cert,
            "POST",
            "https://ca.example/v1/renew",
            std::time::Duration::from_secs(300),
            std::time::SystemTime::now(),
        )
        .unwrap();
        assert_eq!(v.jti, "proof-1");
    }

    #[tokio::test]
    async fn rejects_uri_mismatch() {
        let (cert, proof) =
            make_cert_and_proof("POST", "https://ca.example/v1/renew", now_secs()).await;
        assert!(
            super::verify(
                &proof,
                &cert,
                "POST",
                "https://ca.example/v1/rekey",
                std::time::Duration::from_secs(300),
                std::time::SystemTime::now(),
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn rejects_stale_proof() {
        let (cert, proof) =
            make_cert_and_proof("POST", "https://ca.example/v1/renew", now_secs() - 10_000).await;
        assert!(
            super::verify(
                &proof,
                &cert,
                "POST",
                "https://ca.example/v1/renew",
                std::time::Duration::from_secs(300),
                std::time::SystemTime::now(),
            )
            .is_err()
        );
    }
}
