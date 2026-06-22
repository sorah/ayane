//! Shared low-level signature verification for X.509 certificates and RFC 9421
//! HTTP message signatures.
//!
//! Both the server (CSR proof-of-possession, "did this CA issue this cert?") and
//! the client (`ayane roots` signer-chain anchoring and roots-signature checking)
//! verify the same kinds of signatures; keeping the primitive here means a single
//! audited copy. Supports ECDSA P-256/P-384 and RSA PKCS#1 v1.5 with
//! SHA-256/384/512.

/// A failure to verify a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// The signature algorithm is not one we support.
    Unsupported(String),
    /// The key or signature did not decode, or verification failed.
    Invalid(String),
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureError::Unsupported(a) => write!(f, "unsupported signature algorithm: {a}"),
            SignatureError::Invalid(e) => write!(f, "signature verification failed: {e}"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// Verify an X.509 signature: `sig` over `tbs` under the public key in
/// `spki_der`, dispatching on the certificate `signatureAlgorithm` OID. ECDSA
/// signatures are the DER `ECDSA-Sig-Value` form used in certificates.
pub fn verify_x509_signature(
    spki_der: &[u8],
    tbs: &[u8],
    sig: &[u8],
    alg_oid: const_oid::ObjectIdentifier,
) -> Result<(), SignatureError> {
    use signature::Verifier;
    use spki::DecodePublicKey;

    let invalid = |e: &dyn std::fmt::Display| SignatureError::Invalid(e.to_string());

    if alg_oid == const_oid::db::rfc5912::ECDSA_WITH_SHA_256 {
        let vk =
            p256::ecdsa::VerifyingKey::from_public_key_der(spki_der).map_err(|e| invalid(&e))?;
        let signature = p256::ecdsa::Signature::from_der(sig).map_err(|e| invalid(&e))?;
        vk.verify(tbs, &signature).map_err(|e| invalid(&e))
    } else if alg_oid == const_oid::db::rfc5912::ECDSA_WITH_SHA_384 {
        let vk =
            p384::ecdsa::VerifyingKey::from_public_key_der(spki_der).map_err(|e| invalid(&e))?;
        let signature = p384::ecdsa::Signature::from_der(sig).map_err(|e| invalid(&e))?;
        vk.verify(tbs, &signature).map_err(|e| invalid(&e))
    } else if alg_oid == const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION {
        verify_rsa::<sha2::Sha256>(spki_der, tbs, sig)
    } else if alg_oid == const_oid::db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION {
        verify_rsa::<sha2::Sha384>(spki_der, tbs, sig)
    } else if alg_oid == const_oid::db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION {
        verify_rsa::<sha2::Sha512>(spki_der, tbs, sig)
    } else {
        Err(SignatureError::Unsupported(alg_oid.to_string()))
    }
}

/// Verify an RFC 9421 HTTP message signature: `raw` over `msg` under the public
/// key in `spki_der`, dispatching on the RFC 9421 `alg` token. ECDSA signatures
/// are the fixed-width IEEE P1363 `r‖s` form (not DER); RSA is PKCS#1 v1.5.
pub fn verify_rfc9421_signature(
    alg: &str,
    spki_der: &[u8],
    msg: &[u8],
    raw: &[u8],
) -> Result<(), SignatureError> {
    use signature::Verifier;
    use spki::DecodePublicKey;

    let invalid = |e: &dyn std::fmt::Display| SignatureError::Invalid(e.to_string());

    match alg {
        "ecdsa-p256-sha256" => {
            let vk = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der)
                .map_err(|e| invalid(&e))?;
            let signature = p256::ecdsa::Signature::from_slice(raw).map_err(|e| invalid(&e))?;
            vk.verify(msg, &signature).map_err(|e| invalid(&e))
        }
        "ecdsa-p384-sha384" => {
            let vk = p384::ecdsa::VerifyingKey::from_public_key_der(spki_der)
                .map_err(|e| invalid(&e))?;
            let signature = p384::ecdsa::Signature::from_slice(raw).map_err(|e| invalid(&e))?;
            vk.verify(msg, &signature).map_err(|e| invalid(&e))
        }
        "rsa-v1_5-sha256" => verify_rsa::<sha2::Sha256>(spki_der, msg, raw),
        "rsa-v1_5-sha384" => verify_rsa::<sha2::Sha384>(spki_der, msg, raw),
        "rsa-v1_5-sha512" => verify_rsa::<sha2::Sha512>(spki_der, msg, raw),
        other => Err(SignatureError::Unsupported(other.to_string())),
    }
}

fn verify_rsa<D>(spki_der: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), SignatureError>
where
    D: digest::Digest + const_oid::AssociatedOid,
{
    use signature::Verifier;
    use spki::DecodePublicKey;

    let invalid = |e: &dyn std::fmt::Display| SignatureError::Invalid(e.to_string());
    let pubkey = rsa::RsaPublicKey::from_public_key_der(spki_der).map_err(|e| invalid(&e))?;
    let vk = rsa::pkcs1v15::VerifyingKey::<D>::new(pubkey);
    let signature = rsa::pkcs1v15::Signature::try_from(sig).map_err(|e| invalid(&e))?;
    vk.verify(msg, &signature).map_err(|e| invalid(&e))
}

#[cfg(test)]
mod tests {
    // A fixed, valid P-256 scalar avoids a randomness dependency in this crate.
    fn p256_key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[1u8; 32]).unwrap()
    }

    fn spki_der(k: &p256::ecdsa::SigningKey) -> Vec<u8> {
        use spki::EncodePublicKey;
        k.verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn rfc9421_p256_roundtrip() {
        let k = p256_key();
        let msg = b"signature base";
        let sig =
            <p256::ecdsa::SigningKey as signature::Signer<p256::ecdsa::Signature>>::sign(&k, msg);
        let spki = spki_der(&k);
        super::verify_rfc9421_signature("ecdsa-p256-sha256", &spki, msg, &sig.to_bytes()).unwrap();
        // A tampered message no longer verifies.
        assert!(
            super::verify_rfc9421_signature(
                "ecdsa-p256-sha256",
                &spki,
                b"tampered",
                &sig.to_bytes()
            )
            .is_err()
        );
        // An unknown token is reported as unsupported, not invalid.
        assert!(matches!(
            super::verify_rfc9421_signature("bogus", &spki, msg, &sig.to_bytes()),
            Err(super::SignatureError::Unsupported(_))
        ));
    }

    #[test]
    fn x509_p256_der_roundtrip() {
        let k = p256_key();
        let msg = b"tbs certificate";
        let sig = <p256::ecdsa::SigningKey as signature::Signer<p256::ecdsa::DerSignature>>::sign(
            &k, msg,
        );
        let spki = spki_der(&k);
        super::verify_x509_signature(
            &spki,
            msg,
            sig.as_bytes(),
            const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
        )
        .unwrap();
        // A non-signature OID is unsupported.
        assert!(matches!(
            super::verify_x509_signature(
                &spki,
                msg,
                sig.as_bytes(),
                const_oid::db::rfc5912::SECP_256_R_1,
            ),
            Err(super::SignatureError::Unsupported(_))
        ));
    }
}
