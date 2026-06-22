//! Signature-algorithm modelling and low-level X.509 crypto helpers.
//!
//! The CA never holds a private key in this module; signing is delegated to a
//! [`crate::key_provider::KeyProvider`]. What lives here is the algorithm
//! taxonomy shared by every signer (its OIDs, hash and DER encodings) plus the
//! subject-key-identifier computation.

/// Asymmetric signature algorithms ayane can sign certificates with.
///
/// Each maps 1:1 to an X.509 `signatureAlgorithm` OID, a digest, and an AWS KMS
/// `SigningAlgorithmSpec` (the KMS mapping lives in the KMS key provider).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// `ecdsa-with-SHA256` over a P-256 key.
    EcdsaSha256,
    /// `ecdsa-with-SHA384` over a P-384 key.
    EcdsaSha384,
    /// `sha256WithRSAEncryption` (PKCS#1 v1.5).
    RsaPkcs1Sha256,
    /// `sha384WithRSAEncryption` (PKCS#1 v1.5).
    RsaPkcs1Sha384,
    /// `sha512WithRSAEncryption` (PKCS#1 v1.5).
    RsaPkcs1Sha512,
}

impl SignatureAlgorithm {
    /// The X.509 `signatureAlgorithm` OID.
    pub fn oid(self) -> const_oid::ObjectIdentifier {
        match self {
            SignatureAlgorithm::EcdsaSha256 => const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
            SignatureAlgorithm::EcdsaSha384 => const_oid::db::rfc5912::ECDSA_WITH_SHA_384,
            SignatureAlgorithm::RsaPkcs1Sha256 => {
                const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION
            }
            SignatureAlgorithm::RsaPkcs1Sha384 => {
                const_oid::db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION
            }
            SignatureAlgorithm::RsaPkcs1Sha512 => {
                const_oid::db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION
            }
        }
    }

    /// Whether this is one of the RSA variants.
    pub fn is_rsa(self) -> bool {
        matches!(
            self,
            SignatureAlgorithm::RsaPkcs1Sha256
                | SignatureAlgorithm::RsaPkcs1Sha384
                | SignatureAlgorithm::RsaPkcs1Sha512
        )
    }

    /// The DER `AlgorithmIdentifier` for X.509 signature fields.
    ///
    /// RSA algorithms carry an explicit `NULL` parameter (RFC 3279/4055); ECDSA
    /// algorithms omit parameters entirely.
    pub fn algorithm_identifier(self) -> crate::error::Result<spki::AlgorithmIdentifierOwned> {
        let parameters = if self.is_rsa() {
            Some(der::Any::from(der::asn1::Null))
        } else {
            None
        };
        Ok(spki::AlgorithmIdentifierOwned {
            oid: self.oid(),
            parameters,
        })
    }

    /// Hash `message` with this algorithm's digest, returning the raw digest.
    pub fn digest(self, message: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        match self {
            SignatureAlgorithm::EcdsaSha256 | SignatureAlgorithm::RsaPkcs1Sha256 => {
                sha2::Sha256::digest(message).to_vec()
            }
            SignatureAlgorithm::EcdsaSha384 | SignatureAlgorithm::RsaPkcs1Sha384 => {
                sha2::Sha384::digest(message).to_vec()
            }
            SignatureAlgorithm::RsaPkcs1Sha512 => sha2::Sha512::digest(message).to_vec(),
        }
    }

    /// The RFC 9421 signature algorithm token for this algorithm.
    ///
    /// The SHA-384/512 RSA tokens are ayane-private (RFC 9421 only registers
    /// `rsa-v1_5-sha256` for PKCS#1 v1.5); the only verifier is `ayane-cli`.
    pub fn rfc9421_alg(self) -> &'static str {
        match self {
            SignatureAlgorithm::EcdsaSha256 => "ecdsa-p256-sha256",
            SignatureAlgorithm::EcdsaSha384 => "ecdsa-p384-sha384",
            SignatureAlgorithm::RsaPkcs1Sha256 => "rsa-v1_5-sha256",
            SignatureAlgorithm::RsaPkcs1Sha384 => "rsa-v1_5-sha384",
            SignatureAlgorithm::RsaPkcs1Sha512 => "rsa-v1_5-sha512",
        }
    }

    /// Re-encode an X.509 signature into RFC 9421 form.
    ///
    /// RFC 9421 ECDSA signatures are the fixed-width IEEE P1363 `r‖s`
    /// concatenation, whereas a [`crate::key_provider::KeyProvider`] returns the
    /// DER `ECDSA-Sig-Value` used in certificates; this converts between them.
    /// RSA PKCS#1 v1.5 bytes are identical in both encodings, so they pass
    /// through unchanged.
    pub fn rfc9421_signature_from_der(self, der: &[u8]) -> crate::error::Result<Vec<u8>> {
        let invalid = |e: &dyn std::fmt::Display| {
            crate::error::Error::Internal(format!("re-encode ECDSA signature: {e}"))
        };
        match self {
            SignatureAlgorithm::EcdsaSha256 => p256::ecdsa::Signature::from_der(der)
                .map(|s| s.to_bytes().to_vec())
                .map_err(|e| invalid(&e)),
            SignatureAlgorithm::EcdsaSha384 => p384::ecdsa::Signature::from_der(der)
                .map(|s| s.to_bytes().to_vec())
                .map_err(|e| invalid(&e)),
            SignatureAlgorithm::RsaPkcs1Sha256
            | SignatureAlgorithm::RsaPkcs1Sha384
            | SignatureAlgorithm::RsaPkcs1Sha512 => Ok(der.to_vec()),
        }
    }

    /// Parse from a config string such as `"ECDSA_SHA256"` / `"RSA_PKCS1_SHA256"`.
    pub fn parse(s: &str) -> crate::error::Result<Self> {
        match s.to_ascii_uppercase().replace(['-', ' '], "_").as_str() {
            "ECDSA_SHA256" | "ES256" => Ok(SignatureAlgorithm::EcdsaSha256),
            "ECDSA_SHA384" | "ES384" => Ok(SignatureAlgorithm::EcdsaSha384),
            "RSA_PKCS1_SHA256" | "RS256" => Ok(SignatureAlgorithm::RsaPkcs1Sha256),
            "RSA_PKCS1_SHA384" | "RS384" => Ok(SignatureAlgorithm::RsaPkcs1Sha384),
            "RSA_PKCS1_SHA512" | "RS512" => Ok(SignatureAlgorithm::RsaPkcs1Sha512),
            other => Err(crate::error::Error::Config(format!(
                "unknown signature algorithm: {other}"
            ))),
        }
    }
}

/// Compute the RFC 5280 method-1 subject key identifier: the 160-bit SHA-1
/// digest of the `subjectPublicKey` BIT STRING contents.
pub fn key_identifier(spki: &spki::SubjectPublicKeyInfoOwned) -> Vec<u8> {
    use sha1::Digest;
    sha1::Sha1::digest(spki.subject_public_key.raw_bytes()).to_vec()
}

/// Verify a signature over `tbs` using the public key in `spki_der`, dispatching
/// on the X.509 `signatureAlgorithm` OID.
///
/// Shared by CSR proof-of-possession checks and the "did this CA issue this
/// certificate?" check performed during renewal. Supports ECDSA P-256/P-384 and
/// RSA PKCS#1 v1.5 with SHA-256/384/512.
pub fn verify_signature(
    spki_der: &[u8],
    tbs: &[u8],
    sig: &[u8],
    alg_oid: const_oid::ObjectIdentifier,
) -> crate::error::Result<()> {
    ayane_protocol::crypto::verify_x509_signature(spki_der, tbs, sig, alg_oid).map_err(
        |e| match e {
            // A signature over a CSR/cert that does not validate is a caller error
            // (forbidden); an unsupported algorithm is a bad request.
            ayane_protocol::crypto::SignatureError::Invalid(_) => {
                crate::error::Error::Forbidden(e.to_string())
            }
            ayane_protocol::crypto::SignatureError::Unsupported(_) => {
                crate::error::Error::BadRequest(e.to_string())
            }
        },
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn algorithm_identifier_rsa_has_null_params() {
        let ai = super::SignatureAlgorithm::RsaPkcs1Sha256
            .algorithm_identifier()
            .unwrap();
        assert!(ai.parameters.is_some());
    }

    #[test]
    fn algorithm_identifier_ecdsa_omits_params() {
        let ai = super::SignatureAlgorithm::EcdsaSha256
            .algorithm_identifier()
            .unwrap();
        assert!(ai.parameters.is_none());
    }

    #[test]
    fn parse_roundtrip() {
        assert_eq!(
            super::SignatureAlgorithm::parse("ecdsa-sha256").unwrap(),
            super::SignatureAlgorithm::EcdsaSha256
        );
        assert!(super::SignatureAlgorithm::parse("bogus").is_err());
    }

    #[test]
    fn ecdsa_der_to_rfc9421_is_fixed_width_p1363() {
        use signature::Signer;
        let key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let signature: p256::ecdsa::Signature = key.sign(b"message");
        let der = signature.to_der();
        let raw = super::SignatureAlgorithm::EcdsaSha256
            .rfc9421_signature_from_der(der.as_bytes())
            .unwrap();
        // P-256 P1363 signatures are exactly 64 bytes (r‖s) and equal the
        // signature's own fixed-width encoding.
        assert_eq!(raw.len(), 64);
        assert_eq!(raw, signature.to_bytes().to_vec());
    }

    #[test]
    fn rsa_signature_passes_through_unchanged() {
        let bytes = vec![1u8, 2, 3, 4];
        assert_eq!(
            super::SignatureAlgorithm::RsaPkcs1Sha256
                .rfc9421_signature_from_der(&bytes)
                .unwrap(),
            bytes
        );
    }
}
