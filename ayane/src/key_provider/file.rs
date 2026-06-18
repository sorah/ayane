//! A [`KeyProvider`](crate::key_provider::KeyProvider) backed by a local PEM
//! private key (PKCS#8 for EC P-256/P-384, PKCS#8 or PKCS#1 for RSA).
//!
//! Intended for development, on-box deployments, and tests. Production
//! deployments should prefer [`crate::key_provider::aws_kms`].

enum FileKey {
    EcP256(Box<p256::ecdsa::SigningKey>),
    EcP384(Box<p384::ecdsa::SigningKey>),
    Rsa(Box<rsa::RsaPrivateKey>),
}

/// A signing key loaded from a PEM file.
pub struct FileKeyProvider {
    key: FileKey,
    algorithm: crate::crypto::SignatureAlgorithm,
    public_key_der: Vec<u8>,
}

impl FileKeyProvider {
    /// Load a key from PEM text. For RSA, `algorithm_override` selects the
    /// digest (default SHA-256); it is ignored for EC keys, whose digest is
    /// fixed by the curve.
    pub fn from_pem(
        pem: &str,
        algorithm_override: Option<crate::crypto::SignatureAlgorithm>,
    ) -> crate::error::Result<Self> {
        use pkcs8::DecodePrivateKey;
        use spki::EncodePublicKey;

        if let Ok(secret) = p256::SecretKey::from_pkcs8_pem(pem) {
            let sk = p256::ecdsa::SigningKey::from(secret);
            let public_key_der = sk
                .verifying_key()
                .to_public_key_der()
                .map_err(|e| crate::error::Error::Config(format!("EC P-256 public key: {e}")))?
                .as_bytes()
                .to_vec();
            return Ok(FileKeyProvider {
                key: FileKey::EcP256(Box::new(sk)),
                algorithm: crate::crypto::SignatureAlgorithm::EcdsaSha256,
                public_key_der,
            });
        }

        if let Ok(secret) = p384::SecretKey::from_pkcs8_pem(pem) {
            let sk = p384::ecdsa::SigningKey::from(secret);
            let public_key_der = sk
                .verifying_key()
                .to_public_key_der()
                .map_err(|e| crate::error::Error::Config(format!("EC P-384 public key: {e}")))?
                .as_bytes()
                .to_vec();
            return Ok(FileKeyProvider {
                key: FileKey::EcP384(Box::new(sk)),
                algorithm: crate::crypto::SignatureAlgorithm::EcdsaSha384,
                public_key_der,
            });
        }

        let rsa_key = rsa::RsaPrivateKey::from_pkcs8_pem(pem).ok().or_else(|| {
            use rsa::pkcs1::DecodeRsaPrivateKey;
            rsa::RsaPrivateKey::from_pkcs1_pem(pem).ok()
        });
        if let Some(key) = rsa_key {
            let algorithm = algorithm_override
                .filter(|a| a.is_rsa())
                .unwrap_or(crate::crypto::SignatureAlgorithm::RsaPkcs1Sha256);
            let public_key_der = rsa::RsaPublicKey::from(&key)
                .to_public_key_der()
                .map_err(|e| crate::error::Error::Config(format!("RSA public key: {e}")))?
                .as_bytes()
                .to_vec();
            return Ok(FileKeyProvider {
                key: FileKey::Rsa(Box::new(key)),
                algorithm,
                public_key_der,
            });
        }

        Err(crate::error::Error::Config(
            "unsupported private key PEM (expected PKCS#8 EC P-256/P-384, or PKCS#8/PKCS#1 RSA)"
                .to_string(),
        ))
    }

    /// Load a key from a file path.
    pub fn from_path(
        path: &std::path::Path,
        algorithm_override: Option<crate::crypto::SignatureAlgorithm>,
    ) -> crate::error::Result<Self> {
        let pem = std::fs::read_to_string(path).map_err(|e| {
            crate::error::Error::Config(format!("read key {}: {e}", path.display()))
        })?;
        Self::from_pem(&pem, algorithm_override)
    }
}

fn sign_rsa<D>(key: &rsa::RsaPrivateKey, message: &[u8]) -> crate::error::Result<Vec<u8>>
where
    D: digest::Digest + const_oid::AssociatedOid,
{
    use signature::{SignatureEncoding, Signer};
    let signing_key = rsa::pkcs1v15::SigningKey::<D>::new(key.clone());
    let signature = signing_key
        .try_sign(message)
        .map_err(|e| crate::error::Error::Internal(format!("RSA sign: {e}")))?;
    Ok(signature.to_vec())
}

#[async_trait::async_trait]
impl crate::key_provider::KeyProvider for FileKeyProvider {
    fn algorithm(&self) -> crate::crypto::SignatureAlgorithm {
        self.algorithm
    }

    fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }

    async fn sign(&self, message: &[u8]) -> crate::error::Result<Vec<u8>> {
        match &self.key {
            FileKey::EcP256(sk) => {
                use signature::{SignatureEncoding, Signer};
                let sig: p256::ecdsa::Signature = sk
                    .try_sign(message)
                    .map_err(|e| crate::error::Error::Internal(format!("ECDSA sign: {e}")))?;
                Ok(sig.to_der().to_vec())
            }
            FileKey::EcP384(sk) => {
                use signature::{SignatureEncoding, Signer};
                let sig: p384::ecdsa::Signature = sk
                    .try_sign(message)
                    .map_err(|e| crate::error::Error::Internal(format!("ECDSA sign: {e}")))?;
                Ok(sig.to_der().to_vec())
            }
            FileKey::Rsa(key) => match self.algorithm {
                crate::crypto::SignatureAlgorithm::RsaPkcs1Sha256 => {
                    sign_rsa::<sha2::Sha256>(key, message)
                }
                crate::crypto::SignatureAlgorithm::RsaPkcs1Sha384 => {
                    sign_rsa::<sha2::Sha384>(key, message)
                }
                crate::crypto::SignatureAlgorithm::RsaPkcs1Sha512 => {
                    sign_rsa::<sha2::Sha512>(key, message)
                }
                other => Err(crate::error::Error::Internal(format!(
                    "RSA key cannot sign with {other:?}"
                ))),
            },
        }
    }
}
