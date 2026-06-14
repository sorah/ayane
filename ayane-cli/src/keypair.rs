//! Client-side key pairs: generation, loading, raw signing (for CSRs), and the
//! JWT/JWK glue used to mint issuance tokens and DPoP proofs.

/// A private key the CLI can sign with.
pub enum KeyPair {
    /// NIST P-256 ECDSA.
    EcP256(Box<p256::ecdsa::SigningKey>),
    /// NIST P-384 ECDSA.
    EcP384(Box<p384::ecdsa::SigningKey>),
    /// RSA (PKCS#1 v1.5 with SHA-256).
    Rsa(Box<rsa::RsaPrivateKey>),
}

impl KeyPair {
    /// Generate a fresh key of the named type: `ec256` (default), `ec384`,
    /// `rsa2048`, `rsa3072`, `rsa4096`.
    pub fn generate(kty: &str) -> anyhow::Result<KeyPair> {
        match kty.to_ascii_lowercase().as_str() {
            "ec" | "ec256" | "p256" | "ecdsa-p256" => Ok(KeyPair::EcP256(Box::new(
                p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng),
            ))),
            "ec384" | "p384" | "ecdsa-p384" => Ok(KeyPair::EcP384(Box::new(
                p384::ecdsa::SigningKey::random(&mut rand::rngs::OsRng),
            ))),
            "rsa" | "rsa2048" => Ok(KeyPair::Rsa(Box::new(rsa::RsaPrivateKey::new(
                &mut rand::rngs::OsRng,
                2048,
            )?))),
            "rsa3072" => Ok(KeyPair::Rsa(Box::new(rsa::RsaPrivateKey::new(
                &mut rand::rngs::OsRng,
                3072,
            )?))),
            "rsa4096" => Ok(KeyPair::Rsa(Box::new(rsa::RsaPrivateKey::new(
                &mut rand::rngs::OsRng,
                4096,
            )?))),
            other => anyhow::bail!("unknown key type {other:?}"),
        }
    }

    /// Load a key from PEM (PKCS#8 for EC, PKCS#8 or PKCS#1 for RSA).
    pub fn from_pem(pem: &str) -> anyhow::Result<KeyPair> {
        use pkcs8::DecodePrivateKey;
        if let Ok(k) = p256::SecretKey::from_pkcs8_pem(pem) {
            return Ok(KeyPair::EcP256(Box::new(p256::ecdsa::SigningKey::from(k))));
        }
        if let Ok(k) = p384::SecretKey::from_pkcs8_pem(pem) {
            return Ok(KeyPair::EcP384(Box::new(p384::ecdsa::SigningKey::from(k))));
        }
        if let Ok(k) = rsa::RsaPrivateKey::from_pkcs8_pem(pem) {
            return Ok(KeyPair::Rsa(Box::new(k)));
        }
        use rsa::pkcs1::DecodeRsaPrivateKey;
        if let Ok(k) = rsa::RsaPrivateKey::from_pkcs1_pem(pem) {
            return Ok(KeyPair::Rsa(Box::new(k)));
        }
        anyhow::bail!("unsupported private key PEM")
    }

    /// PKCS#8 PEM encoding of the private key.
    pub fn to_pkcs8_pem(&self) -> anyhow::Result<String> {
        use pkcs8::EncodePrivateKey;
        let pem = match self {
            KeyPair::EcP256(k) => k.to_pkcs8_pem(der::pem::LineEnding::LF)?,
            KeyPair::EcP384(k) => k.to_pkcs8_pem(der::pem::LineEnding::LF)?,
            KeyPair::Rsa(k) => k.to_pkcs8_pem(der::pem::LineEnding::LF)?,
        };
        Ok(pem.to_string())
    }

    /// DER `SubjectPublicKeyInfo` of the public key.
    pub fn public_key_der(&self) -> anyhow::Result<Vec<u8>> {
        use spki::EncodePublicKey;
        let der = match self {
            KeyPair::EcP256(k) => k.verifying_key().to_public_key_der()?,
            KeyPair::EcP384(k) => k.verifying_key().to_public_key_der()?,
            KeyPair::Rsa(k) => rsa::RsaPublicKey::from(k.as_ref()).to_public_key_der()?,
        };
        Ok(der.as_bytes().to_vec())
    }

    /// Sign `message`, returning X.509 signature bytes (DER ECDSA / PKCS#1).
    pub fn sign_der(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        use signature::{SignatureEncoding, Signer};
        match self {
            KeyPair::EcP256(k) => {
                let sig: p256::ecdsa::Signature = k.try_sign(message)?;
                Ok(sig.to_der().to_vec())
            }
            KeyPair::EcP384(k) => {
                let sig: p384::ecdsa::Signature = k.try_sign(message)?;
                Ok(sig.to_der().to_vec())
            }
            KeyPair::Rsa(k) => {
                let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new((**k).clone());
                let sig = signing_key.try_sign(message)?;
                Ok(sig.to_vec())
            }
        }
    }

    /// The X.509 `AlgorithmIdentifier` matching [`sign_der`](Self::sign_der).
    pub fn algorithm_identifier(&self) -> anyhow::Result<spki::AlgorithmIdentifierOwned> {
        let (oid, params) = match self {
            KeyPair::EcP256(_) => (const_oid::db::rfc5912::ECDSA_WITH_SHA_256, None),
            KeyPair::EcP384(_) => (const_oid::db::rfc5912::ECDSA_WITH_SHA_384, None),
            KeyPair::Rsa(_) => (
                const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
                Some(der::Any::from(der::asn1::Null)),
            ),
        };
        Ok(spki::AlgorithmIdentifierOwned {
            oid,
            parameters: params,
        })
    }

    /// The JWT algorithm to sign tokens/proofs with.
    pub fn jwt_algorithm(&self) -> jsonwebtoken::Algorithm {
        match self {
            KeyPair::EcP256(_) => jsonwebtoken::Algorithm::ES256,
            KeyPair::EcP384(_) => jsonwebtoken::Algorithm::ES384,
            KeyPair::Rsa(_) => jsonwebtoken::Algorithm::RS256,
        }
    }

    /// A jsonwebtoken signing key derived from this key.
    pub fn encoding_key(&self) -> anyhow::Result<jsonwebtoken::EncodingKey> {
        let pem = self.to_pkcs8_pem()?;
        let key = match self {
            KeyPair::EcP256(_) | KeyPair::EcP384(_) => {
                jsonwebtoken::EncodingKey::from_ec_pem(pem.as_bytes())?
            }
            KeyPair::Rsa(_) => jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes())?,
        };
        Ok(key)
    }

    /// The public key as a JWK (for DPoP proof headers).
    pub fn public_jwk(&self) -> anyhow::Result<jsonwebtoken::jwk::Jwk> {
        let value = match self {
            KeyPair::EcP256(k) => {
                let point = k.verifying_key().to_encoded_point(false);
                serde_json::json!({
                    "kty": "EC", "crv": "P-256",
                    "x": b64url(point.x().ok_or_else(|| anyhow::anyhow!("no x"))?),
                    "y": b64url(point.y().ok_or_else(|| anyhow::anyhow!("no y"))?),
                })
            }
            KeyPair::EcP384(k) => {
                let point = k.verifying_key().to_encoded_point(false);
                serde_json::json!({
                    "kty": "EC", "crv": "P-384",
                    "x": b64url(point.x().ok_or_else(|| anyhow::anyhow!("no x"))?),
                    "y": b64url(point.y().ok_or_else(|| anyhow::anyhow!("no y"))?),
                })
            }
            KeyPair::Rsa(k) => {
                use rsa::traits::PublicKeyParts;
                let pubkey = rsa::RsaPublicKey::from(k.as_ref());
                serde_json::json!({
                    "kty": "RSA",
                    "n": b64url(&pubkey.n().to_bytes_be()),
                    "e": b64url(&pubkey.e().to_bytes_be()),
                })
            }
        };
        Ok(serde_json::from_value(value)?)
    }
}

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    #[test]
    fn ec_p256_roundtrip_and_sign() {
        let kp = super::KeyPair::generate("ec256").unwrap();
        let pem = kp.to_pkcs8_pem().unwrap();
        let loaded = super::KeyPair::from_pem(&pem).unwrap();
        let sig = loaded.sign_der(b"hello").unwrap();
        assert!(!sig.is_empty());
        assert!(kp.public_key_der().unwrap() == loaded.public_key_der().unwrap());
        let _jwk = kp.public_jwk().unwrap();
        let _ek = kp.encoding_key().unwrap();
    }
}
