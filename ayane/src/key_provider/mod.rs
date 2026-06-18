//! The signing-key abstraction.
//!
//! A [`KeyProvider`] owns (or fronts) the CA's private key and produces X.509
//! signatures over a to-be-signed certificate body. The actual private key may
//! live in a local file or remotely in AWS KMS; the certificate-building engine
//! only ever sees this trait, so it works identically against either.

pub mod aws_kms;
pub mod file;

/// Build the configured signing key provider.
///
/// File keys are read locally; KMS keys resolve a client from the shared AWS
/// configuration (loaded lazily on first use). This keeps all provider-specific
/// construction inside the provider modules rather than in the service builder.
pub async fn from_config(
    cfg: &crate::config::KeyConfig,
) -> crate::error::Result<std::sync::Arc<dyn KeyProvider>> {
    match cfg {
        crate::config::KeyConfig::File {
            file,
            pem,
            algorithm,
        } => {
            let pem_text = match (pem, file) {
                (Some(pem), _) => pem.clone(),
                (None, Some(path)) => std::fs::read_to_string(path)
                    .map_err(|e| crate::error::Error::Config(format!("read key {path}: {e}")))?,
                (None, None) => {
                    return Err(crate::error::Error::Config(
                        "file key requires `pem` or `file`".into(),
                    ));
                }
            };
            let algorithm = match algorithm {
                Some(a) => Some(crate::crypto::SignatureAlgorithm::parse(a)?),
                None => None,
            };
            Ok(
                std::sync::Arc::new(crate::key_provider::file::FileKeyProvider::from_pem(
                    &pem_text, algorithm,
                )?) as std::sync::Arc<dyn KeyProvider>,
            )
        }
        crate::config::KeyConfig::AwsKms {
            key_id,
            algorithm,
            region,
        } => {
            let algorithm = crate::crypto::SignatureAlgorithm::parse(algorithm)?;
            let client = crate::key_provider::aws_kms::client(region.as_deref()).await;
            Ok(std::sync::Arc::new(
                crate::key_provider::aws_kms::AwsKmsKeyProvider::new(
                    client,
                    key_id.clone(),
                    algorithm,
                )
                .await?,
            ) as std::sync::Arc<dyn KeyProvider>)
        }
    }
}

/// A source of CA signatures.
///
/// Implementations hash the supplied message with the digest implied by
/// [`algorithm`](KeyProvider::algorithm) and return the X.509 signature bytes:
/// a DER-encoded `ECDSA-Sig-Value` for ECDSA, or the PKCS#1 v1.5 octet string
/// for RSA — exactly what is embedded in a certificate's `signatureValue`.
#[async_trait::async_trait]
pub trait KeyProvider: Send + Sync {
    /// The signature algorithm (and therefore digest) this key signs with.
    fn algorithm(&self) -> crate::crypto::SignatureAlgorithm;

    /// The DER `SubjectPublicKeyInfo` of the corresponding public key.
    ///
    /// Used at startup to confirm the configured key matches the CA certificate.
    fn public_key_der(&self) -> &[u8];

    /// Sign `message` (the DER TBSCertificate), returning X.509 signature bytes.
    async fn sign(&self, message: &[u8]) -> crate::error::Result<Vec<u8>>;
}
