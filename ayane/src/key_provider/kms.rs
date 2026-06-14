//! A [`KeyProvider`](crate::key_provider::KeyProvider) backed by an AWS KMS
//! asymmetric key.
//!
//! The private key never leaves KMS: the to-be-signed certificate body is
//! hashed locally and the digest is signed with `kms:Sign` in `DIGEST` mode
//! (KMS caps `RAW` messages at 4 KiB, which a TBSCertificate can exceed). The
//! public key is fetched once via `kms:GetPublicKey`, which already returns DER
//! `SubjectPublicKeyInfo`. KMS returns ECDSA signatures in the DER form X.509
//! expects, so no re-encoding is needed.

/// Build a KMS client from the shared AWS configuration, applying an optional
/// region override.
pub(crate) async fn client(region: Option<&str>) -> aws_sdk_kms::Client {
    let mut builder = aws_sdk_kms::config::Builder::from(crate::aws::shared_config().await);
    if let Some(region) = region {
        builder = builder.region(aws_sdk_kms::config::Region::new(region.to_string()));
    }
    aws_sdk_kms::Client::from_conf(builder.build())
}

/// A signing key fronted by AWS KMS.
pub struct KmsKeyProvider {
    client: aws_sdk_kms::Client,
    key_id: String,
    algorithm: crate::crypto::SignatureAlgorithm,
    public_key_der: Vec<u8>,
}

impl KmsKeyProvider {
    /// Construct a provider for `key_id`, fetching its public key up front.
    pub async fn new(
        client: aws_sdk_kms::Client,
        key_id: impl Into<String>,
        algorithm: crate::crypto::SignatureAlgorithm,
    ) -> crate::error::Result<Self> {
        let key_id = key_id.into();
        let resp = client
            .get_public_key()
            .key_id(&key_id)
            .send()
            .await
            .map_err(|e| {
                crate::error::Error::Config(format!(
                    "kms GetPublicKey({key_id}): {}",
                    aws_smithy_types::error::display::DisplayErrorContext(&e)
                ))
            })?;
        let public_key_der = resp
            .public_key()
            .ok_or_else(|| {
                crate::error::Error::Config(format!("kms GetPublicKey({key_id}): no public key"))
            })?
            .as_ref()
            .to_vec();
        Ok(KmsKeyProvider {
            client,
            key_id,
            algorithm,
            public_key_der,
        })
    }

    fn signing_spec(&self) -> aws_sdk_kms::types::SigningAlgorithmSpec {
        match self.algorithm {
            crate::crypto::SignatureAlgorithm::EcdsaSha256 => {
                aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256
            }
            crate::crypto::SignatureAlgorithm::EcdsaSha384 => {
                aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha384
            }
            crate::crypto::SignatureAlgorithm::RsaPkcs1Sha256 => {
                aws_sdk_kms::types::SigningAlgorithmSpec::RsassaPkcs1V15Sha256
            }
            crate::crypto::SignatureAlgorithm::RsaPkcs1Sha384 => {
                aws_sdk_kms::types::SigningAlgorithmSpec::RsassaPkcs1V15Sha384
            }
            crate::crypto::SignatureAlgorithm::RsaPkcs1Sha512 => {
                aws_sdk_kms::types::SigningAlgorithmSpec::RsassaPkcs1V15Sha512
            }
        }
    }
}

#[async_trait::async_trait]
impl crate::key_provider::KeyProvider for KmsKeyProvider {
    fn algorithm(&self) -> crate::crypto::SignatureAlgorithm {
        self.algorithm
    }

    fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }

    async fn sign(&self, message: &[u8]) -> crate::error::Result<Vec<u8>> {
        let digest = self.algorithm.digest(message);
        let resp = self
            .client
            .sign()
            .key_id(&self.key_id)
            .message(aws_smithy_types::Blob::new(digest))
            .message_type(aws_sdk_kms::types::MessageType::Digest)
            .signing_algorithm(self.signing_spec())
            .send()
            .await
            .map_err(|e| {
                crate::error::Error::Internal(format!(
                    "kms Sign({}): {}",
                    self.key_id,
                    aws_smithy_types::error::display::DisplayErrorContext(&e)
                ))
            })?;
        let sig = resp.signature().ok_or_else(|| {
            crate::error::Error::Internal("kms Sign: empty signature".to_string())
        })?;
        Ok(sig.as_ref().to_vec())
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn signs_via_mocked_kms() {
        use crate::key_provider::KeyProvider;

        let get_pub =
            aws_smithy_mocks::mock!(aws_sdk_kms::Client::get_public_key).then_output(|| {
                aws_sdk_kms::operation::get_public_key::GetPublicKeyOutput::builder()
                    .public_key(aws_smithy_types::Blob::new(vec![1, 2, 3]))
                    .build()
            });
        let sign = aws_smithy_mocks::mock!(aws_sdk_kms::Client::sign)
            .match_requests(|req| {
                req.message_type() == Some(&aws_sdk_kms::types::MessageType::Digest)
                    && req.signing_algorithm()
                        == Some(&aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256)
            })
            .then_output(|| {
                aws_sdk_kms::operation::sign::SignOutput::builder()
                    .signature(aws_smithy_types::Blob::new(vec![9, 9, 9, 9]))
                    .build()
            });
        let client = aws_smithy_mocks::mock_client!(
            aws_sdk_kms,
            aws_smithy_mocks::RuleMode::MatchAny,
            [&get_pub, &sign]
        );

        let provider = super::KmsKeyProvider::new(
            client,
            "alias/test",
            crate::crypto::SignatureAlgorithm::EcdsaSha256,
        )
        .await
        .unwrap();
        assert_eq!(provider.public_key_der(), &[1, 2, 3]);
        let sig = provider.sign(b"hello tbs").await.unwrap();
        assert_eq!(sig, vec![9, 9, 9, 9]);
    }
}
