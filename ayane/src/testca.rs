//! Test-only helper that mints an ephemeral self-signed CA.
//!
//! Used by unit and integration tests so they never need real key material or
//! AWS. Not compiled into release builds.

/// An ephemeral self-signed CA: its signing key and issuing certificate.
pub struct TestCa {
    /// The CA signing key (a local file-backed provider).
    pub key: std::sync::Arc<crate::key_provider::file::FileKeyProvider>,
    /// PKCS#8 PEM of the CA private key (for tests that need to act as the CA).
    pub key_pem: String,
    /// PEM of the self-signed CA certificate.
    pub ca_cert_pem: String,
    /// The parsed CA certificate.
    pub ca_cert: x509_cert::Certificate,
}

/// Generate an EC P-256 self-signed CA.
pub async fn ec_p256() -> TestCa {
    use der::Decode;
    use p256::pkcs8::EncodePrivateKey;
    use spki::EncodePublicKey;

    let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let key_pem = secret
        .to_pkcs8_pem(der::pem::LineEnding::LF)
        .unwrap()
        .to_string();
    let key = crate::key_provider::file::FileKeyProvider::from_pem(&key_pem, None).unwrap();

    let spki = spki::SubjectPublicKeyInfoOwned::from_der(
        secret.public_key().to_public_key_der().unwrap().as_bytes(),
    )
    .unwrap();
    let ca_key_id = crate::crypto::key_identifier(&spki);
    let name = crate::x509::name_with_common_name("ayane-test-ca").unwrap();

    let now = std::time::SystemTime::now();
    let validity = crate::x509::validity(
        now - std::time::Duration::from_secs(3600),
        now + std::time::Duration::from_secs(3650 * 86_400),
    )
    .unwrap();

    let key_usage = x509_cert::ext::pkix::KeyUsage(
        x509_cert::ext::pkix::KeyUsages::KeyCertSign
            | x509_cert::ext::pkix::KeyUsages::CRLSign
            | x509_cert::ext::pkix::KeyUsages::DigitalSignature,
    );
    let extensions = vec![
        crate::x509::extension(
            &x509_cert::ext::pkix::BasicConstraints {
                ca: true,
                path_len_constraint: Some(0),
            },
            true,
        )
        .unwrap(),
        crate::x509::extension(&key_usage, true).unwrap(),
        crate::x509::extension(
            &x509_cert::ext::pkix::SubjectKeyIdentifier(
                der::asn1::OctetString::new(ca_key_id.clone()).unwrap(),
            ),
            false,
        )
        .unwrap(),
        crate::x509::extension(
            &x509_cert::ext::pkix::AuthorityKeyIdentifier {
                key_identifier: Some(der::asn1::OctetString::new(ca_key_id.clone()).unwrap()),
                authority_cert_issuer: None,
                authority_cert_serial_number: None,
            },
            false,
        )
        .unwrap(),
    ];

    let tbs = crate::x509::build_tbs(crate::x509::TbsParams {
        serial_number: crate::x509::random_serial_number().unwrap(),
        signature_algorithm: crate::key_provider::KeyProvider::algorithm(&key),
        issuer: name.clone(),
        validity,
        subject: name,
        subject_public_key_info: spki,
        extensions,
    })
    .unwrap();

    let ca_cert = crate::x509::sign_tbs(tbs, &key).await.unwrap();
    let ca_cert_pem = crate::x509::certificate_pem(&ca_cert).unwrap();

    TestCa {
        key: std::sync::Arc::new(key),
        key_pem,
        ca_cert_pem,
        ca_cert,
    }
}
