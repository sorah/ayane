//! The `ayane-csr` binary: build a PKCS#10 CSR from a signing key.
//!
//! Reads an [`ayane::config::KeyConfig`] — the same `ca.key` schema the server
//! uses — and emits a `CERTIFICATE REQUEST` PEM on stdout, signed by that key.
//! Because signing goes through the [`ayane::key_provider::KeyProvider`]
//! abstraction, it works against a KMS-resident key without exposing the private
//! key bytes, e.g. to get the CA's own key cross-signed or certified by a parent.
//!
//! Usage: `ayane-csr <key-config> [--cn NAME] [SAN ...]`, where `<key-config>`
//! is inline JSON (anything starting with `{`) or a path to a JSON file, and
//! each `SAN` is classified the way `step` does (IP / URI / email / DNS).

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(pem) => {
            print!("{pem}");
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> ayane::error::Result<String> {
    let mut args = std::env::args().skip(1);
    let key_arg = args.next().ok_or_else(|| {
        ayane::error::Error::Config("usage: ayane-csr <key-config> [--cn NAME] [SAN ...]".into())
    })?;

    let mut common_name = String::new();
    let mut sans: Vec<ayane::san::San> = Vec::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--cn" => {
                common_name = args
                    .next()
                    .ok_or_else(|| ayane::error::Error::Config("--cn requires a value".into()))?;
            }
            other => sans.push(ayane::san::San::parse(other)),
        }
    }

    // The argument is inline JSON when it looks like an object, else a file path.
    let key_json = if key_arg.trim_start().starts_with('{') {
        key_arg
    } else {
        std::fs::read_to_string(&key_arg)
            .map_err(|e| ayane::error::Error::Config(format!("read key config {key_arg}: {e}")))?
    };
    let key_config: ayane::config::KeyConfig = serde_json::from_str(&key_json)
        .map_err(|e| ayane::error::Error::Config(format!("invalid key config: {e}")))?;
    let key = ayane::key_provider::from_config(&key_config).await?;

    build_csr_pem(key.as_ref(), &common_name, &sans).await
}

/// Assemble a `CertReqInfo` carrying the key's public key and the requested
/// subject/SANs, sign its DER with the key provider, and PEM-encode the result.
async fn build_csr_pem(
    key: &dyn ayane::key_provider::KeyProvider,
    common_name: &str,
    sans: &[ayane::san::San],
) -> ayane::error::Result<String> {
    let public_key = {
        use der::Decode;
        spki::SubjectPublicKeyInfoOwned::from_der(key.public_key_der())
            .map_err(|e| ayane::error::Error::Internal(format!("decode key SPKI: {e}")))?
    };

    let mut attributes = der::asn1::SetOfVec::new();
    if !sans.is_empty() {
        let gns = sans
            .iter()
            .map(x509_cert::ext::pkix::name::GeneralName::try_from)
            .collect::<ayane::error::Result<Vec<_>>>()?;
        let san_ext = ayane::x509::extension(&x509_cert::ext::pkix::SubjectAltName(gns), false)?;
        let attr = x509_cert::attr::Attribute::try_from(x509_cert::request::ExtensionReq(vec![
            san_ext,
        ]))
        .map_err(|e| ayane::error::Error::Internal(format!("encode extensionRequest: {e}")))?;
        attributes
            .insert(attr)
            .map_err(|e| ayane::error::Error::Internal(format!("CSR attributes: {e}")))?;
    }

    let info = x509_cert::request::CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject: ayane::x509::name_with_common_name(common_name)?,
        public_key,
        attributes,
    };

    let info_der = {
        use der::Encode;
        info.to_der()
            .map_err(|e| ayane::error::Error::Internal(format!("encode CertReqInfo: {e}")))?
    };
    let sig = key.sign(&info_der).await?;
    let signature = der::asn1::BitString::from_bytes(&sig)
        .map_err(|e| ayane::error::Error::Internal(format!("signature bitstring: {e}")))?;

    let req = x509_cert::request::CertReq {
        info,
        algorithm: key.algorithm().algorithm_identifier()?,
        signature,
    };

    use der::EncodePem;
    req.to_pem(der::pem::LineEnding::LF)
        .map_err(|e| ayane::error::Error::Internal(format!("CSR PEM: {e}")))
}
