//! `rekey`: rekey an existing certificate (new key), authenticated with DPoP.

#[derive(clap::Args)]
pub struct RekeyArgs {
    #[command(flatten)]
    conn: crate::cmd::UrlArgs,
    /// Existing certificate PEM.
    #[arg(long)]
    cert: std::path::PathBuf,
    /// Existing private key PEM (proves possession via DPoP).
    #[arg(long)]
    key: std::path::PathBuf,
    /// New key type.
    #[arg(long, default_value = "ec256")]
    kty: String,
    /// Where to write the new private key.
    #[arg(long)]
    key_out: std::path::PathBuf,
    /// Where to write the rekeyed certificate.
    #[arg(long)]
    out: std::path::PathBuf,
}

pub async fn run(args: RekeyArgs) -> anyhow::Result<()> {
    let cert_pem = std::fs::read_to_string(&args.cert)?;
    let old_key = crate::keypair::KeyPair::from_pem(&std::fs::read_to_string(&args.key)?)?;
    let new_key = crate::keypair::KeyPair::generate(&args.kty)?;

    // Reuse the existing subject for the new CSR.
    let (subject, sans) = subject_and_sans_from_cert(&cert_pem)?;
    let csr = crate::csrgen::build_csr(&new_key, &subject, &sans)?;

    let client = crate::cmd::http_client(&args.conn)?;
    let url = crate::cmd::endpoint(&args.conn.url, "/v1/rekey");
    let dpop = crate::proof::make_dpop(&old_key, &url)?;
    let request = ayane_protocol::RekeyRequest {
        certificate: cert_pem,
        csr,
    };
    let resp: ayane_protocol::CertificateResponse =
        crate::cmd::post_json(&client, &url, Some(&dpop), &request).await?;
    std::fs::write(&args.key_out, new_key.to_pkcs8_pem()?)?;
    std::fs::write(&args.out, crate::cmd::fullchain(&resp))?;
    eprintln!("rekeyed serial {}", resp.serial_number);
    Ok(())
}

fn subject_and_sans_from_cert(cert_pem: &str) -> anyhow::Result<(String, Vec<String>)> {
    use const_oid::AssociatedOid;
    use der::Decode;
    // Tolerate a fullchain file: parse the first CERTIFICATE block (the leaf).
    let blocks = pem::parse_many(cert_pem.as_bytes())?;
    let leaf = blocks
        .iter()
        .find(|b| b.tag() == "CERTIFICATE")
        .ok_or_else(|| anyhow::anyhow!("no CERTIFICATE block in {}", "certificate file"))?;
    let cert = x509_cert::Certificate::from_der(leaf.contents())?;

    let mut subject = String::new();
    for rdn in cert.tbs_certificate.subject.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid == const_oid::db::rfc4519::CN
                && let Ok(s) = atv.value.decode_as::<der::asn1::Utf8StringRef<'_>>()
            {
                subject = s.as_str().to_string();
            }
        }
    }

    let mut sans = Vec::new();
    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions {
            if ext.extn_id == x509_cert::ext::pkix::SubjectAltName::OID {
                use der::Decode;
                let san =
                    x509_cert::ext::pkix::SubjectAltName::from_der(ext.extn_value.as_bytes())?;
                for gn in san.0.iter() {
                    match gn {
                        x509_cert::ext::pkix::name::GeneralName::DnsName(d) => {
                            sans.push(d.as_str().to_string())
                        }
                        x509_cert::ext::pkix::name::GeneralName::Rfc822Name(m) => {
                            sans.push(m.as_str().to_string())
                        }
                        x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(u) => {
                            sans.push(u.as_str().to_string())
                        }
                        x509_cert::ext::pkix::name::GeneralName::IpAddress(b) => {
                            match b.as_bytes().len() {
                                4 => {
                                    let arr: [u8; 4] = b.as_bytes().try_into().unwrap();
                                    sans.push(std::net::IpAddr::from(arr).to_string());
                                }
                                16 => {
                                    let arr: [u8; 16] = b.as_bytes().try_into().unwrap();
                                    sans.push(std::net::IpAddr::from(arr).to_string());
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    Ok((subject, sans))
}
