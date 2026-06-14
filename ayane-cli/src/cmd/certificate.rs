//! `certificate`: request a new certificate using an issuance token.

#[derive(clap::Args)]
pub struct CertificateArgs {
    #[command(flatten)]
    conn: crate::cmd::UrlArgs,
    /// Issuance token (OTT), read from the given file, or from stdin when
    /// omitted or `-`. Never accepted as an inline argument value.
    #[arg(long = "token-file")]
    token_file: Option<std::path::PathBuf>,
    /// Subject / common name.
    #[arg(long)]
    subject: String,
    /// SANs to request (repeatable).
    #[arg(long = "san")]
    sans: Vec<String>,
    /// Key type: ec256 (default), ec384, rsa2048, rsa3072, rsa4096.
    #[arg(long, default_value = "ec256")]
    kty: String,
    /// Where to write the private key PEM.
    #[arg(long)]
    key_out: std::path::PathBuf,
    /// Where to write the certificate (leaf + chain) PEM.
    #[arg(long)]
    out: std::path::PathBuf,
    /// Optional RFC 3339 notBefore.
    #[arg(long)]
    not_before: Option<String>,
    /// Optional RFC 3339 notAfter.
    #[arg(long)]
    not_after: Option<String>,
}

pub async fn run(args: CertificateArgs) -> anyhow::Result<()> {
    let token = read_token(args.token_file.as_deref())?;
    let key = crate::keypair::KeyPair::generate(&args.kty)?;
    let csr = crate::csrgen::build_csr(&key, &args.subject, &args.sans)?;

    let request = ayane_protocol::SignRequest {
        csr,
        token,
        not_before: args.not_before,
        not_after: args.not_after,
    };
    let client = crate::cmd::http_client(&args.conn)?;
    let url = crate::cmd::endpoint(&args.conn.url, "/v1/sign");
    let resp: ayane_protocol::CertificateResponse =
        crate::cmd::post_json(&client, &url, None, &request).await?;

    std::fs::write(&args.key_out, key.to_pkcs8_pem()?)?;
    std::fs::write(&args.out, crate::cmd::fullchain(&resp))?;
    eprintln!(
        "issued serial {} (notAfter {})",
        resp.serial_number, resp.not_after
    );
    Ok(())
}

fn read_token(token_file: Option<&std::path::Path>) -> anyhow::Result<String> {
    let raw = match token_file {
        Some(path) if path != std::path::Path::new("-") => std::fs::read_to_string(path)?,
        _ => {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf
        }
    };
    Ok(raw.trim().to_string())
}
