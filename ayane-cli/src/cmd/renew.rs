//! `renew`: renew an existing certificate (same key), authenticated with DPoP.

#[derive(clap::Args)]
pub struct RenewArgs {
    #[command(flatten)]
    conn: crate::cmd::UrlArgs,
    /// Existing certificate PEM.
    #[arg(long)]
    cert: std::path::PathBuf,
    /// Existing private key PEM.
    #[arg(long)]
    key: std::path::PathBuf,
    /// Where to write the renewed certificate.
    #[arg(long)]
    out: std::path::PathBuf,
}

pub async fn run(args: RenewArgs) -> anyhow::Result<()> {
    let cert_pem = std::fs::read_to_string(&args.cert)?;
    let key = crate::keypair::KeyPair::from_pem(&std::fs::read_to_string(&args.key)?)?;
    let client = crate::cmd::http_client(&args.conn)?;
    let url = crate::cmd::endpoint(&args.conn.url, "/v1/renew");
    let dpop = crate::proof::make_dpop(&key, &url)?;

    let request = ayane_protocol::RenewRequest {
        certificate: cert_pem,
    };
    let resp: ayane_protocol::CertificateResponse =
        crate::cmd::post_json(&client, &url, Some(&dpop), &request).await?;
    std::fs::write(&args.out, crate::cmd::fullchain(&resp))?;
    eprintln!("renewed serial {}", resp.serial_number);
    Ok(())
}
