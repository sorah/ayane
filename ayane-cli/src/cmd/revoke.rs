//! `revoke`: revoke a certificate by serial number.

#[derive(clap::Args)]
pub struct RevokeArgs {
    #[command(flatten)]
    conn: crate::cmd::UrlArgs,
    /// Serial number (decimal or 0x-hex).
    #[arg(long)]
    serial: String,
    /// Human-readable reason.
    #[arg(long)]
    reason: Option<String>,
    /// RFC 5280 reason code.
    #[arg(long)]
    reason_code: Option<i32>,
    /// Revocation token (provisioner-authorized).
    #[arg(long)]
    token: Option<String>,
    /// Certificate PEM, for DPoP self-revocation.
    #[arg(long)]
    cert: Option<std::path::PathBuf>,
    /// Private key PEM, for DPoP self-revocation.
    #[arg(long)]
    key: Option<std::path::PathBuf>,
}

pub async fn run(args: RevokeArgs) -> anyhow::Result<()> {
    let client = crate::cmd::http_client(&args.conn)?;
    let url = crate::cmd::endpoint(&args.conn.url, "/v1/revoke");

    let (certificate, dpop) = match (&args.cert, &args.key) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = std::fs::read_to_string(cert_path)?;
            let key = crate::keypair::KeyPair::from_pem(&std::fs::read_to_string(key_path)?)?;
            let dpop = crate::proof::make_dpop(&key, &url)?;
            (Some(cert_pem), Some(dpop))
        }
        (None, None) => (None, None),
        _ => anyhow::bail!("--cert and --key must be provided together"),
    };
    if args.token.is_none() && dpop.is_none() {
        anyhow::bail!("provide --token, or --cert and --key for DPoP self-revocation");
    }

    let request = ayane_protocol::RevokeRequest {
        serial_number: args.serial,
        reason: args.reason,
        reason_code: args.reason_code,
        token: args.token,
        certificate,
    };
    let resp: ayane_protocol::RevokeResponse =
        crate::cmd::post_json(&client, &url, dpop.as_deref(), &request).await?;
    eprintln!("revocation status: {}", resp.status);
    Ok(())
}
