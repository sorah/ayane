//! `token`: mint an issuance token (OTT) signed by a provisioner key.

#[derive(clap::Args)]
pub struct TokenArgs {
    /// Provisioner private key PEM.
    #[arg(long)]
    key: std::path::PathBuf,
    /// Provisioner name (token `iss`).
    #[arg(long)]
    issuer: String,
    /// CA base URL (used to derive the audience if `--audience` is absent).
    #[arg(long)]
    url: Option<String>,
    /// Explicit token audience (overrides --url/--operation derivation).
    #[arg(long)]
    audience: Option<String>,
    /// Operation the token authorizes: `sign` (default) or `revoke`. For
    /// `revoke`, set --subject to the certificate serial number.
    #[arg(long, default_value = "sign")]
    operation: String,
    /// Certificate subject / common name (or, for `revoke`, the serial number).
    #[arg(long)]
    subject: String,
    /// Permitted SANs (repeatable).
    #[arg(long = "san")]
    sans: Vec<String>,
    /// Token lifetime, e.g. `5m`.
    #[arg(long, default_value = "5m")]
    validity: String,
}

pub fn run(args: TokenArgs) -> anyhow::Result<()> {
    let key = crate::keypair::KeyPair::from_pem(&std::fs::read_to_string(&args.key)?)?;
    let audience = match (args.audience, args.url) {
        (Some(a), _) => a,
        (None, Some(url)) => format!("{}/v1/{}", url.trim_end_matches('/'), args.operation),
        (None, None) => anyhow::bail!("provide --audience or --url"),
    };
    let validity = parse_duration_secs(&args.validity)?;
    let token = crate::proof::make_ott(
        &key,
        &args.issuer,
        &audience,
        &args.subject,
        &args.sans,
        validity,
    )?;
    println!("{token}");
    Ok(())
}

fn parse_duration_secs(s: &str) -> anyhow::Result<i64> {
    let split = s
        .find(|c: char| c.is_ascii_alphabetic())
        .ok_or_else(|| anyhow::anyhow!("duration {s:?} missing unit"))?;
    let (num, unit) = s.split_at(split);
    let value: i64 = num.parse()?;
    let secs = match unit {
        "s" => value,
        "m" => value * 60,
        "h" => value * 3600,
        "d" => value * 86_400,
        other => anyhow::bail!("unknown duration unit {other:?}"),
    };
    Ok(secs)
}
