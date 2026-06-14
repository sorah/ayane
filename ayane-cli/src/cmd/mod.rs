//! Subcommand implementations and shared helpers for the `ayane` CLI.

pub mod certificate;
pub mod health;
pub mod provisioners;
pub mod rekey;
pub mod renew;
pub mod revoke;
pub mod roots;
pub mod token;

#[derive(clap::Args)]
pub(crate) struct UrlArgs {
    /// CA base URL, e.g. https://ca.example.
    #[arg(long)]
    pub url: String,
    /// Trust this PEM root certificate when connecting.
    #[arg(long)]
    pub root: Option<std::path::PathBuf>,
    /// Skip TLS verification (testing only).
    #[arg(long)]
    pub insecure: bool,
}

pub(crate) async fn simple_get(args: UrlArgs, path: &str) -> anyhow::Result<()> {
    let client = http_client(&args)?;
    let url = endpoint(&args.url, path);
    let resp: serde_json::Value = get_json(&client, &url).await?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}

pub(crate) fn endpoint(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

pub(crate) fn fullchain(resp: &ayane_protocol::CertificateResponse) -> String {
    let mut out = resp.certificate.clone();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    for cert in &resp.chain {
        out.push_str(cert);
        if !cert.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

pub(crate) fn http_client(args: &UrlArgs) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    if let Some(root) = &args.root {
        let pem = std::fs::read(root)?;
        builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&pem)?);
    }
    if args.insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    Ok(builder.build()?)
}

pub(crate) async fn post_json<B: serde::Serialize, R: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    dpop: Option<&str>,
    body: &B,
) -> anyhow::Result<R> {
    let mut req = client.post(url).json(body);
    if let Some(dpop) = dpop {
        req = req.header(ayane_protocol::DPOP_HEADER, dpop);
    }
    let resp = req.send().await?;
    deserialize_response(resp).await
}

pub(crate) async fn get_json<R: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> anyhow::Result<R> {
    let resp = client.get(url).send().await?;
    deserialize_response(resp).await
}

pub(crate) async fn deserialize_response<R: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> anyhow::Result<R> {
    let status = resp.status();
    let bytes = resp.bytes().await?;
    if !status.is_success() {
        if let Ok(problem) = serde_json::from_slice::<ayane_protocol::ProblemDetails>(&bytes) {
            anyhow::bail!(
                "CA returned {}: {}",
                status,
                problem.detail.unwrap_or(problem.title)
            );
        }
        anyhow::bail!(
            "CA returned {}: {}",
            status,
            String::from_utf8_lossy(&bytes)
        );
    }
    Ok(serde_json::from_slice(&bytes)?)
}
