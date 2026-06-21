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

/// Atomically replace `path` with `contents`: write a sibling temp file, then
/// rename over the target so a concurrent reader never sees a truncated file.
/// When `path` already exists, its Unix permission bits are preserved;
/// otherwise the file is created `0644`.
pub(crate) fn write_atomic(path: &std::path::Path, contents: &[u8]) -> anyhow::Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(
            || std::path::PathBuf::from("."),
            std::path::Path::to_path_buf,
        );
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("invalid output path {path:?}"))?
        .to_string_lossy();
    let tmp = dir.join(format!(".{file_name}.tmp.{}", random_suffix()));

    let mode = std::fs::metadata(path).ok().map(|m| {
        use std::os::unix::fs::PermissionsExt;
        m.permissions().mode()
    });
    std::fs::write(&tmp, contents)?;
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode.unwrap_or(0o644));
        if let Err(e) = std::fs::set_permissions(&tmp, perms) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

fn random_suffix() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
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
        // The root bundle may carry more than one certificate — e.g. an old and
        // a new root trusted together during a root rotation — so trust every
        // certificate in it, not just the first.
        let pem = std::fs::read(root)?;
        for cert in reqwest::Certificate::from_pem_bundle(&pem)? {
            builder = builder.add_root_certificate(cert);
        }
    }
    if args.insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    Ok(builder.build()?)
}

/// A failed request, classified so callers (notably the renewal loop) can tell
/// retryable conditions from terminal ones.
#[derive(Debug)]
pub(crate) enum RequestError {
    /// Transport-level failure (connect, timeout, read) — retryable.
    Transport(reqwest::Error),
    /// The CA returned a non-success HTTP status with a (best-effort) message.
    Status {
        status: reqwest::StatusCode,
        message: String,
    },
    /// A success response body that could not be decoded — a protocol mismatch.
    Decode(serde_json::Error),
}

impl RequestError {
    /// Whether retrying the same request might succeed: transport errors,
    /// `5xx`, and `429`. A `4xx` (other than `429`) or a decode failure is
    /// terminal.
    pub(crate) fn is_transient(&self) -> bool {
        match self {
            RequestError::Transport(_) => true,
            RequestError::Decode(_) => false,
            RequestError::Status { status, .. } => {
                status.is_server_error() || *status == reqwest::StatusCode::TOO_MANY_REQUESTS
            }
        }
    }
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestError::Transport(e) => write!(f, "request failed: {e}"),
            RequestError::Status { status, message } => {
                write!(f, "CA returned {status}: {message}")
            }
            RequestError::Decode(e) => write!(f, "could not decode CA response: {e}"),
        }
    }
}

impl std::error::Error for RequestError {}

pub(crate) async fn post_json<B: serde::Serialize, R: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    dpop: Option<&str>,
    body: &B,
) -> anyhow::Result<R> {
    Ok(post_json_typed(client, url, dpop, body).await?)
}

pub(crate) async fn post_json_typed<B: serde::Serialize, R: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    dpop: Option<&str>,
    body: &B,
) -> Result<R, RequestError> {
    let mut req = client.post(url).json(body);
    if let Some(dpop) = dpop {
        req = req.header(ayane_protocol::DPOP_HEADER, dpop);
    }
    let resp = req.send().await.map_err(RequestError::Transport)?;
    deserialize_response_typed(resp).await
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
    Ok(deserialize_response_typed(resp).await?)
}

pub(crate) async fn deserialize_response_typed<R: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<R, RequestError> {
    let status = resp.status();
    let bytes = resp.bytes().await.map_err(RequestError::Transport)?;
    if !status.is_success() {
        let message = serde_json::from_slice::<ayane_protocol::ProblemDetails>(&bytes)
            .ok()
            .map(|problem| problem.detail.unwrap_or(problem.title))
            .unwrap_or_else(|| String::from_utf8_lossy(&bytes).into_owned());
        return Err(RequestError::Status { status, message });
    }
    serde_json::from_slice(&bytes).map_err(RequestError::Decode)
}

#[cfg(test)]
mod tests {
    #[test]
    fn transient_classification() {
        let status = |c: u16| super::RequestError::Status {
            status: reqwest::StatusCode::from_u16(c).unwrap(),
            message: String::new(),
        };
        assert!(status(500).is_transient());
        assert!(status(503).is_transient());
        assert!(status(429).is_transient());
        assert!(!status(401).is_transient());
        assert!(!status(403).is_transient());
        assert!(!status(400).is_transient());
        assert!(
            !super::RequestError::Decode(serde_json::from_str::<u8>("x").unwrap_err())
                .is_transient()
        );
    }

    #[test]
    fn write_atomic_preserves_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("ayane-test-{}", super::random_suffix()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cert.pem");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        super::write_atomic(&path, b"new").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
