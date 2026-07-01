//! The `ayane-server` binary: load configuration and serve the CA.

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    if let Err(e) = run().await {
        tracing::error!(error = %e, "fatal");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

async fn run() -> ayane::error::Result<()> {
    let config = load_config().await?;
    let listen = config.server.listen.clone();
    let external_url = config.server.external_url.clone();
    let tls = config.server.tls.clone();

    if external_url.is_none() {
        tracing::warn!(
            "server.external_url is not set; token audiences and DPoP htu will be derived from \
             request Host/X-Forwarded headers. Set external_url to a trusted public base URL for \
             any deployment reachable through an untrusted proxy."
        );
    }

    let service = ayane::builder::build_service(&config).await?;
    let state = ayane::http::AppState {
        service: std::sync::Arc::new(service),
        external_url,
    };

    ayane::server::run(state, &listen, &tls).await
}

/// Resolve the configuration, in order of precedence:
///
/// 1. A file path given as the first command-line argument.
/// 2. `AYANE_BOOTSTRAP_STORAGE_CONFIG` (+ `AYANE_CONFIG_SHA256`): load the
///    document from a storage backend. The variable carries the bootstrap
///    [`ayane::config::StorageConfig`] as base64url (no padding) JSON, and the
///    SHA-256 digest both locates and authenticates the stored document. For
///    deployments where the configuration is too large or sensitive to pass
///    inline. See [`ayane::bootstrap`].
/// 3. `AYANE_CONFIG_BASE64URL`: the whole document as base64url (no padding)
///    encoded JSON, carried inline in an environment variable. Useful for AWS
///    Lambda, where there is no convenient sidecar file.
/// 4. `AYANE_CONFIG`: a file path.
/// 5. The default `ayane.json` in the working directory.
async fn load_config() -> ayane::error::Result<ayane::config::Config> {
    if let Some(arg) = std::env::args().nth(1) {
        return ayane::config::Config::from_path(std::path::Path::new(&arg));
    }
    if let Some(storage) = env_nonempty("AYANE_BOOTSTRAP_STORAGE_CONFIG") {
        let digest = env_nonempty("AYANE_CONFIG_SHA256").ok_or_else(|| {
            ayane::error::Error::Config(
                "AYANE_BOOTSTRAP_STORAGE_CONFIG is set but AYANE_CONFIG_SHA256 is not; the \
                 SHA-256 digest is required to locate and verify the stored configuration"
                    .into(),
            )
        })?;
        return ayane::bootstrap::load_config_from_storage(&storage, &digest).await;
    }
    if let Some(encoded) = env_nonempty("AYANE_CONFIG_BASE64URL") {
        return ayane::config::Config::from_base64url(&encoded);
    }
    let path = std::env::var("AYANE_CONFIG").unwrap_or_else(|_| "ayane.json".to_string());
    ayane::config::Config::from_path(std::path::Path::new(&path))
}

/// A non-empty environment variable, or `None` when unset or empty.
fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}
