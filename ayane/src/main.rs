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
    let config_path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("AYANE_CONFIG").ok())
        .unwrap_or_else(|| "ayane.json".to_string());

    let config = ayane::config::Config::from_path(std::path::Path::new(&config_path))?;
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
