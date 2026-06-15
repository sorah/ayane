//! Process entry points: serve the [`router`](crate::http::router) either as a
//! standalone tokio HTTP(S) server or behind AWS Lambda Function URLs.
//!
//! The mode is chosen at runtime by the presence of `AWS_LAMBDA_RUNTIME_API`,
//! which the Lambda execution environment always sets, so the same binary works
//! in both deployments. Self-issued serving TLS ([`crate::tls`]) applies only to
//! the standalone runtime; under Lambda the Function URL terminates TLS, so the
//! `tls` configuration is ignored there.

/// Run the server, auto-selecting standalone vs. Lambda mode.
pub async fn run(
    state: crate::http::AppState,
    listen: &str,
    tls: &crate::config::TlsConfig,
) -> crate::error::Result<()> {
    let ca = state.service.ca();
    let external_url = state.external_url.clone();
    let app = crate::http::router(state);

    if std::env::var_os("AWS_LAMBDA_RUNTIME_API").is_some() {
        if tls.enabled {
            tracing::debug!(
                "server.tls is ignored under AWS Lambda; TLS is terminated by the Function URL"
            );
        }
        // Function URLs have no stage prefix; strip it defensively for API GW too.
        // Safe: this runs once at startup, before `lambda_http::run` spawns any
        // worker threads, so no other thread can be reading the environment.
        unsafe {
            std::env::set_var("AWS_LAMBDA_HTTP_IGNORE_STAGE_IN_PATH", "true");
        }
        return lambda_http::run(app)
            .await
            .map_err(|e| crate::error::Error::Internal(format!("lambda runtime error: {e}")));
    }

    if tls.enabled {
        serve_tls(app, listen, tls, ca, external_url.as_deref()).await
    } else {
        serve_plain(app, listen).await
    }
}

/// Serve plaintext HTTP (TLS terminated by a fronting proxy).
async fn serve_plain(app: axum::Router, listen: &str) -> crate::error::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| crate::error::Error::Config(format!("bind {listen}: {e}")))?;
    tracing::info!(listen = %listen, "ayane server listening (HTTP)");
    axum::serve(listener, app)
        .await
        .map_err(|e| crate::error::Error::Internal(format!("server error: {e}")))
}

/// Serve HTTPS with a self-issued, auto-renewing serving certificate.
async fn serve_tls(
    app: axum::Router,
    listen: &str,
    tls: &crate::config::TlsConfig,
    ca: std::sync::Arc<crate::ca::CertificateAuthority>,
    external_url: Option<&str>,
) -> crate::error::Result<()> {
    let issuer = std::sync::Arc::new(crate::tls::SelfIssuer::new(ca, tls, external_url)?);
    let serving = issuer.issue_serving().await?;
    let not_after = serving.not_after;
    let resolver = crate::tls::SwappableResolver::new(serving.certified_key);
    tokio::spawn(crate::tls::run_renewer(
        std::sync::Arc::clone(&issuer),
        std::sync::Arc::clone(&resolver),
        not_after,
    ));
    let server_config = crate::tls::build_server_tls_config(resolver)?;

    let addr = resolve_listen_addr(listen)?;
    tracing::info!(
        listen = %listen,
        sans = ?issuer.sans(),
        "ayane server listening (HTTPS, self-issued)"
    );
    axum_server::bind_rustls(
        addr,
        axum_server::tls_rustls::RustlsConfig::from_config(server_config),
    )
    .serve(app.into_make_service())
    .await
    .map_err(|e| crate::error::Error::Internal(format!("server error: {e}")))
}

/// Resolve the listen string (e.g. `0.0.0.0:9443`) to a single socket address.
fn resolve_listen_addr(listen: &str) -> crate::error::Result<std::net::SocketAddr> {
    std::net::ToSocketAddrs::to_socket_addrs(listen)
        .map_err(|e| crate::error::Error::Config(format!("bind {listen}: {e}")))?
        .next()
        .ok_or_else(|| crate::error::Error::Config(format!("bind {listen}: no address resolved")))
}
