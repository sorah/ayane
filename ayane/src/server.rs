//! Process entry points: serve the [`router`](crate::http::router) either as a
//! standalone tokio HTTP server or behind AWS Lambda Function URLs.
//!
//! The mode is chosen at runtime by the presence of `AWS_LAMBDA_RUNTIME_API`,
//! which the Lambda execution environment always sets, so the same binary works
//! in both deployments.

/// Run the server, auto-selecting standalone vs. Lambda mode.
pub async fn run(state: crate::http::AppState, listen: &str) -> crate::error::Result<()> {
    let app = crate::http::router(state);

    if std::env::var_os("AWS_LAMBDA_RUNTIME_API").is_some() {
        // Function URLs have no stage prefix; strip it defensively for API GW too.
        // Safe: this runs once at startup, before `lambda_http::run` spawns any
        // worker threads, so no other thread can be reading the environment.
        unsafe {
            std::env::set_var("AWS_LAMBDA_HTTP_IGNORE_STAGE_IN_PATH", "true");
        }
        lambda_http::run(app)
            .await
            .map_err(|e| crate::error::Error::Internal(format!("lambda runtime error: {e}")))
    } else {
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .map_err(|e| crate::error::Error::Config(format!("bind {listen}: {e}")))?;
        tracing::info!(listen = %listen, "ayane server listening");
        axum::serve(listener, app)
            .await
            .map_err(|e| crate::error::Error::Internal(format!("server error: {e}")))
    }
}
