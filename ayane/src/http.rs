//! The axum HTTP layer: a thin adapter from requests to [`crate::service`].
//!
//! The same [`router`] is served standalone (tokio) and behind AWS Lambda
//! Function URLs (see [`crate::server`]). Request metadata (the effective URL,
//! a correlation id, the DPoP proof) and typed bodies are pulled in through the
//! custom extractors below, and errors become RFC 7807
//! `application/problem+json` responses.

/// Shared handler state.
#[derive(Clone)]
pub struct AppState {
    /// The certificate service.
    pub service: std::sync::Arc<crate::service::Service>,
    /// Public base URL, used to compute token audiences and DPoP `htu`. When
    /// unset, the request scheme/host headers are used instead.
    pub external_url: Option<String>,
}

/// Build the application router.
pub fn router(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/v1/health", axum::routing::get(health))
        .route("/v1/roots", axum::routing::get(roots))
        .route("/v1/provisioners", axum::routing::get(provisioners))
        .route("/v1/sign", axum::routing::post(sign))
        .route("/v1/renew", axum::routing::post(renew))
        .route("/v1/rekey", axum::routing::post(rekey))
        .route("/v1/revoke", axum::routing::post(revoke))
        .with_state(state)
}

/// Wrapper turning a [`crate::error::Error`] into a problem+json response.
pub struct ApiError(crate::error::Error);

impl From<crate::error::Error> for ApiError {
    fn from(e: crate::error::Error) -> Self {
        ApiError(e)
    }
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = axum::http::StatusCode::from_u16(self.0.status().as_u16())
            .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        if matches!(
            self.0,
            crate::error::Error::Internal(_) | crate::error::Error::Config(_)
        ) {
            tracing::error!(error = %self.0, "request failed");
        }
        let mut response = (status, axum::Json(self.0.to_problem())).into_response();
        response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}

fn header<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// The effective request URL, used to bind token audiences and DPoP `htu`.
///
/// Derived from the configured `external_url` when set, otherwise reconstructed
/// from the request's forwarded scheme/host headers.
pub struct RequestUrl(pub String);

impl axum::extract::FromRequestParts<AppState> for RequestUrl {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let path = parts.uri.path();
        let url = if let Some(base) = &state.external_url {
            format!("{}{}", base.trim_end_matches('/'), path)
        } else {
            let scheme = header(&parts.headers, "x-forwarded-proto").unwrap_or("https");
            let host = header(&parts.headers, "x-forwarded-host")
                .or_else(|| header(&parts.headers, "host"))
                .unwrap_or("localhost");
            format!("{scheme}://{host}{path}")
        };
        Ok(RequestUrl(url))
    }
}

/// A correlation id taken from `X-Request-Id`, or a fresh random one.
pub struct RequestId(pub String);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for RequestId {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let id = header(&parts.headers, "x-request-id")
            .map(str::to_string)
            .unwrap_or_else(|| {
                use rand::RngCore;
                let mut bytes = [0u8; 16];
                rand::rngs::OsRng.fill_bytes(&mut bytes);
                hex::encode(bytes)
            });
        Ok(RequestId(id))
    }
}

/// The optional DPoP proof header.
pub struct Dpop(pub Option<String>);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for Dpop {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Dpop(
            header(&parts.headers, ayane_protocol::DPOP_HEADER).map(str::to_string),
        ))
    }
}

/// A JSON body deserialized into `T`, reporting failures as problem+json.
pub struct ApiJson<T>(pub T);

impl<T, S> axum::extract::FromRequest<S> for ApiJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = axum::body::Bytes::from_request(req, state)
            .await
            .map_err(|e| {
                ApiError(crate::error::Error::BadRequest(format!(
                    "read request body: {e}"
                )))
            })?;
        let value = serde_json::from_slice(&bytes).map_err(|e| {
            ApiError(crate::error::Error::BadRequest(format!(
                "invalid JSON body: {e}"
            )))
        })?;
        Ok(ApiJson(value))
    }
}

async fn health(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> axum::Json<ayane_protocol::HealthResponse> {
    axum::Json(state.service.health())
}

async fn roots(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> axum::Json<ayane_protocol::RootsResponse> {
    axum::Json(state.service.roots())
}

async fn provisioners(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> axum::Json<ayane_protocol::ProvisionersResponse> {
    axum::Json(state.service.provisioners())
}

async fn sign(
    axum::extract::State(state): axum::extract::State<AppState>,
    RequestUrl(url): RequestUrl,
    RequestId(request_id): RequestId,
    ApiJson(req): ApiJson<ayane_protocol::SignRequest>,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse;
    let resp = state.service.sign(req, &url, Some(request_id)).await?;
    Ok((axum::http::StatusCode::CREATED, axum::Json(resp)).into_response())
}

async fn renew(
    axum::extract::State(state): axum::extract::State<AppState>,
    RequestUrl(url): RequestUrl,
    RequestId(request_id): RequestId,
    Dpop(dpop): Dpop,
    ApiJson(req): ApiJson<ayane_protocol::RenewRequest>,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse;
    let resp = state
        .service
        .renew(req, dpop.as_deref(), &url, Some(request_id))
        .await?;
    Ok((axum::http::StatusCode::CREATED, axum::Json(resp)).into_response())
}

async fn rekey(
    axum::extract::State(state): axum::extract::State<AppState>,
    RequestUrl(url): RequestUrl,
    RequestId(request_id): RequestId,
    Dpop(dpop): Dpop,
    ApiJson(req): ApiJson<ayane_protocol::RekeyRequest>,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse;
    let resp = state
        .service
        .rekey(req, dpop.as_deref(), &url, Some(request_id))
        .await?;
    Ok((axum::http::StatusCode::CREATED, axum::Json(resp)).into_response())
}

async fn revoke(
    axum::extract::State(state): axum::extract::State<AppState>,
    RequestUrl(url): RequestUrl,
    RequestId(request_id): RequestId,
    Dpop(dpop): Dpop,
    ApiJson(req): ApiJson<ayane_protocol::RevokeRequest>,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse;
    let resp = state
        .service
        .revoke(req, dpop.as_deref(), &url, Some(request_id))
        .await?;
    Ok((axum::http::StatusCode::OK, axum::Json(resp)).into_response())
}
