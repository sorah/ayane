//! The crate-wide error type and its mapping to HTTP problem responses.

/// Errors produced anywhere in the ayane core.
///
/// Variants are grouped by the HTTP semantics they map to (see
/// [`Error::status`]); the `*Internal*` family is never surfaced to clients with
/// its detail, to avoid leaking implementation specifics.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid or unloadable configuration.
    #[error("configuration error: {0}")]
    Config(String),

    /// The request was malformed (bad CSR, bad JSON, bad serial, ...).
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Authentication failed (bad token signature, expired, replayed, ...).
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// The request was authenticated but not permitted (policy, webhook deny,
    /// SAN not allowed, certificate revoked).
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// The referenced object does not exist.
    #[error("not found: {0}")]
    NotFound(String),

    /// A uniqueness constraint was violated (token/proof replay).
    #[error("conflict: {0}")]
    Conflict(String),

    /// An unexpected internal failure. The detail is logged, not returned.
    #[error("internal error: {0}")]
    Internal(String),
}

impl Error {
    /// HTTP status code for this error.
    pub fn status(&self) -> http::StatusCode {
        match self {
            Error::Config(_) | Error::Internal(_) => http::StatusCode::INTERNAL_SERVER_ERROR,
            Error::BadRequest(_) => http::StatusCode::BAD_REQUEST,
            Error::Unauthorized(_) => http::StatusCode::UNAUTHORIZED,
            Error::Forbidden(_) => http::StatusCode::FORBIDDEN,
            Error::NotFound(_) => http::StatusCode::NOT_FOUND,
            Error::Conflict(_) => http::StatusCode::CONFLICT,
        }
    }

    /// Render an RFC 7807 problem body, suppressing internal detail.
    pub fn to_problem(&self) -> ayane_protocol::ProblemDetails {
        let status = self.status();
        let (title, detail) = match self {
            Error::Config(_) | Error::Internal(_) => ("Internal Server Error".to_string(), None),
            Error::BadRequest(d) => ("Bad Request".to_string(), Some(d.clone())),
            Error::Unauthorized(d) => ("Unauthorized".to_string(), Some(d.clone())),
            Error::Forbidden(d) => ("Forbidden".to_string(), Some(d.clone())),
            Error::NotFound(d) => ("Not Found".to_string(), Some(d.clone())),
            Error::Conflict(d) => ("Conflict".to_string(), Some(d.clone())),
        };
        ayane_protocol::ProblemDetails {
            kind: "about:blank".to_string(),
            title,
            status: status.as_u16(),
            detail,
            instance: None,
        }
    }

    /// Helper to build an [`Error::Internal`] from any displayable error.
    pub fn internal(e: impl std::fmt::Display) -> Self {
        Error::Internal(e.to_string())
    }

    /// Helper to build an [`Error::BadRequest`] from any displayable error.
    pub fn bad_request(e: impl std::fmt::Display) -> Self {
        Error::BadRequest(e.to_string())
    }
}

/// Convenient crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

impl From<der::Error> for Error {
    fn from(e: der::Error) -> Self {
        Error::Internal(format!("der: {e}"))
    }
}

impl From<spki::Error> for Error {
    fn from(e: spki::Error) -> Self {
        Error::Internal(format!("spki: {e}"))
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Internal(format!("json: {e}"))
    }
}
