//! RFC 7807 `application/problem+json` error body.

/// Machine-readable error response returned for non-2xx outcomes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProblemDetails {
    /// URI reference identifying the problem type; `about:blank` when unspecified.
    #[serde(rename = "type", default = "ProblemDetails::default_type")]
    pub kind: String,
    /// Short, human-readable summary of the problem type.
    pub title: String,
    /// HTTP status code, duplicated into the body for convenience.
    pub status: u16,
    /// Human-readable explanation specific to this occurrence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// URI reference identifying the specific occurrence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

impl ProblemDetails {
    fn default_type() -> String {
        "about:blank".to_string()
    }

    /// Construct a problem with the given status, title and detail.
    pub fn new(status: u16, title: impl Into<String>, detail: impl Into<String>) -> Self {
        ProblemDetails {
            kind: Self::default_type(),
            title: title.into(),
            status,
            detail: Some(detail.into()),
            instance: None,
        }
    }
}
