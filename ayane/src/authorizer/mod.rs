//! Token authorization: validates the externally-provided JWT that authorizes
//! an issuance or revocation.
//!
//! The authorizer is intentionally storage-free: it proves a token is
//! authentic and well-formed and returns its claims. One-time (anti-replay)
//! enforcement of the `jti` is performed by [`crate::service`] against
//! [`crate::storage`], using the [`jti`](ayane_protocol::OttClaims::jti) this
//! returns.

pub mod jwt;

/// A token that has passed signature and registered-claim validation.
pub struct ValidatedToken {
    /// The provisioner that issued (and verified) the token.
    pub provisioner: String,
    /// The decoded claims.
    pub claims: ayane_protocol::OttClaims,
    /// Template name override carried by the provisioner, if any.
    pub template: Option<String>,
    /// Whether the provisioner authorizes issuance on its own. When `false`, an
    /// authorize webhook must explicitly grant the request.
    pub authorized: bool,
    /// Anti-replay identifier: the token's `jti` when present, otherwise a value
    /// derived from the token so one-time enforcement still applies.
    pub replay_id: String,
}

/// Validates issuance/revocation tokens.
#[async_trait::async_trait]
pub trait Authorizer: Send + Sync {
    /// Validate `token`, requiring its `aud` claim to match `audience` (one of
    /// the server's accepted audiences for the operation). Returns the decoded,
    /// verified claims. Does **not** enforce one-time use.
    async fn validate(&self, token: &str, audience: &str) -> crate::error::Result<ValidatedToken>;

    /// Public, non-secret description of configured provisioners.
    fn provisioners(&self) -> Vec<ayane_protocol::ProvisionerInfo>;
}
