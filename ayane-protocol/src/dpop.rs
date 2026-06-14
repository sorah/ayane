//! RFC 9449 DPoP proof claims, used to prove possession of an existing
//! certificate's private key during renewal, rekeying and self-revocation.
//!
//! The proof JWT is signed by the certificate's private key, with JOSE header
//! `typ` of `dpop+jwt` and an `alg` matching the certificate key. The server
//! verifies the proof's signature directly against the presented certificate's
//! public key (so a valid signature is itself the proof of possession), then
//! validates these claims. Per RFC 9449 the header also carries the public key
//! as a `jwk`, but the server does not rely on it.
pub use crate::token::Confirmation;

/// JOSE `typ` value required on a DPoP proof.
pub const DPOP_TYP: &str = "dpop+jwt";

/// Decoded DPoP proof claim set.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DpopClaims {
    /// HTTP method of the request the proof is bound to, uppercased (e.g. `POST`).
    pub htm: String,
    /// HTTP target URI of the request the proof is bound to.
    pub htu: String,
    /// Issued-at (epoch seconds); the server enforces a freshness window.
    pub iat: i64,
    /// Unique proof id, used for one-time (anti-replay) enforcement.
    pub jti: String,
    /// Optional server-provided nonce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}
