//! Claims for the one-time issuance token (OTT).
//!
//! The OTT is a JWT signed by a provisioner's key. The server validates the
//! signature against the provisioner's configured public key (JWK) and enforces
//! the standard registered claims plus the ayane-specific `sans`/`cnf` claims.

/// Decoded OTT claim set.
///
/// The `aud`, `iss`, `nbf` and `exp` claims are validated by the JWT layer; the
/// `sub`, `sans` and `cnf` claims constrain the issued certificate.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OttClaims {
    /// Issuer: the provisioner name.
    pub iss: String,
    /// Audience: the CA endpoint this token is valid for.
    pub aud: String,
    /// Subject: the certificate common name / primary identity.
    pub sub: String,
    /// Permitted Subject Alternative Names. When empty, only `sub` is permitted.
    #[serde(default)]
    pub sans: Vec<String>,
    /// Issued-at (epoch seconds).
    pub iat: i64,
    /// Not-before (epoch seconds).
    pub nbf: i64,
    /// Expiry (epoch seconds).
    pub exp: i64,
    /// Unique token id, used for one-time (anti-replay) enforcement.
    pub jti: String,
    /// Optional confirmation binding the token to a specific CSR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,
}

/// RFC 7800-style confirmation claim.
///
/// When present, [`x5t_s256`](Self::x5t_s256) binds the token to the SHA-256
/// thumbprint of the DER-encoded CSR, so a captured token cannot be replayed
/// against a different CSR.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Confirmation {
    /// Base64url (no padding) SHA-256 digest of the DER-encoded CSR.
    #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
}
