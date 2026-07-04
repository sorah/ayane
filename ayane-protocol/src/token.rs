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
    /// Unique token id, used for one-time (anti-replay) enforcement. Optional:
    /// ayane's own OTTs always set it, but public OIDC issuers may omit it (e.g.
    /// Google), in which case the server derives a replay id from the token.
    #[serde(default)]
    pub jti: Option<String>,
    /// Optional confirmation binding the token to a specific CSR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,
    /// Optional once-per-scope constraint: bind issuance to happen at most once
    /// per an external identity (e.g. a backing EC2 instance id), independent of
    /// the per-token `jti`. See [`OnceScope`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub once: Option<OnceScope>,
}

/// A once-per-scope anti-replay constraint carried by an OTT.
///
/// Where `jti` makes a token itself single-use, a `once` scope makes *issuance*
/// single-use per an arbitrary value: the CA will issue at most one certificate
/// per [`scope`](Self::scope) until [`exp`](Self::exp), regardless of how many
/// distinct tokens carry that scope. Typical use: pin one certificate to one
/// backing instance for the certificate's lifetime.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OnceScope {
    /// The uniqueness value, e.g. a backing EC2 instance id. Issuance is
    /// rejected as a replay when this scope was already consumed (within the
    /// provisioner's namespace) and has not yet expired.
    pub scope: String,
    /// Epoch-seconds expiry of the scope claim. When omitted, the claim is held
    /// until the issued certificate's notAfter (at most one *valid* certificate
    /// per scope).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
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
