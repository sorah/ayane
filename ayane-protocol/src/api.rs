//! HTTP/JSON request and response bodies for the ayane certificate authority.
//!
//! All PEM-bearing fields use standard PEM text (with `-----BEGIN ...-----`
//! armor). Timestamps are RFC 3339 strings. Serial numbers are decimal strings
//! (an optional `0x` hex form is accepted on input for revocation).

/// `POST /v1/sign` — request a brand new certificate.
///
/// Authentication is carried entirely by [`token`](Self::token), a one-time
/// issuance token (OTT) JWT signed by a configured provisioner. The CSR's
/// public key becomes the certificate's public key; its requested SANs must be
/// permitted by the token (see [`crate::token::OttClaims`]).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignRequest {
    /// PEM-encoded PKCS#10 certificate signing request.
    pub csr: String,
    /// One-time issuance token (a signed JWT).
    pub token: String,
    /// Optional requested notBefore (RFC 3339). Clamped to provisioner/template policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Optional requested notAfter (RFC 3339). Clamped to provisioner/template policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

/// `POST /v1/renew` — renew an existing certificate, keeping its public key.
///
/// Possession of the existing certificate's private key is proven with an
/// RFC 9449 DPoP proof carried in the `DPoP` header; the proof's embedded JWK
/// must match the presented certificate's public key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RenewRequest {
    /// PEM-encoded leaf certificate to be renewed.
    pub certificate: String,
}

/// `POST /v1/rekey` — renew an existing certificate with a new key pair.
///
/// As with [`RenewRequest`], the DPoP proof in the `DPoP` header must prove
/// possession of the *existing* certificate's private key. The new key is taken
/// from [`csr`](Self::csr).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RekeyRequest {
    /// PEM-encoded leaf certificate to be rekeyed.
    pub certificate: String,
    /// PEM-encoded PKCS#10 CSR carrying the new public key.
    pub csr: String,
}

/// `POST /v1/revoke` — revoke a certificate by serial number.
///
/// Two authorization paths are accepted: a revocation [`token`](Self::token)
/// issued by a provisioner, or a DPoP proof (in the `DPoP` header) together with
/// the [`certificate`](Self::certificate) being revoked, for self-service
/// revocation by the key holder.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RevokeRequest {
    /// Serial number, as a decimal string or `0x`-prefixed hex.
    pub serial_number: String,
    /// Human-readable reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// RFC 5280 CRLReason code (0-10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<i32>,
    /// Revocation token authorizing the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// PEM leaf certificate, for DPoP self-revocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
}

/// Response to a successful sign/renew/rekey.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CertificateResponse {
    /// PEM-encoded issued leaf certificate.
    pub certificate: String,
    /// PEM-encoded issuer chain: the immediate issuer first, up to (but not
    /// including) the root unless the CA is configured to bundle it.
    pub chain: Vec<String>,
    /// Decimal serial number of the issued certificate.
    pub serial_number: String,
    /// notAfter of the issued certificate (RFC 3339).
    pub not_after: String,
}

/// Response to a successful revocation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RevokeResponse {
    /// Always `"revoked"`.
    pub status: String,
}

/// `GET /v1/health`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthResponse {
    /// `"ok"`.
    pub status: String,
}

/// `GET /v1/roots`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RootsResponse {
    /// PEM-encoded trusted root certificate(s).
    pub certificates: Vec<String>,
}

/// `GET /v1/provisioners`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProvisionersResponse {
    /// Public metadata about configured provisioners (no secrets).
    pub provisioners: Vec<ProvisionerInfo>,
}

/// Public, non-secret description of a provisioner.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProvisionerInfo {
    /// Provisioner name; matches the `iss` claim of tokens it issues.
    pub name: String,
    /// Provisioner kind, e.g. `"jwk"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Accepted token audiences.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audiences: Vec<String>,
}
