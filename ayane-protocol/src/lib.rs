//! Shared wire protocol definitions between the ayane server and clients.
//!
//! These types form the HTTP/JSON contract for certificate issuance, renewal,
//! rekeying and revocation, plus the JWT claim shapes for the one-time issuance
//! token (OTT) and the RFC 9449 DPoP proof used to authenticate renewal/rekey of
//! an existing certificate.

pub mod api;
pub mod dpop;
pub mod problem;
pub mod token;

pub use crate::api::{
    CertificateResponse, HealthResponse, ProvisionerInfo, ProvisionersResponse, RekeyRequest,
    RenewRequest, RevokeRequest, RevokeResponse, RootsResponse, SignRequest,
};
pub use crate::dpop::DpopClaims;
pub use crate::problem::ProblemDetails;
pub use crate::token::{Confirmation, OttClaims};

/// HTTP header carrying the RFC 9449 DPoP proof JWT.
pub const DPOP_HEADER: &str = "DPoP";

/// Default mount prefix for the HTTP API.
pub const API_PREFIX: &str = "/v1";
