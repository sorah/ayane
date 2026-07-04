//! Mint issuance tokens (OTT) and RFC 9449 DPoP proofs.

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn random_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Inputs for [`make_ott`].
pub struct OttParams<'a> {
    /// Token issuer (provisioner name).
    pub issuer: &'a str,
    /// Token audience (CA endpoint URL).
    pub audience: &'a str,
    /// Certificate subject / common name (or serial number, for `revoke`).
    pub subject: &'a str,
    /// Permitted SANs.
    pub sans: &'a [String],
    /// Token lifetime in seconds.
    pub validity_secs: i64,
    /// Whether the issued certificate may later be renewed or rekeyed.
    pub renew: bool,
    /// Optional once-per-scope anti-replay constraint.
    pub once: Option<ayane_protocol::OnceScope>,
}

/// Build a signed one-time issuance token.
pub fn make_ott(key: &crate::keypair::KeyPair, params: OttParams<'_>) -> anyhow::Result<String> {
    let now = unix_now();
    let claims = ayane_protocol::OttClaims {
        iss: params.issuer.to_string(),
        aud: params.audience.to_string(),
        sub: params.subject.to_string(),
        sans: params.sans.to_vec(),
        iat: now,
        nbf: now - 5,
        exp: now + params.validity_secs,
        jti: Some(random_id()),
        renew: params.renew,
        cnf: None,
        once: params.once,
    };
    let header = jsonwebtoken::Header::new(key.jwt_algorithm());
    Ok(jsonwebtoken::encode(
        &header,
        &claims,
        &key.encoding_key()?,
    )?)
}

/// Build a DPoP proof bound to `POST` of `htu`, signed by `key`.
pub fn make_dpop(key: &crate::keypair::KeyPair, htu: &str) -> anyhow::Result<String> {
    let now = unix_now();
    let claims = ayane_protocol::DpopClaims {
        htm: "POST".to_string(),
        htu: htu.to_string(),
        iat: now,
        jti: random_id(),
        nonce: None,
    };
    let mut header = jsonwebtoken::Header::new(key.jwt_algorithm());
    header.typ = Some(ayane_protocol::dpop::DPOP_TYP.to_string());
    header.jwk = Some(key.public_jwk()?);
    Ok(jsonwebtoken::encode(
        &header,
        &claims,
        &key.encoding_key()?,
    )?)
}
