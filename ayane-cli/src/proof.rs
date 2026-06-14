//! Mint issuance tokens (OTT) and RFC 9449 DPoP proofs.

fn unix_now() -> i64 {
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

/// Build a signed one-time issuance token.
pub fn make_ott(
    key: &crate::keypair::KeyPair,
    issuer: &str,
    audience: &str,
    subject: &str,
    sans: &[String],
    validity_secs: i64,
) -> anyhow::Result<String> {
    let now = unix_now();
    let claims = ayane_protocol::OttClaims {
        iss: issuer.to_string(),
        aud: audience.to_string(),
        sub: subject.to_string(),
        sans: sans.to_vec(),
        iat: now,
        nbf: now - 5,
        exp: now + validity_secs,
        jti: random_id(),
        cnf: None,
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
