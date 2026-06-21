//! Minimal RFC 9421 HTTP Message Signature wire format for the `GET /v1/roots`
//! response — the only signed message in ayane.
//!
//! This is deliberately **not** a general RFC 9421 engine. The covered-component
//! set is fixed to `("@status" "content-type" "content-digest" "signature-key")`,
//! and the only key-distribution mechanism is the `x509` scheme of
//! [draft-hardt-httpbis-signature-key], carrying `x5u` (the URL of the signer
//! certificate chain) and `x5t` (the leaf thumbprint, signed so it authenticates
//! the out-of-band chain). Both the server (signer) and the CLI (verifier) build
//! the signature base through this module so the signed and verified bytes are
//! byte-identical.
//!
//! The body digest (`Content-Digest`, RFC 9530) is computed by the caller and
//! passed in as raw bytes, so this crate needs no hash dependency.
//!
//! [draft-hardt-httpbis-signature-key]: https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/

/// `Signature` response header (RFC 9421).
pub const SIGNATURE_HEADER: &str = "Signature";
/// `Signature-Input` response header (RFC 9421).
pub const SIGNATURE_INPUT_HEADER: &str = "Signature-Input";
/// `Signature-Key` response header (draft-hardt-httpbis-signature-key).
pub const SIGNATURE_KEY_HEADER: &str = "Signature-Key";
/// `Content-Digest` response header (RFC 9530).
pub const CONTENT_DIGEST_HEADER: &str = "Content-Digest";
/// The single signature label used throughout the roots response.
pub const ROOTS_SIGNATURE_LABEL: &str = "sig";
/// Path of the endpoint serving the signer certificate chain as PEM.
pub const SIGNER_CHAIN_PATH: &str = "/v1/roots/signer-chain";
/// Media type of the signer chain response (RFC 8555).
pub const PEM_CHAIN_MEDIA_TYPE: &str = "application/pem-certificate-chain";
/// Content-Type signed and returned for the `GET /v1/roots` body.
pub const ROOTS_CONTENT_TYPE: &str = "application/json";

/// The fixed, ordered covered-component inner list, as it appears in the
/// signature parameters.
const COVERED_COMPONENTS: &str =
    "(\"@status\" \"content-type\" \"content-digest\" \"signature-key\")";

/// A malformed signature header encountered while parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpSigError(pub String);

impl std::fmt::Display for HttpSigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "malformed HTTP signature: {}", self.0)
    }
}

impl std::error::Error for HttpSigError {}

fn err(msg: impl Into<String>) -> HttpSigError {
    HttpSigError(msg.into())
}

/// Signature parameters carried in `Signature-Input` / `@signature-params`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootsSigParams {
    /// Signature creation instant (epoch seconds).
    pub created: u64,
    /// Signature expiry instant (epoch seconds).
    pub expires: u64,
    /// RFC 9421 algorithm token, e.g. `ecdsa-p256-sha256`.
    pub alg: String,
}

/// `sha-384=:<base64(digest)>:` (RFC 9530 format) from a 48-byte SHA-384 digest.
///
/// `sha-384` is not a registered Content-Digest algorithm (RFC 9530 registers
/// `sha-256` and `sha-512`); it is an ayane-private choice, safe because the only
/// verifier is `ayane-cli`. It matches the digest strength of the SHA-384 signing
/// algorithms.
pub fn content_digest_header(sha384: &[u8; 48]) -> String {
    use base64::Engine;
    format!(
        "sha-384=:{}:",
        base64::engine::general_purpose::STANDARD.encode(sha384)
    )
}

/// Parse the SHA-384 digest out of a `sha-384=:…:` value.
pub fn parse_content_digest(value: &str) -> Result<[u8; 48], HttpSigError> {
    let inner = value
        .trim()
        .strip_prefix("sha-384=:")
        .and_then(|v| v.strip_suffix(':'))
        .ok_or_else(|| err("Content-Digest is not a single sha-384 byte sequence"))?;
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(inner)
        .map_err(|e| err(format!("Content-Digest base64: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| err("Content-Digest is not 48 bytes"))
}

/// `BASE64URL_NOPAD(digest)` — the `x5t` thumbprint, from a precomputed SHA-256
/// of the leaf certificate's DER.
pub fn x5t_from_digest(leaf_sha256: &[u8; 32]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(leaf_sha256)
}

/// `sig=x509;x5u="<url>";x5t="<thumbprint>"` — the full `Signature-Key` value.
pub fn signature_key_x509(x5u: &str, x5t: &str) -> String {
    format!("{ROOTS_SIGNATURE_LABEL}=x509;x5u=\"{x5u}\";x5t=\"{x5t}\"")
}

/// Parse `x5u` and `x5t` out of a `Signature-Key` value carrying the `x509`
/// scheme under the `sig` label.
pub fn parse_signature_key_x509(value: &str) -> Result<(String, String), HttpSigError> {
    let body = strip_label(value).ok_or_else(|| err("Signature-Key has no `sig` label"))?;
    if !body.trim_start().starts_with("x509") {
        return Err(err("Signature-Key is not the x509 scheme"));
    }
    let x5u = quoted_param(body, "x5u").ok_or_else(|| err("Signature-Key missing x5u"))?;
    let x5t = quoted_param(body, "x5t").ok_or_else(|| err("Signature-Key missing x5t"))?;
    Ok((x5u, x5t))
}

/// The `("@status" …);created=…;expires=…;alg="…"` string used verbatim both as
/// the `@signature-params` line value and (with the `sig=` label) as the
/// `Signature-Input` value.
pub fn roots_sig_params_value(p: &RootsSigParams) -> String {
    format!(
        "{COVERED_COMPONENTS};created={};expires={};alg=\"{}\"",
        p.created, p.expires, p.alg
    )
}

/// `sig=("@status" …);created=…;…` — the full `Signature-Input` header value.
pub fn signature_input_value(p: &RootsSigParams) -> String {
    format!("{ROOTS_SIGNATURE_LABEL}={}", roots_sig_params_value(p))
}

/// Parse a `Signature-Input` value, validating the covered-component set is
/// exactly the fixed roots set in order.
pub fn parse_roots_sig_params(value: &str) -> Result<RootsSigParams, HttpSigError> {
    let body = strip_label(value).ok_or_else(|| err("Signature-Input has no `sig` label"))?;
    let rest = body
        .trim()
        .strip_prefix(COVERED_COMPONENTS)
        .ok_or_else(|| err("Signature-Input covered components are not the expected roots set"))?;

    let mut created = None;
    let mut expires = None;
    let mut alg = None;
    for param in rest.split(';').filter(|s| !s.is_empty()) {
        let (k, v) = param.split_once('=').ok_or_else(|| {
            err(format!(
                "Signature-Input parameter {param:?} is not key=value"
            ))
        })?;
        match k {
            "created" => {
                created = Some(
                    v.parse::<u64>()
                        .map_err(|e| err(format!("Signature-Input created: {e}")))?,
                )
            }
            "expires" => {
                expires = Some(
                    v.parse::<u64>()
                        .map_err(|e| err(format!("Signature-Input expires: {e}")))?,
                )
            }
            "alg" => {
                alg = Some(
                    v.strip_prefix('"')
                        .and_then(|s| s.strip_suffix('"'))
                        .ok_or_else(|| err("Signature-Input alg is not a quoted string"))?
                        .to_string(),
                )
            }
            _ => {}
        }
    }
    Ok(RootsSigParams {
        created: created.ok_or_else(|| err("Signature-Input missing created"))?,
        expires: expires.ok_or_else(|| err("Signature-Input missing expires"))?,
        alg: alg.ok_or_else(|| err("Signature-Input missing alg"))?,
    })
}

/// The RFC 9421 signature base bytes to sign or verify, over the fixed component
/// set. Component values are the exact header values that are/were sent.
pub fn roots_signature_base(
    status: u16,
    content_type: &str,
    content_digest: &str,
    signature_key: &str,
    p: &RootsSigParams,
) -> String {
    format!(
        "\"@status\": {status}\n\
         \"content-type\": {content_type}\n\
         \"content-digest\": {content_digest}\n\
         \"signature-key\": {signature_key}\n\
         \"@signature-params\": {}",
        roots_sig_params_value(p)
    )
}

/// `sig=:<base64(signature)>:` — the full `Signature` header value.
pub fn signature_header_value(signature: &[u8]) -> String {
    use base64::Engine;
    format!(
        "{ROOTS_SIGNATURE_LABEL}=:{}:",
        base64::engine::general_purpose::STANDARD.encode(signature)
    )
}

/// Parse the raw signature bytes out of a `Signature` value (`sig=:…:`).
pub fn parse_signature_header(value: &str) -> Result<Vec<u8>, HttpSigError> {
    let body = strip_label(value).ok_or_else(|| err("Signature has no `sig` label"))?;
    let inner = body
        .trim()
        .strip_prefix(':')
        .and_then(|v| v.strip_suffix(':'))
        .ok_or_else(|| err("Signature is not a byte sequence"))?;
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(inner)
        .map_err(|e| err(format!("Signature base64: {e}")))
}

/// Strip the leading `sig=` label from a structured-field dictionary value
/// carrying the single roots signature.
fn strip_label(value: &str) -> Option<&str> {
    value
        .trim()
        .strip_prefix(ROOTS_SIGNATURE_LABEL)?
        .strip_prefix('=')
}

/// Extract a `name="value"` quoted parameter from a parameter string.
fn quoted_param(s: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let start = s.find(&needle)? + needle.len();
    let end = s[start..].find('"')? + start;
    Some(s[start..end].to_string())
}

#[cfg(test)]
mod tests {
    fn params() -> super::RootsSigParams {
        super::RootsSigParams {
            created: 1718360000,
            expires: 1718363600,
            alg: "ecdsa-p256-sha256".to_string(),
        }
    }

    #[test]
    fn params_value_is_exact() {
        assert_eq!(
            super::roots_sig_params_value(&params()),
            "(\"@status\" \"content-type\" \"content-digest\" \"signature-key\");created=1718360000;expires=1718363600;alg=\"ecdsa-p256-sha256\""
        );
    }

    #[test]
    fn params_roundtrip_via_input_value() {
        let value = super::signature_input_value(&params());
        assert!(value.starts_with("sig="));
        assert_eq!(super::parse_roots_sig_params(&value).unwrap(), params());
    }

    #[test]
    fn params_rejects_foreign_covered_set() {
        let bad = "sig=(\"@method\");created=1;expires=2;alg=\"ecdsa-p256-sha256\"";
        assert!(super::parse_roots_sig_params(bad).is_err());
    }

    #[test]
    fn signature_base_is_exact() {
        let digest = super::content_digest_header(&[0u8; 48]);
        let key = super::signature_key_x509("/v1/roots/signer-chain", "thumb");
        let base = super::roots_signature_base(200, "application/json", &digest, &key, &params());
        let expected = format!(
            "\"@status\": 200\n\"content-type\": application/json\n\"content-digest\": {digest}\n\"signature-key\": {key}\n\"@signature-params\": {}",
            super::roots_sig_params_value(&params())
        );
        assert_eq!(base, expected);
    }

    #[test]
    fn content_digest_roundtrip() {
        let d = [7u8; 48];
        let header = super::content_digest_header(&d);
        assert_eq!(super::parse_content_digest(&header).unwrap(), d);
    }

    #[test]
    fn signature_key_roundtrip() {
        let value = super::signature_key_x509("https://ca.example/v1/roots/signer-chain", "abc123");
        let (x5u, x5t) = super::parse_signature_key_x509(&value).unwrap();
        assert_eq!(x5u, "https://ca.example/v1/roots/signer-chain");
        assert_eq!(x5t, "abc123");
    }

    #[test]
    fn signature_roundtrip() {
        let sig = [1u8, 2, 3, 250, 251, 252];
        let value = super::signature_header_value(&sig);
        assert_eq!(super::parse_signature_header(&value).unwrap(), sig);
    }
}
