//! Verify the RFC 9421 signature on a `GET /v1/roots` response against a pinned
//! trusted root bundle.
//!
//! The CA signs the roots response with its issuing key; this proves the bundle
//! came from our PKI even when TLS is terminated by a third-party certificate.
//! Verification is fail-closed: the body digest must match, the signature must be
//! fresh and valid under the signer (issuing) certificate referenced by `x5u`
//! (with its leaf pinned by the signed `x5t`), and that signer certificate must
//! chain to a certificate in the pinned `--root` bundle. The signature-base
//! construction is shared with the server via [`ayane_protocol::httpsig`].

use der::{Decode, Encode};

/// Clock-skew leeway for the signature `created` instant, matching the OTT/DPoP
/// convention.
const SKEW: u64 = 60;

/// Upper bound on a signature's `expires - created` lifetime. The server default
/// is 24h; this caps the replay window defensively so a misconfigured CA cannot
/// hand out a signature valid for an unreasonably long time.
const MAX_SIGNATURE_LIFETIME: u64 = 7 * 24 * 3600;

/// Maximum number of intermediate hops considered while anchoring the signer
/// chain, a backstop against a pathological bag of certificates.
const MAX_PATH_DEPTH: usize = 8;

/// The header values pulled off the `GET /v1/roots` response.
pub(crate) struct ResponseHeaders {
    pub content_digest: String,
    pub signature_input: String,
    pub signature: String,
    pub signature_key: String,
}

/// Verify the signed roots response.
///
/// `signer_chain_pem` is the chain already fetched from the response's `x5u`
/// (the caller enforces same-origin); `known_roots_pem` is the pinned `--root`
/// bundle. `now` is the verification instant in epoch seconds.
pub(crate) fn verify_roots_response(
    body: &[u8],
    headers: &ResponseHeaders,
    signer_chain_pem: &[u8],
    known_roots_pem: &[u8],
    now: u64,
) -> anyhow::Result<()> {
    // 1. Body digest must match Content-Digest.
    let want_digest = sha384(body);
    let got_digest = ayane_protocol::httpsig::parse_content_digest(&headers.content_digest)?;
    if got_digest != want_digest {
        anyhow::bail!("roots response Content-Digest does not match the body");
    }

    // 2. Freshness.
    let params = ayane_protocol::httpsig::parse_roots_sig_params(&headers.signature_input)?;
    if params.expires <= params.created {
        anyhow::bail!("roots signature expires before it was created");
    }
    if params.expires - params.created > MAX_SIGNATURE_LIFETIME {
        anyhow::bail!("roots signature lifetime exceeds the maximum allowed");
    }
    if now >= params.expires {
        anyhow::bail!("roots signature has expired");
    }
    if params.created > now + SKEW {
        anyhow::bail!("roots signature is dated in the future");
    }

    // 3. Signer chain and the signed leaf thumbprint.
    let (_x5u, x5t) = ayane_protocol::httpsig::parse_signature_key_x509(&headers.signature_key)?;
    let chain = parse_certificates(signer_chain_pem)?;
    let leaf = chain
        .first()
        .ok_or_else(|| anyhow::anyhow!("signer chain is empty"))?;
    let leaf_thumbprint = ayane_protocol::httpsig::x5t_from_digest(&sha256(&leaf.to_der()?));
    if leaf_thumbprint != x5t {
        anyhow::bail!("signer chain leaf does not match the signed x5t thumbprint");
    }

    // 4. Verify the signature under the leaf's public key.
    let base = ayane_protocol::httpsig::roots_signature_base(
        200,
        ayane_protocol::httpsig::ROOTS_CONTENT_TYPE,
        &headers.content_digest,
        &headers.signature_key,
        &params,
    );
    let signature = ayane_protocol::httpsig::parse_signature_header(&headers.signature)?;
    let leaf_spki = leaf.tbs_certificate.subject_public_key_info.to_der()?;
    verify_rfc9421_signature(&params.alg, &leaf_spki, base.as_bytes(), &signature)?;

    // 5. Anchor the signer chain in the pinned root bundle.
    let known = parse_certificates(known_roots_pem)?;
    if known.is_empty() {
        anyhow::bail!("pinned root bundle contains no certificates");
    }
    anchor_signer(&chain, &known, now)?;

    Ok(())
}

/// A parsed certificate with the fields path-building needs precomputed.
struct Node<'a> {
    cert: &'a x509_cert::Certificate,
    subject: Vec<u8>,
    issuer: Vec<u8>,
    spki: Vec<u8>,
    der: Vec<u8>,
    not_before: u64,
    not_after: u64,
    is_ca: bool,
}

impl<'a> Node<'a> {
    fn new(cert: &'a x509_cert::Certificate) -> anyhow::Result<Node<'a>> {
        Ok(Node {
            subject: cert.tbs_certificate.subject.to_der()?,
            issuer: cert.tbs_certificate.issuer.to_der()?,
            spki: cert.tbs_certificate.subject_public_key_info.to_der()?,
            der: cert.to_der()?,
            not_before: cert
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration()
                .as_secs(),
            not_after: cert
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs(),
            is_ca: is_ca(cert),
            cert,
        })
    }

    fn temporally_valid(&self, now: u64) -> bool {
        self.not_before <= self.not_after && self.not_before <= now && now <= self.not_after
    }
}

/// Anchor the signer (`chain[0]`, already bound to `x5t` and signature-verified)
/// to a certificate in the pinned bundle `known`.
///
/// This is a path search, not a fixed linear walk: the served `chain` is an
/// unordered *bag* of candidate issuers that may include cross-signed twins
/// (same subject and key, signed by different roots) to support root rotation,
/// so issuers are matched by name + signature rather than by array position. A
/// valid path exists when the signer — or a same-key twin of any cert on the
/// path — is issued by (or is byte-equal to) a pinned root, with every served
/// cert temporally valid and every intermediate marked as a CA.
fn anchor_signer(
    chain: &[x509_cert::Certificate],
    known: &[x509_cert::Certificate],
    now: u64,
) -> anyhow::Result<()> {
    let bag = chain
        .iter()
        .map(Node::new)
        .collect::<anyhow::Result<Vec<_>>>()?;
    let anchors = known
        .iter()
        .map(Node::new)
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut visited: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    if reaches_anchor(&bag[0], &bag, &anchors, now, &mut visited, 0) {
        Ok(())
    } else {
        anyhow::bail!("signer chain does not anchor to the pinned root bundle")
    }
}

/// Whether `cert` (or a cross-signed twin of it in `bag`) reaches a pinned
/// anchor. `visited` records the `(subject, spki, issuer)` of edges already on
/// the current path to prevent loops.
fn reaches_anchor(
    cert: &Node<'_>,
    bag: &[Node<'_>],
    anchors: &[Node<'_>],
    now: u64,
    visited: &mut Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    depth: usize,
) -> bool {
    if depth > MAX_PATH_DEPTH {
        return false;
    }
    // The equivalence class of `cert`: itself plus any bag cert with the same
    // subject and key — a cross-signed twin, which may carry a different issuer
    // and so reach a different (e.g. older) root.
    let twins =
        std::iter::once(cert).chain(bag.iter().filter(|n| {
            !std::ptr::eq(*n, cert) && n.subject == cert.subject && n.spki == cert.spki
        }));

    for t in twins {
        if !t.temporally_valid(now) {
            continue;
        }
        let edge = (t.subject.clone(), t.spki.clone(), t.issuer.clone());
        if visited.contains(&edge) {
            continue;
        }

        // Anchored: this representative IS a pinned root, or is issued by one.
        // A pinned anchor is trusted a priori, so its own validity/CA bits are
        // not re-checked here.
        if anchors.iter().any(|a| a.der == t.der) {
            return true;
        }
        if anchors
            .iter()
            .any(|a| a.subject == t.issuer && verify_x509_signature(t.cert, &a.spki).is_ok())
        {
            return true;
        }

        // Otherwise climb: any bag cert that is a CA, is named as `t`'s issuer,
        // and actually signed `t`.
        visited.push(edge);
        for issuer in bag.iter().filter(|n| {
            n.is_ca && n.subject == t.issuer && verify_x509_signature(t.cert, &n.spki).is_ok()
        }) {
            if reaches_anchor(issuer, bag, anchors, now, visited, depth + 1) {
                return true;
            }
        }
        visited.pop();
    }
    false
}

/// Whether `cert` asserts `basicConstraints` cA=TRUE.
fn is_ca(cert: &x509_cert::Certificate) -> bool {
    use const_oid::AssociatedOid;
    let Some(exts) = &cert.tbs_certificate.extensions else {
        return false;
    };
    for ext in exts {
        if ext.extn_id == x509_cert::ext::pkix::BasicConstraints::OID {
            return x509_cert::ext::pkix::BasicConstraints::from_der(ext.extn_value.as_bytes())
                .map(|bc| bc.ca)
                .unwrap_or(false);
        }
    }
    false
}

/// Verify an RFC 9421 message signature (`raw` over `msg`) using the public key
/// in `spki_der`, dispatching on the `alg` token.
fn verify_rfc9421_signature(
    alg: &str,
    spki_der: &[u8],
    msg: &[u8],
    raw: &[u8],
) -> anyhow::Result<()> {
    ayane_protocol::crypto::verify_rfc9421_signature(alg, spki_der, msg, raw)
        .map_err(|e| anyhow::anyhow!("roots signature is invalid: {e}"))
}

/// Verify that `cert`'s X.509 signature validates under `parent_spki_der`.
fn verify_x509_signature(
    cert: &x509_cert::Certificate,
    parent_spki_der: &[u8],
) -> anyhow::Result<()> {
    let tbs = cert.tbs_certificate.to_der()?;
    ayane_protocol::crypto::verify_x509_signature(
        parent_spki_der,
        &tbs,
        cert.signature.raw_bytes(),
        cert.signature_algorithm.oid,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Parse every `CERTIFICATE` block from a PEM bundle into DER certificates.
fn parse_certificates(pem_bytes: &[u8]) -> anyhow::Result<Vec<x509_cert::Certificate>> {
    let mut out = Vec::new();
    for block in pem::parse_many(pem_bytes)? {
        if block.tag() == "CERTIFICATE" {
            out.push(x509_cert::Certificate::from_der(block.contents())?);
        }
    }
    Ok(out)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

fn sha384(bytes: &[u8]) -> [u8; 48] {
    use sha2::Digest;
    sha2::Sha384::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use der::EncodePem;

    /// A self-signed P-256 CA: its signing key and certificate. Acting as both
    /// the signer leaf and the trust anchor (single-tier) keeps the fixture small.
    fn self_signed_ca() -> (p256::ecdsa::SigningKey, x509_cert::Certificate) {
        use std::str::FromStr;
        let signing = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let spki = {
            use der::Decode;
            use spki::EncodePublicKey;
            spki::SubjectPublicKeyInfoOwned::from_der(
                signing
                    .verifying_key()
                    .to_public_key_der()
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap()
        };
        let builder = x509_cert::builder::CertificateBuilder::new(
            x509_cert::builder::Profile::Root,
            x509_cert::serial_number::SerialNumber::from(1u32),
            x509_cert::time::Validity::from_now(std::time::Duration::from_secs(3600)).unwrap(),
            x509_cert::name::Name::from_str("CN=ayane-test-ca").unwrap(),
            spki,
            &signing,
        )
        .unwrap();
        use x509_cert::builder::Builder;
        let cert = builder.build::<p256::ecdsa::DerSignature>().unwrap();
        (signing, cert)
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Sign `body` as the CA would, returning the response headers.
    fn sign_response(
        signing: &p256::ecdsa::SigningKey,
        cert: &x509_cert::Certificate,
        body: &[u8],
        created: u64,
        expires: u64,
    ) -> super::ResponseHeaders {
        use der::Encode;
        let content_digest = ayane_protocol::httpsig::content_digest_header(&super::sha384(body));
        let x5t = ayane_protocol::httpsig::x5t_from_digest(&super::sha256(&cert.to_der().unwrap()));
        let signature_key = ayane_protocol::httpsig::signature_key_x509(
            ayane_protocol::httpsig::SIGNER_CHAIN_PATH,
            &x5t,
        );
        let params = ayane_protocol::httpsig::RootsSigParams {
            created,
            expires,
            alg: "ecdsa-p256-sha256".to_string(),
        };
        let base = ayane_protocol::httpsig::roots_signature_base(
            200,
            ayane_protocol::httpsig::ROOTS_CONTENT_TYPE,
            &content_digest,
            &signature_key,
            &params,
        );
        let sig = <p256::ecdsa::SigningKey as signature::Signer<p256::ecdsa::Signature>>::sign(
            signing,
            base.as_bytes(),
        );
        super::ResponseHeaders {
            content_digest,
            signature_input: ayane_protocol::httpsig::signature_input_value(&params),
            signature: ayane_protocol::httpsig::signature_header_value(&sig.to_bytes()),
            signature_key,
        }
    }

    fn pem_of(cert: &x509_cert::Certificate) -> String {
        cert.to_pem(der::pem::LineEnding::LF).unwrap()
    }

    fn spki_of(key: &p256::ecdsa::SigningKey) -> spki::SubjectPublicKeyInfoOwned {
        use der::Decode;
        use spki::EncodePublicKey;
        spki::SubjectPublicKeyInfoOwned::from_der(
            key.verifying_key().to_public_key_der().unwrap().as_bytes(),
        )
        .unwrap()
    }

    fn time_at(offset_secs: i64) -> x509_cert::time::Time {
        let base = now() as i64 + offset_secs;
        x509_cert::time::Time::UtcTime(
            der::asn1::UtcTime::from_unix_duration(std::time::Duration::from_secs(
                base.max(0) as u64
            ))
            .unwrap(),
        )
    }

    /// Mint a CA certificate. `issuer` is `(issuer_cn, issuer_key)`, or `None`
    /// for a self-signed root. `subject_key`'s public half is embedded; the
    /// validity window is `[now+nb_off, now+na_off]`.
    fn make_ca(
        subject_cn: &str,
        subject_key: &p256::ecdsa::SigningKey,
        issuer: Option<(&str, &p256::ecdsa::SigningKey)>,
        nb_off: i64,
        na_off: i64,
    ) -> x509_cert::Certificate {
        use std::str::FromStr;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        let validity = x509_cert::time::Validity {
            not_before: time_at(nb_off),
            not_after: time_at(na_off),
        };
        let subject = x509_cert::name::Name::from_str(&format!("CN={subject_cn}")).unwrap();
        let (profile, signer) = match issuer {
            None => (Profile::Root, subject_key),
            Some((issuer_cn, issuer_key)) => (
                Profile::SubCA {
                    issuer: x509_cert::name::Name::from_str(&format!("CN={issuer_cn}")).unwrap(),
                    path_len_constraint: None,
                },
                issuer_key,
            ),
        };
        let builder = CertificateBuilder::new(
            profile,
            x509_cert::serial_number::SerialNumber::from(1u32),
            validity,
            subject,
            spki_of(subject_key),
            signer,
        )
        .unwrap();
        builder.build::<p256::ecdsa::DerSignature>().unwrap()
    }

    fn key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng)
    }

    #[test]
    fn accepts_two_tier_signer() {
        // Signer is an intermediate issued by a root; only the root is pinned and
        // the intermediate is not even served alongside itself beyond chain[0].
        let root_key = key();
        let root = make_ca("root", &root_key, None, -60, 3600);
        let signer_key = key();
        let signer = make_ca(
            "intermediate",
            &signer_key,
            Some(("root", &root_key)),
            -60,
            3600,
        );

        let body = b"body";
        let headers = sign_response(&signer_key, &signer, body, now(), now() + 600);
        super::verify_roots_response(
            body,
            &headers,
            pem_of(&signer).as_bytes(),
            pem_of(&root).as_bytes(),
            now(),
        )
        .expect("two-tier signer anchors to the pinned root");
    }

    #[test]
    fn accepts_cross_signed_during_root_rotation() {
        // Root rotation: same root DN, two keys. The intermediate is signed by
        // the new root; a cross-signed twin (same subject+key) is signed by the
        // old root. A client trusting ONLY the old root must still anchor the
        // signer via the twin — which the old linear `windows(2)` walk could not
        // do, since the served bag is [signer, new-root, twin].
        let old_root_key = key();
        let new_root_key = key();
        let old_root = make_ca("root", &old_root_key, None, -60, 3600);
        let new_root = make_ca("root", &new_root_key, None, -60, 3600);
        let signer_key = key();
        let signer = make_ca(
            "inter",
            &signer_key,
            Some(("root", &new_root_key)),
            -60,
            3600,
        );
        let twin = make_ca(
            "inter",
            &signer_key,
            Some(("root", &old_root_key)),
            -60,
            3600,
        );

        let body = b"body";
        let headers = sign_response(&signer_key, &signer, body, now(), now() + 600);
        let bag = format!("{}{}{}", pem_of(&signer), pem_of(&new_root), pem_of(&twin));

        // Client trusting only the OLD root anchors via the cross-signed twin.
        super::verify_roots_response(
            body,
            &headers,
            bag.as_bytes(),
            pem_of(&old_root).as_bytes(),
            now(),
        )
        .expect("anchors to the old root via the cross-signed twin");

        // Client trusting only the NEW root anchors via the canonical path.
        super::verify_roots_response(
            body,
            &headers,
            bag.as_bytes(),
            pem_of(&new_root).as_bytes(),
            now(),
        )
        .expect("anchors to the new root via the canonical path");
    }

    #[test]
    fn rejects_expired_signer_certificate() {
        // The signature window is fresh, but the signer certificate itself has
        // expired — it must not keep producing acceptable signatures.
        let signer_key = key();
        let signer = make_ca("ca", &signer_key, None, -7200, -3600);
        let body = b"body";
        let headers = sign_response(&signer_key, &signer, body, now(), now() + 600);
        assert!(
            super::verify_roots_response(
                body,
                &headers,
                pem_of(&signer).as_bytes(),
                pem_of(&signer).as_bytes(),
                now(),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_signature_lifetime_over_cap() {
        let (signing, cert) = self_signed_ca();
        let body = b"body";
        // expires - created exceeds the client cap.
        let headers = sign_response(
            &signing,
            &cert,
            body,
            now(),
            now() + super::MAX_SIGNATURE_LIFETIME + 1,
        );
        let chain = pem_of(&cert);
        assert!(
            super::verify_roots_response(body, &headers, chain.as_bytes(), chain.as_bytes(), now())
                .is_err()
        );
    }

    #[test]
    fn accepts_a_valid_signed_response() {
        let (signing, cert) = self_signed_ca();
        let body = br#"{"certificates":["root-pem"]}"#;
        let headers = sign_response(&signing, &cert, body, now(), now() + 600);
        let chain = pem_of(&cert);
        super::verify_roots_response(body, &headers, chain.as_bytes(), chain.as_bytes(), now())
            .expect("valid response verifies");
    }

    #[test]
    fn rejects_tampered_body() {
        let (signing, cert) = self_signed_ca();
        let headers = sign_response(&signing, &cert, b"original", now(), now() + 600);
        let chain = pem_of(&cert);
        // A different body no longer matches Content-Digest.
        assert!(
            super::verify_roots_response(
                b"tampered",
                &headers,
                chain.as_bytes(),
                chain.as_bytes(),
                now()
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_expired_signature() {
        let (signing, cert) = self_signed_ca();
        let body = b"body";
        let headers = sign_response(&signing, &cert, body, now() - 1200, now() - 600);
        let chain = pem_of(&cert);
        assert!(
            super::verify_roots_response(body, &headers, chain.as_bytes(), chain.as_bytes(), now())
                .is_err()
        );
    }

    #[test]
    fn rejects_unanchored_signer() {
        let (signing, cert) = self_signed_ca();
        let body = b"body";
        let headers = sign_response(&signing, &cert, body, now(), now() + 600);
        let chain = pem_of(&cert);
        // A different, unrelated CA is the only pinned root.
        let (_other_key, other) = self_signed_ca();
        let other_root = pem_of(&other);
        assert!(
            super::verify_roots_response(
                body,
                &headers,
                chain.as_bytes(),
                other_root.as_bytes(),
                now()
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_wrong_x5t() {
        let (signing, cert) = self_signed_ca();
        let body = b"body";
        let mut headers = sign_response(&signing, &cert, body, now(), now() + 600);
        // Swap in a Signature-Key whose x5t does not match the leaf.
        headers.signature_key = ayane_protocol::httpsig::signature_key_x509(
            ayane_protocol::httpsig::SIGNER_CHAIN_PATH,
            "not-the-leaf-thumbprint",
        );
        let chain = pem_of(&cert);
        assert!(
            super::verify_roots_response(body, &headers, chain.as_bytes(), chain.as_bytes(), now())
                .is_err()
        );
    }
}
