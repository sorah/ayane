//! Parsing and validation of PKCS#10 certificate signing requests.

/// A parsed CSR together with its DER encoding.
pub struct ParsedCsr {
    /// The decoded request.
    pub req: x509_cert::request::CertReq,
    /// The DER encoding the request was parsed from (used for fingerprinting).
    pub der: Vec<u8>,
}

impl ParsedCsr {
    /// Parse a PEM-encoded (`CERTIFICATE REQUEST`) CSR.
    pub fn from_pem(pem: &str) -> crate::error::Result<Self> {
        use der::DecodePem;
        let req = x509_cert::request::CertReq::from_pem(pem)
            .map_err(|e| crate::error::Error::BadRequest(format!("invalid CSR PEM: {e}")))?;
        Self::from_req(req)
    }

    /// Parse a DER-encoded CSR.
    pub fn from_der(der_bytes: &[u8]) -> crate::error::Result<Self> {
        use der::Decode;
        let req = x509_cert::request::CertReq::from_der(der_bytes)
            .map_err(|e| crate::error::Error::BadRequest(format!("invalid CSR DER: {e}")))?;
        Self::from_req(req)
    }

    fn from_req(req: x509_cert::request::CertReq) -> crate::error::Result<Self> {
        use der::Encode;
        let der = req
            .to_der()
            .map_err(|e| crate::error::Error::BadRequest(format!("cannot re-encode CSR: {e}")))?;
        Ok(ParsedCsr { req, der })
    }

    /// The requested public key (`SubjectPublicKeyInfo`).
    pub fn public_key(&self) -> &spki::SubjectPublicKeyInfoOwned {
        &self.req.info.public_key
    }

    /// Best-effort extraction of the subject common name.
    pub fn subject_common_name(&self) -> Option<String> {
        for rdn in self.req.info.subject.0.iter() {
            for atv in rdn.0.iter() {
                if atv.oid == const_oid::db::rfc4519::CN {
                    if let Ok(s) = atv.value.decode_as::<der::asn1::Utf8StringRef<'_>>() {
                        return Some(s.as_str().to_string());
                    }
                    if let Ok(s) = atv.value.decode_as::<der::asn1::PrintableStringRef<'_>>() {
                        return Some(s.as_str().to_string());
                    }
                }
            }
        }
        None
    }

    /// Extract the requested Subject Alternative Names from the
    /// `extensionRequest` attribute (PKCS#9, OID 1.2.840.113549.1.9.14).
    pub fn requested_sans(&self) -> crate::error::Result<Vec<crate::san::San>> {
        use const_oid::AssociatedOid;
        use der::{Decode, Encode};

        let mut sans = Vec::new();
        for attr in self.req.info.attributes.iter() {
            if attr.oid != x509_cert::request::ExtensionReq::OID {
                continue;
            }
            for value in attr.values.iter() {
                let ext_req = x509_cert::request::ExtensionReq::from_der(&value.to_der()?)
                    .map_err(|e| {
                        crate::error::Error::BadRequest(format!("invalid extensionRequest: {e}"))
                    })?;
                for ext in ext_req.0.iter() {
                    if ext.extn_id != x509_cert::ext::pkix::SubjectAltName::OID {
                        continue;
                    }
                    let san_ext =
                        x509_cert::ext::pkix::SubjectAltName::from_der(ext.extn_value.as_bytes())
                            .map_err(|e| {
                            crate::error::Error::BadRequest(format!("invalid SubjectAltName: {e}"))
                        })?;
                    for gn in san_ext.0.iter() {
                        if let Ok(san) = crate::san::San::try_from(gn) {
                            sans.push(san);
                        }
                    }
                }
            }
        }
        Ok(sans)
    }

    /// SHA-256 fingerprint of the DER CSR, base64url without padding. This is
    /// the value bound by the token's `cnf` / `x5t#S256` confirmation claim.
    pub fn fingerprint_b64url(&self) -> String {
        use base64::Engine;
        use sha2::Digest;
        let digest = sha2::Sha256::digest(&self.der);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    }

    /// Verify the CSR's self-signature, proving possession of the private key.
    pub fn verify_signature(&self) -> crate::error::Result<()> {
        use der::Encode;
        let tbs = self.req.info.to_der()?;
        let spki_der = self.public_key().to_der()?;
        let sig = self.req.signature.raw_bytes();
        crate::crypto::verify_signature(&spki_der, &tbs, sig, self.req.algorithm.oid).map_err(|e| {
            crate::error::Error::BadRequest(format!("CSR proof-of-possession failed: {e}"))
        })
    }
}
