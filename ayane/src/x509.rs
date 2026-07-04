//! Manual X.509 certificate construction and remote signing.
//!
//! ayane builds the `TBSCertificate` by hand (rather than via a synchronous
//! signing builder) so that the actual signature can be produced asynchronously
//! by an arbitrary [`KeyProvider`] — in particular AWS KMS, which is async and
//! never exposes private-key bytes. The flow is: assemble extensions → build the
//! TBS → DER-encode it → hand the bytes to the key provider → wrap the returned
//! signature into a `Certificate`.

use der::{Decode, Encode};

/// ayane's private OID root (`1.3.6.1.4.1.47517.9.1`).
pub const OID_ROOT: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.47517.9.1");

/// Arc under [`OID_ROOT`] for ayane-specific X.509 certificate extensions
/// (`…9.1.509`, the label chosen to echo "X.509").
pub const OID_X509_EXTENSIONS: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.47517.9.1.509");

/// Non-renewable marker extension (`…9.1.509.1`). A certificate that must not be
/// renewed or rekeyed carries this extension with an ASN.1 `BOOLEAN` value of
/// `FALSE` (the `renewable` flag); a renewable certificate — the default — omits
/// it entirely. Non-critical, so relying parties ignore it.
pub const NON_RENEWABLE_OID: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.47517.9.1.509.1");

/// Build the non-renewable marker extension: OID [`NON_RENEWABLE_OID`],
/// non-critical, value `BOOLEAN FALSE` (`renewable = false`).
pub fn non_renewable_extension() -> crate::error::Result<x509_cert::ext::Extension> {
    Ok(x509_cert::ext::Extension {
        extn_id: NON_RENEWABLE_OID,
        critical: false,
        extn_value: der::asn1::OctetString::new(false.to_der()?)?,
    })
}

/// Whether `cert` is marked non-renewable: the [`NON_RENEWABLE_OID`] extension is
/// present and its `renewable` BOOLEAN is `FALSE`. A present-but-undecodable
/// value is treated as non-renewable (fail-closed); an absent extension means
/// renewable.
pub fn is_marked_non_renewable(cert: &x509_cert::Certificate) -> bool {
    let Some(extensions) = &cert.tbs_certificate.extensions else {
        return false;
    };
    match extensions.iter().find(|e| e.extn_id == NON_RENEWABLE_OID) {
        Some(ext) => !bool::from_der(ext.extn_value.as_bytes()).unwrap_or(false),
        None => false,
    }
}

/// Wrap a typed, DER-encodable extension value into an X.509 `Extension`.
pub fn extension<T>(value: &T, critical: bool) -> crate::error::Result<x509_cert::ext::Extension>
where
    T: der::Encode + const_oid::AssociatedOid,
{
    Ok(x509_cert::ext::Extension {
        extn_id: <T as const_oid::AssociatedOid>::OID,
        critical,
        extn_value: der::asn1::OctetString::new(value.to_der()?)?,
    })
}

/// Generate a positive, ~152-bit random serial number.
pub fn random_serial_number() -> crate::error::Result<x509_cert::serial_number::SerialNumber> {
    use rand::RngCore;
    let mut bytes = [0u8; 19];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    // Clear the top bit so the INTEGER is positive, and force a non-zero leading
    // byte so the encoding is canonical and the value is comfortably large.
    bytes[0] &= 0x7f;
    bytes[0] |= 0x40;
    x509_cert::serial_number::SerialNumber::new(&bytes)
        .map_err(|e| crate::error::Error::Internal(format!("serial number: {e}")))
}

/// Build a [`Validity`](x509_cert::time::Validity) from two wall-clock instants.
pub fn validity(
    not_before: std::time::SystemTime,
    not_after: std::time::SystemTime,
) -> crate::error::Result<x509_cert::time::Validity> {
    Ok(x509_cert::time::Validity {
        not_before: to_x509_time(not_before)?,
        not_after: to_x509_time(not_after)?,
    })
}

/// Encode an instant as an X.509 `Time`, choosing `UTCTime` for years through
/// 2049 and `GeneralizedTime` for 2050+, as RFC 5280 §4.1.2.5 requires.
fn to_x509_time(time: std::time::SystemTime) -> crate::error::Result<x509_cert::time::Time> {
    let dt = der::DateTime::from_system_time(time)
        .map_err(|e| crate::error::Error::Internal(format!("validity time: {e}")))?;
    if dt.year() <= 2049 {
        Ok(x509_cert::time::Time::UtcTime(
            der::asn1::UtcTime::from_date_time(dt)
                .map_err(|e| crate::error::Error::Internal(format!("utc time: {e}")))?,
        ))
    } else {
        Ok(x509_cert::time::Time::GeneralTime(
            der::asn1::GeneralizedTime::from_date_time(dt),
        ))
    }
}

/// Build an X.500 `Name` carrying a single `commonName`, or an empty name when
/// `cn` is empty (valid when identity is conveyed solely through SANs).
pub fn name_with_common_name(cn: &str) -> crate::error::Result<x509_cert::name::Name> {
    if cn.is_empty() {
        return Ok(x509_cert::name::RdnSequence(Vec::new()));
    }
    let utf8 = der::asn1::Utf8StringRef::new(cn)
        .map_err(|e| crate::error::Error::BadRequest(format!("invalid common name: {e}")))?;
    // Round-trip through DER to obtain an owned `Any` for the attribute value.
    let value = der::Any::from_der(&utf8.to_der()?)?;
    let atv = x509_cert::attr::AttributeTypeAndValue {
        oid: const_oid::db::rfc4519::CN,
        value,
    };
    let mut set = der::asn1::SetOfVec::new();
    set.insert(atv)
        .map_err(|e| crate::error::Error::Internal(format!("rdn set: {e}")))?;
    let rdn = x509_cert::name::RelativeDistinguishedName(set);
    Ok(x509_cert::name::RdnSequence(vec![rdn]))
}

/// Parameters for one leaf certificate's TBS body.
pub struct TbsParams {
    /// Serial number.
    pub serial_number: x509_cert::serial_number::SerialNumber,
    /// Algorithm the CA will sign with (drives the inner `signature` field).
    pub signature_algorithm: crate::crypto::SignatureAlgorithm,
    /// Issuer distinguished name (the CA subject).
    pub issuer: x509_cert::name::Name,
    /// Validity window.
    pub validity: x509_cert::time::Validity,
    /// Subject distinguished name.
    pub subject: x509_cert::name::Name,
    /// Subject public key (copied verbatim from the CSR).
    pub subject_public_key_info: spki::SubjectPublicKeyInfoOwned,
    /// Fully-built extensions.
    pub extensions: Vec<x509_cert::ext::Extension>,
}

/// Assemble a v3 `TBSCertificate` from [`TbsParams`].
pub fn build_tbs(params: TbsParams) -> crate::error::Result<x509_cert::TbsCertificate> {
    Ok(x509_cert::TbsCertificate {
        version: x509_cert::Version::V3,
        serial_number: params.serial_number,
        signature: params.signature_algorithm.algorithm_identifier()?,
        issuer: params.issuer,
        validity: params.validity,
        subject: params.subject,
        subject_public_key_info: params.subject_public_key_info,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(params.extensions),
    })
}

/// DER-encode the TBS, sign it via the key provider, and wrap the result into a
/// complete `Certificate`.
pub async fn sign_tbs(
    tbs: x509_cert::TbsCertificate,
    key: &dyn crate::key_provider::KeyProvider,
) -> crate::error::Result<x509_cert::Certificate> {
    let tbs_der = tbs.to_der()?;
    let sig = key.sign(&tbs_der).await?;
    let signature = der::asn1::BitString::from_bytes(&sig)
        .map_err(|e| crate::error::Error::Internal(format!("signature bitstring: {e}")))?;
    Ok(x509_cert::Certificate {
        tbs_certificate: tbs,
        signature_algorithm: key.algorithm().algorithm_identifier()?,
        signature,
    })
}

/// PEM-encode a certificate (`CERTIFICATE`, LF line endings).
pub fn certificate_pem(cert: &x509_cert::Certificate) -> crate::error::Result<String> {
    use der::EncodePem;
    cert.to_pem(der::pem::LineEnding::LF)
        .map_err(|e| crate::error::Error::Internal(format!("certificate PEM: {e}")))
}

/// Parse the first certificate from PEM text, tolerating a full chain bundle
/// (leaf followed by intermediates) — clients commonly present a fullchain file.
pub fn certificate_from_pem(pem: &str) -> crate::error::Result<x509_cert::Certificate> {
    use der::Decode;
    let blocks = pem::parse_many(pem.as_bytes())
        .map_err(|e| crate::error::Error::BadRequest(format!("invalid certificate PEM: {e}")))?;
    let leaf = blocks
        .iter()
        .find(|b| b.tag() == "CERTIFICATE")
        .ok_or_else(|| {
            crate::error::Error::BadRequest("no CERTIFICATE block in PEM".to_string())
        })?;
    x509_cert::Certificate::from_der(leaf.contents())
        .map_err(|e| crate::error::Error::BadRequest(format!("invalid certificate: {e}")))
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_renewable_extension_is_non_critical_boolean_false() {
        let ext = super::non_renewable_extension().unwrap();
        assert_eq!(ext.extn_id, super::NON_RENEWABLE_OID);
        assert!(!ext.critical);
        // Value is a DER ASN.1 BOOLEAN FALSE: tag 0x01, length 0x01, value 0x00.
        assert_eq!(ext.extn_value.as_bytes(), &[0x01, 0x01, 0x00]);
    }

    #[test]
    fn oid_arc_layout() {
        assert_eq!(super::OID_ROOT.to_string(), "1.3.6.1.4.1.47517.9.1");
        assert_eq!(
            super::OID_X509_EXTENSIONS.to_string(),
            "1.3.6.1.4.1.47517.9.1.509"
        );
        assert_eq!(
            super::NON_RENEWABLE_OID.to_string(),
            "1.3.6.1.4.1.47517.9.1.509.1"
        );
    }
}
