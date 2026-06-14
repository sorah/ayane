//! The certificate authority core: holds the issuing certificate and signing
//! key, and turns an authorized request into a signed leaf certificate.
//!
//! This layer is policy-free beyond the template's validity clamping; callers
//! (the [`crate::service`] orchestration) are responsible for authentication,
//! SAN authorization, webhooks and events.

use der::Encode;

/// Inputs for one issuance.
pub struct IssueParams<'a> {
    /// Subject common name; empty for a SAN-only certificate.
    pub common_name: String,
    /// Subject Alternative Names to place in the certificate.
    pub sans: Vec<crate::san::San>,
    /// The subject public key, taken verbatim from the CSR.
    pub public_key: spki::SubjectPublicKeyInfoOwned,
    /// Effective notBefore.
    pub not_before: std::time::SystemTime,
    /// Effective notAfter.
    pub not_after: std::time::SystemTime,
    /// Template governing extensions.
    pub template: &'a crate::template::CertificateTemplate,
    /// Webhook override for `keyUsage`; falls back to the template when `None`.
    pub key_usage_override: Option<Vec<crate::template::KeyUsageName>>,
    /// Webhook override for `extendedKeyUsage`; falls back to the template.
    pub extended_key_usage_override: Option<Vec<crate::template::ExtKeyUsageName>>,
    /// Extra extensions (e.g. from a webhook), layered on top by OID.
    pub additional_extensions: Vec<x509_cert::ext::Extension>,
}

/// Inputs for one reissuance (renew or rekey).
///
/// Unlike [`IssueParams`], the baseline is the previous certificate's identity
/// and extensions; the override fields apply a webhook's customization on top of
/// them (the SAN set is taken as-is from [`sans`](Self::sans), seeded by the
/// caller from the previous certificate).
pub struct ReissueParams<'a> {
    /// The certificate being reissued.
    pub old: &'a x509_cert::Certificate,
    /// The subject public key (same key for renew; new key for rekey).
    pub public_key: spki::SubjectPublicKeyInfoOwned,
    /// Webhook override for the subject common name; preserves the previous
    /// subject when `None`.
    pub subject_common_name_override: Option<String>,
    /// Effective SAN set for the reissued certificate.
    pub sans: Vec<crate::san::San>,
    /// Effective notBefore.
    pub not_before: std::time::SystemTime,
    /// Effective notAfter.
    pub not_after: std::time::SystemTime,
    /// Webhook override for `keyUsage`; preserves the previous set when `None`.
    pub key_usage_override: Option<Vec<crate::template::KeyUsageName>>,
    /// Webhook override for `extendedKeyUsage`; preserves the previous set.
    pub extended_key_usage_override: Option<Vec<crate::template::ExtKeyUsageName>>,
    /// Extra extensions (e.g. from a webhook), layered on top by OID.
    pub additional_extensions: Vec<x509_cert::ext::Extension>,
}

/// A freshly issued certificate plus convenient derived fields.
pub struct IssuedCertificate {
    /// The parsed certificate.
    pub certificate: x509_cert::Certificate,
    /// PEM encoding of the leaf.
    pub pem: String,
    /// Decimal serial number.
    pub serial_decimal: String,
    /// notAfter as an RFC 3339 string.
    pub not_after_rfc3339: String,
}

/// The issuing certificate authority.
pub struct CertificateAuthority {
    key: std::sync::Arc<dyn crate::key_provider::KeyProvider>,
    issuer_name: x509_cert::name::Name,
    ca_key_id: Vec<u8>,
    ca_spki_der: Vec<u8>,
    chain_pem: Vec<String>,
    roots_pem: Vec<String>,
}

impl CertificateAuthority {
    /// Construct from the signing key, issuing certificate PEM, the chain to
    /// return to clients (issuer up to but not including the root, or including
    /// it if desired), and the trusted root PEM(s).
    ///
    /// Fails if the key's public key does not match the issuing certificate.
    pub fn new(
        key: std::sync::Arc<dyn crate::key_provider::KeyProvider>,
        issuer_cert_pem: &str,
        chain_pem: Vec<String>,
        roots_pem: Vec<String>,
    ) -> crate::error::Result<Self> {
        let ca_cert = crate::x509::certificate_from_pem(issuer_cert_pem)?;
        let issuer_name = ca_cert.tbs_certificate.subject.clone();
        let ca_spki = &ca_cert.tbs_certificate.subject_public_key_info;
        let ca_key_id = crate::crypto::key_identifier(ca_spki);
        let ca_spki_der = ca_spki.to_der()?;

        if key.public_key_der() != ca_spki_der.as_slice() {
            return Err(crate::error::Error::Config(
                "signing key public key does not match the issuing certificate".into(),
            ));
        }

        Ok(CertificateAuthority {
            key,
            issuer_name,
            ca_key_id,
            ca_spki_der,
            chain_pem,
            roots_pem,
        })
    }

    /// The issuer distinguished name.
    pub fn issuer_name(&self) -> &x509_cert::name::Name {
        &self.issuer_name
    }

    /// PEM chain returned alongside issued certificates.
    pub fn chain_pem(&self) -> &[String] {
        &self.chain_pem
    }

    /// Trusted root PEM(s).
    pub fn roots_pem(&self) -> &[String] {
        &self.roots_pem
    }

    /// Build, sign and return a leaf certificate.
    pub async fn issue(&self, params: IssueParams<'_>) -> crate::error::Result<IssuedCertificate> {
        let subject_is_empty = !params.template.set_common_name || params.common_name.is_empty();
        let common_name = if params.template.set_common_name {
            params.common_name.as_str()
        } else {
            ""
        };
        let subject = crate::x509::name_with_common_name(common_name)?;

        let extensions = params.template.build_extensions(
            &params.public_key,
            &params.sans,
            &self.ca_key_id,
            subject_is_empty,
            &crate::template::ExtensionOverrides {
                key_usage: params.key_usage_override.as_deref(),
                extended_key_usage: params.extended_key_usage_override.as_deref(),
                additional_extensions: &params.additional_extensions,
            },
        )?;

        let serial_number = crate::x509::random_serial_number()?;
        let serial_decimal = serial_to_decimal(serial_number.as_bytes());
        let validity = crate::x509::validity(params.not_before, params.not_after)?;

        let tbs = crate::x509::build_tbs(crate::x509::TbsParams {
            serial_number,
            signature_algorithm: self.key.algorithm(),
            issuer: self.issuer_name.clone(),
            validity,
            subject,
            subject_public_key_info: params.public_key,
            extensions,
        })?;

        let certificate = crate::x509::sign_tbs(tbs, self.key.as_ref()).await?;
        let pem = crate::x509::certificate_pem(&certificate)?;
        let not_after_rfc3339 = humantime::format_rfc3339_seconds(params.not_after).to_string();

        Ok(IssuedCertificate {
            certificate,
            pem,
            serial_decimal,
            not_after_rfc3339,
        })
    }

    /// Reissue the previous certificate with a fresh serial and validity.
    ///
    /// By default the subject and all extensions (key usage, EKU, basic
    /// constraints, SANs, and any others) are preserved — so a renewal keeps the
    /// policy it was originally issued under rather than re-deriving it from a
    /// possibly-different current template. The override fields on
    /// [`ReissueParams`] (populated from a webhook) replace the subject common
    /// name, SAN set, key usages or extensions on top of that baseline; the
    /// subject and authority key identifiers are always recomputed.
    pub async fn reissue(
        &self,
        params: ReissueParams<'_>,
    ) -> crate::error::Result<IssuedCertificate> {
        use const_oid::AssociatedOid;

        let ski_oid = x509_cert::ext::pkix::SubjectKeyIdentifier::OID;
        let aki_oid = x509_cert::ext::pkix::AuthorityKeyIdentifier::OID;
        let san_oid = x509_cert::ext::pkix::SubjectAltName::OID;
        let ku_oid = x509_cert::ext::pkix::KeyUsage::OID;
        let eku_oid = x509_cert::ext::pkix::ExtendedKeyUsage::OID;

        // Resolve the subject: override the common name when asked, else preserve.
        let subject = match &params.subject_common_name_override {
            Some(cn) => crate::x509::name_with_common_name(cn)?,
            None => params.old.tbs_certificate.subject.clone(),
        };
        let subject_is_empty = subject.0.is_empty();

        // Start from the previous extensions, dropping the SAN and key
        // identifiers, which are re-derived from the effective inputs below.
        let mut extensions = Vec::new();
        if let Some(old_exts) = &params.old.tbs_certificate.extensions {
            for ext in old_exts {
                if ext.extn_id == ski_oid || ext.extn_id == aki_oid || ext.extn_id == san_oid {
                    continue;
                }
                extensions.push(ext.clone());
            }
        }

        if let Some(ext) =
            crate::template::subject_alt_name_extension(&params.sans, subject_is_empty)?
        {
            crate::template::upsert_extension(&mut extensions, ext);
        }

        if let Some(names) = &params.key_usage_override {
            match crate::template::key_usage_extension(names)? {
                Some(ext) => crate::template::upsert_extension(&mut extensions, ext),
                None => extensions.retain(|e| e.extn_id != ku_oid),
            }
        }
        if let Some(names) = &params.extended_key_usage_override {
            match crate::template::extended_key_usage_extension(names)? {
                Some(ext) => crate::template::upsert_extension(&mut extensions, ext),
                None => extensions.retain(|e| e.extn_id != eku_oid),
            }
        }

        for ext in &params.additional_extensions {
            crate::template::upsert_extension(&mut extensions, ext.clone());
        }
        crate::template::finalize_key_identifiers(
            &mut extensions,
            &params.public_key,
            &self.ca_key_id,
        )?;

        let serial_number = crate::x509::random_serial_number()?;
        let serial_decimal = serial_to_decimal(serial_number.as_bytes());
        let validity = crate::x509::validity(params.not_before, params.not_after)?;

        let tbs = crate::x509::build_tbs(crate::x509::TbsParams {
            serial_number,
            signature_algorithm: self.key.algorithm(),
            issuer: self.issuer_name.clone(),
            validity,
            subject,
            subject_public_key_info: params.public_key,
            extensions,
        })?;
        let certificate = crate::x509::sign_tbs(tbs, self.key.as_ref()).await?;
        let pem = crate::x509::certificate_pem(&certificate)?;
        Ok(IssuedCertificate {
            certificate,
            pem,
            serial_decimal,
            not_after_rfc3339: humantime::format_rfc3339_seconds(params.not_after).to_string(),
        })
    }

    /// Verify that `cert` was issued by this CA (its signature validates under
    /// the CA public key). Used to gate renewal/rekey/self-revocation to
    /// certificates this CA actually produced.
    pub fn verify_issued(&self, cert: &x509_cert::Certificate) -> crate::error::Result<()> {
        let tbs = cert.tbs_certificate.to_der()?;
        let sig = cert.signature.raw_bytes();
        crate::crypto::verify_signature(&self.ca_spki_der, &tbs, sig, cert.signature_algorithm.oid)
            .map_err(|_| {
                crate::error::Error::Forbidden("certificate was not issued by this CA".into())
            })
    }
}

/// Convert a big-endian unsigned serial-number magnitude into a decimal string.
pub fn serial_to_decimal(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = vec![0];
    for &byte in bytes {
        let mut carry = byte as u16;
        for d in digits.iter_mut() {
            let v = (*d as u16) * 256 + carry;
            *d = (v % 10) as u8;
            carry = v / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| char::from(b'0' + d)).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn serial_decimal_conversion() {
        assert_eq!(super::serial_to_decimal(&[0]), "0");
        assert_eq!(super::serial_to_decimal(&[1]), "1");
        assert_eq!(super::serial_to_decimal(&[0x01, 0x00]), "256");
        assert_eq!(super::serial_to_decimal(&[0xff, 0xff]), "65535");
    }

    #[tokio::test]
    async fn issues_verifiable_leaf() {
        use der::Encode;

        let ca = crate::testca::ec_p256().await;
        let authority = super::CertificateAuthority::new(
            ca.key.clone(),
            &ca.ca_cert_pem,
            vec![ca.ca_cert_pem.clone()],
            vec![ca.ca_cert_pem.clone()],
        )
        .unwrap();

        // A throwaway leaf key whose SPKI we embed.
        let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let leaf_spki = {
            use spki::EncodePublicKey;
            let der = leaf.public_key().to_public_key_der().unwrap();
            use der::Decode;
            spki::SubjectPublicKeyInfoOwned::from_der(der.as_bytes()).unwrap()
        };

        let template = crate::template::CertificateTemplate::default();
        let now = std::time::SystemTime::now();
        let issued = authority
            .issue(super::IssueParams {
                common_name: "leaf.example.com".into(),
                sans: vec![crate::san::San::Dns("leaf.example.com".into())],
                public_key: leaf_spki,
                not_before: now,
                not_after: now + std::time::Duration::from_secs(3600),
                template: &template,
                key_usage_override: None,
                extended_key_usage_override: None,
                additional_extensions: Vec::new(),
            })
            .await
            .unwrap();

        assert!(issued.pem.contains("BEGIN CERTIFICATE"));
        assert_ne!(issued.serial_decimal, "0");
        // RFC 5280 §4.1.2.5: present-day validity must be UTCTime, not GeneralizedTime.
        assert!(matches!(
            issued.certificate.tbs_certificate.validity.not_before,
            x509_cert::time::Time::UtcTime(_)
        ));
        assert!(matches!(
            issued.certificate.tbs_certificate.validity.not_after,
            x509_cert::time::Time::UtcTime(_)
        ));
        // The CA must recognize its own issuance.
        authority.verify_issued(&issued.certificate).unwrap();
        // The issuer DN must match.
        assert_eq!(
            issued.certificate.tbs_certificate.issuer.to_der().unwrap(),
            authority.issuer_name().to_der().unwrap()
        );
    }
}
