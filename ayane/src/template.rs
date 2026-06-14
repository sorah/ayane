//! Certificate templates: the configured shape of an issued certificate.
//!
//! A template is structured (not a free-form text template): it declares key
//! usages, extended key usages, basic constraints and the validity policy. The
//! per-request identity (subject, SANs) and the computed key identifiers are
//! supplied by the CA when the template is rendered into concrete extensions.

/// The configured certificate template.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateTemplate {
    /// `keyUsage` bits. Defaults to `["digital_signature"]`.
    #[serde(default = "default_key_usage")]
    pub key_usage: Vec<KeyUsageName>,
    /// `extendedKeyUsage` purposes. Defaults to `["server_auth"]`.
    #[serde(default = "default_eku")]
    pub extended_key_usage: Vec<ExtKeyUsageName>,
    /// `basicConstraints` CA flag. Leaf templates leave this `false`.
    #[serde(default)]
    pub is_ca: bool,
    /// `basicConstraints` pathLenConstraint (only meaningful when `is_ca`).
    #[serde(default)]
    pub path_len: Option<u8>,
    /// Set the subject `commonName` from the token subject. Defaults to `true`.
    #[serde(default = "default_true")]
    pub set_common_name: bool,
    /// Default certificate lifetime when the request does not pin `notAfter`.
    #[serde(default = "default_validity")]
    pub default_validity: crate::duration::ConfigDuration,
    /// Minimum acceptable lifetime.
    #[serde(default = "min_validity")]
    pub min_validity: crate::duration::ConfigDuration,
    /// Maximum acceptable lifetime.
    #[serde(default = "default_validity")]
    pub max_validity: crate::duration::ConfigDuration,
    /// Backdate applied to `notBefore` to tolerate clock skew.
    #[serde(default = "default_backdate")]
    pub backdate: crate::duration::ConfigDuration,
}

fn default_key_usage() -> Vec<KeyUsageName> {
    vec![KeyUsageName::DigitalSignature]
}

fn default_eku() -> Vec<ExtKeyUsageName> {
    vec![ExtKeyUsageName::ServerAuth]
}

fn default_true() -> bool {
    true
}

fn default_validity() -> crate::duration::ConfigDuration {
    crate::duration::ConfigDuration(std::time::Duration::from_secs(24 * 3600))
}

fn min_validity() -> crate::duration::ConfigDuration {
    crate::duration::ConfigDuration(std::time::Duration::from_secs(60))
}

fn default_backdate() -> crate::duration::ConfigDuration {
    crate::duration::ConfigDuration(std::time::Duration::from_secs(60))
}

impl Default for CertificateTemplate {
    fn default() -> Self {
        CertificateTemplate {
            key_usage: default_key_usage(),
            extended_key_usage: default_eku(),
            is_ca: false,
            path_len: None,
            set_common_name: true,
            default_validity: default_validity(),
            min_validity: min_validity(),
            max_validity: default_validity(),
            backdate: default_backdate(),
        }
    }
}

/// A `keyUsage` bit, by name (snake_case in JSON).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyUsageName {
    DigitalSignature,
    #[serde(alias = "non_repudiation")]
    ContentCommitment,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
    KeyCertSign,
    CrlSign,
    EncipherOnly,
    DecipherOnly,
}

impl KeyUsageName {
    fn flag(self) -> x509_cert::ext::pkix::KeyUsages {
        match self {
            KeyUsageName::DigitalSignature => x509_cert::ext::pkix::KeyUsages::DigitalSignature,
            KeyUsageName::ContentCommitment => x509_cert::ext::pkix::KeyUsages::NonRepudiation,
            KeyUsageName::KeyEncipherment => x509_cert::ext::pkix::KeyUsages::KeyEncipherment,
            KeyUsageName::DataEncipherment => x509_cert::ext::pkix::KeyUsages::DataEncipherment,
            KeyUsageName::KeyAgreement => x509_cert::ext::pkix::KeyUsages::KeyAgreement,
            KeyUsageName::KeyCertSign => x509_cert::ext::pkix::KeyUsages::KeyCertSign,
            KeyUsageName::CrlSign => x509_cert::ext::pkix::KeyUsages::CRLSign,
            KeyUsageName::EncipherOnly => x509_cert::ext::pkix::KeyUsages::EncipherOnly,
            KeyUsageName::DecipherOnly => x509_cert::ext::pkix::KeyUsages::DecipherOnly,
        }
    }
}

/// An `extendedKeyUsage` purpose, by name (snake_case in JSON).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtKeyUsageName {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
}

impl ExtKeyUsageName {
    fn oid(self) -> const_oid::ObjectIdentifier {
        match self {
            ExtKeyUsageName::ServerAuth => const_oid::db::rfc5280::ID_KP_SERVER_AUTH,
            ExtKeyUsageName::ClientAuth => const_oid::db::rfc5280::ID_KP_CLIENT_AUTH,
            ExtKeyUsageName::CodeSigning => const_oid::db::rfc5280::ID_KP_CODE_SIGNING,
            ExtKeyUsageName::EmailProtection => const_oid::db::rfc5280::ID_KP_EMAIL_PROTECTION,
            ExtKeyUsageName::TimeStamping => const_oid::db::rfc5280::ID_KP_TIME_STAMPING,
            ExtKeyUsageName::OcspSigning => const_oid::db::rfc5280::ID_KP_OCSP_SIGNING,
        }
    }
}

/// Webhook-supplied overrides layered onto a template's extensions.
#[derive(Default)]
pub struct ExtensionOverrides<'a> {
    /// Replace the template's `keyUsage` set when present.
    pub key_usage: Option<&'a [KeyUsageName]>,
    /// Replace the template's `extendedKeyUsage` set when present.
    pub extended_key_usage: Option<&'a [ExtKeyUsageName]>,
    /// Extra extensions, layered on top by OID.
    pub additional_extensions: &'a [x509_cert::ext::Extension],
}

impl CertificateTemplate {
    /// Render the template into a full set of certificate extensions for a leaf
    /// with the given public key, SANs and issuing-CA key identifier.
    ///
    /// [`overrides`](ExtensionOverrides) replace the template's key-usage sets
    /// and layer extra extensions on top (replacing any same-OID extension). The
    /// subject and authority key identifiers are always (re)computed last, so
    /// they cannot be overridden.
    pub fn build_extensions(
        &self,
        subject_spki: &spki::SubjectPublicKeyInfoOwned,
        sans: &[crate::san::San],
        ca_key_id: &[u8],
        subject_is_empty: bool,
        overrides: &ExtensionOverrides<'_>,
    ) -> crate::error::Result<Vec<x509_cert::ext::Extension>> {
        let mut exts = Vec::new();

        let bc = x509_cert::ext::pkix::BasicConstraints {
            ca: self.is_ca,
            path_len_constraint: if self.is_ca { self.path_len } else { None },
        };
        upsert_extension(&mut exts, crate::x509::extension(&bc, true)?);

        let key_usage = overrides.key_usage.unwrap_or(&self.key_usage);
        if let Some(ext) = key_usage_extension(key_usage)? {
            upsert_extension(&mut exts, ext);
        }

        let extended_key_usage = overrides
            .extended_key_usage
            .unwrap_or(&self.extended_key_usage);
        if let Some(ext) = extended_key_usage_extension(extended_key_usage)? {
            upsert_extension(&mut exts, ext);
        }

        if let Some(ext) = subject_alt_name_extension(sans, subject_is_empty)? {
            upsert_extension(&mut exts, ext);
        }

        for ext in overrides.additional_extensions {
            upsert_extension(&mut exts, ext.clone());
        }

        finalize_key_identifiers(&mut exts, subject_spki, ca_key_id)?;
        Ok(exts)
    }

    /// Compute the certificate validity window, clamping the requested duration
    /// into `[min_validity, max_validity]`.
    pub fn compute_validity(
        &self,
        now: std::time::SystemTime,
        requested_not_before: Option<std::time::SystemTime>,
        requested_not_after: Option<std::time::SystemTime>,
    ) -> crate::error::Result<(std::time::SystemTime, std::time::SystemTime)> {
        let backdate = self.backdate.get();
        let base = requested_not_before.unwrap_or(now);
        let not_before = base.checked_sub(backdate).unwrap_or(base);

        let requested = match requested_not_after {
            Some(na) => na.duration_since(not_before).map_err(|_| {
                crate::error::Error::BadRequest("notAfter precedes notBefore".into())
            })?,
            None => self.default_validity.get() + backdate,
        };

        let min = self.min_validity.get();
        let max = self.max_validity.get() + backdate;
        if requested < min {
            return Err(crate::error::Error::BadRequest(format!(
                "requested validity {}s is below the minimum {}s",
                requested.as_secs(),
                min.as_secs()
            )));
        }
        let duration = requested.min(max);
        let not_after = not_before
            .checked_add(duration)
            .ok_or_else(|| crate::error::Error::Internal("validity overflow".into()))?;
        Ok((not_before, not_after))
    }

    /// The latest permissible `notAfter` for a window starting at `not_before`,
    /// i.e. `not_before + max_validity` (plus the skew backdate).
    ///
    /// Used to re-clamp a webhook-adjusted validity window so issuance can never
    /// exceed the template's configured maximum lifetime, even when a webhook
    /// overrides `notAfter`. Returns `None` only on arithmetic overflow.
    pub fn max_not_after(
        &self,
        not_before: std::time::SystemTime,
    ) -> Option<std::time::SystemTime> {
        not_before.checked_add(self.max_validity.get() + self.backdate.get())
    }
}

/// Insert `ext`, replacing any existing extension carrying the same OID.
pub(crate) fn upsert_extension(
    exts: &mut Vec<x509_cert::ext::Extension>,
    ext: x509_cert::ext::Extension,
) {
    exts.retain(|e| e.extn_id != ext.extn_id);
    exts.push(ext);
}

/// Build a `keyUsage` extension from names, or `None` when the set is empty.
pub(crate) fn key_usage_extension(
    names: &[KeyUsageName],
) -> crate::error::Result<Option<x509_cert::ext::Extension>> {
    if names.is_empty() {
        return Ok(None);
    }
    let mut flags: flagset::FlagSet<x509_cert::ext::pkix::KeyUsages> = flagset::FlagSet::default();
    for ku in names {
        flags |= ku.flag();
    }
    Ok(Some(crate::x509::extension(
        &x509_cert::ext::pkix::KeyUsage(flags),
        true,
    )?))
}

/// Build an `extendedKeyUsage` extension from names, or `None` when empty.
pub(crate) fn extended_key_usage_extension(
    names: &[ExtKeyUsageName],
) -> crate::error::Result<Option<x509_cert::ext::Extension>> {
    if names.is_empty() {
        return Ok(None);
    }
    let eku = x509_cert::ext::pkix::ExtendedKeyUsage(names.iter().map(|e| e.oid()).collect());
    Ok(Some(crate::x509::extension(&eku, false)?))
}

/// Build a `subjectAltName` extension (critical when the subject DN is empty),
/// or `None` when there are no SANs.
pub(crate) fn subject_alt_name_extension(
    sans: &[crate::san::San],
    critical: bool,
) -> crate::error::Result<Option<x509_cert::ext::Extension>> {
    if sans.is_empty() {
        return Ok(None);
    }
    let gns = sans
        .iter()
        .map(|s| s.to_general_name())
        .collect::<crate::error::Result<Vec<_>>>()?;
    Ok(Some(crate::x509::extension(
        &x509_cert::ext::pkix::SubjectAltName(gns),
        critical,
    )?))
}

/// (Re)compute and append the subject and authority key identifiers, replacing
/// any already present so they can never be overridden by template or webhook
/// input.
pub(crate) fn finalize_key_identifiers(
    exts: &mut Vec<x509_cert::ext::Extension>,
    subject_spki: &spki::SubjectPublicKeyInfoOwned,
    ca_key_id: &[u8],
) -> crate::error::Result<()> {
    let ski = crate::crypto::key_identifier(subject_spki);
    upsert_extension(
        exts,
        crate::x509::extension(
            &x509_cert::ext::pkix::SubjectKeyIdentifier(der::asn1::OctetString::new(ski)?),
            false,
        )?,
    );
    let aki = x509_cert::ext::pkix::AuthorityKeyIdentifier {
        key_identifier: Some(der::asn1::OctetString::new(ca_key_id.to_vec())?),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };
    upsert_extension(exts, crate::x509::extension(&aki, false)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn validity_clamps_to_max() {
        let tpl = super::CertificateTemplate {
            max_validity: crate::duration::ConfigDuration(std::time::Duration::from_secs(3600)),
            backdate: crate::duration::ConfigDuration(std::time::Duration::ZERO),
            ..Default::default()
        };
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        let want_na = now + std::time::Duration::from_secs(100_000);
        let (nb, na) = tpl.compute_validity(now, None, Some(want_na)).unwrap();
        assert_eq!(nb, now);
        assert_eq!(na, now + std::time::Duration::from_secs(3600));
    }

    #[test]
    fn validity_rejects_too_short() {
        let tpl = super::CertificateTemplate {
            min_validity: crate::duration::ConfigDuration(std::time::Duration::from_secs(3600)),
            backdate: crate::duration::ConfigDuration(std::time::Duration::ZERO),
            ..Default::default()
        };
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        let want_na = now + std::time::Duration::from_secs(60);
        assert!(tpl.compute_validity(now, None, Some(want_na)).is_err());
    }
}
