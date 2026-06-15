//! A normalized Subject Alternative Name value.
//!
//! The same [`San`] type is parsed out of a CSR, compared against the SANs a
//! token permits, and re-encoded into the issued certificate's `SubjectAltName`
//! extension, so issuance policy is enforced over one canonical representation.

/// A single Subject Alternative Name.
///
/// In webhook payloads this serializes as an adjacently tagged enum
/// (`{"type": "dns", "value": "example.com"}`), so the SAN kind is explicit
/// rather than re-derived from the string by [`San::parse`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum San {
    /// `dNSName`.
    Dns(String),
    /// `iPAddress`.
    Ip(std::net::IpAddr),
    /// `rfc822Name` (email).
    Email(String),
    /// `uniformResourceIdentifier`.
    Uri(String),
}

impl San {
    /// Heuristically classify a SAN string the way `step` and most CAs do:
    /// a parseable IP literal is an IP, a `scheme://` string is a URI, a string
    /// with an `@` is an email, otherwise a DNS name.
    pub fn parse(s: &str) -> San {
        if let Ok(ip) = s.parse::<std::net::IpAddr>() {
            return San::Ip(ip);
        }
        if s.contains("://") {
            return San::Uri(s.to_string());
        }
        if s.contains('@') {
            return San::Email(s.to_string());
        }
        San::Dns(s.to_string())
    }
}

impl TryFrom<&San> for x509_cert::ext::pkix::name::GeneralName {
    type Error = crate::error::Error;

    /// Encode into an X.509 `GeneralName`.
    fn try_from(san: &San) -> crate::error::Result<Self> {
        let gn = match san {
            San::Dns(d) => x509_cert::ext::pkix::name::GeneralName::DnsName(
                der::asn1::Ia5String::new(d).map_err(|e| {
                    crate::error::Error::BadRequest(format!("invalid DNS SAN {d:?}: {e}"))
                })?,
            ),
            San::Email(m) => x509_cert::ext::pkix::name::GeneralName::Rfc822Name(
                der::asn1::Ia5String::new(m).map_err(|e| {
                    crate::error::Error::BadRequest(format!("invalid email SAN {m:?}: {e}"))
                })?,
            ),
            San::Uri(u) => x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
                der::asn1::Ia5String::new(u).map_err(|e| {
                    crate::error::Error::BadRequest(format!("invalid URI SAN {u:?}: {e}"))
                })?,
            ),
            San::Ip(ip) => {
                let octets = match ip {
                    std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                    std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
                };
                x509_cert::ext::pkix::name::GeneralName::IpAddress(der::asn1::OctetString::new(
                    octets,
                )?)
            }
        };
        Ok(gn)
    }
}

impl TryFrom<&x509_cert::ext::pkix::name::GeneralName> for San {
    type Error = ();

    /// Decode from an X.509 `GeneralName`, failing for variants ayane does not
    /// model (directory name, otherName, ...).
    fn try_from(gn: &x509_cert::ext::pkix::name::GeneralName) -> Result<San, ()> {
        match gn {
            x509_cert::ext::pkix::name::GeneralName::DnsName(d) => {
                Ok(San::Dns(d.as_str().to_string()))
            }
            x509_cert::ext::pkix::name::GeneralName::Rfc822Name(m) => {
                Ok(San::Email(m.as_str().to_string()))
            }
            x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(u) => {
                Ok(San::Uri(u.as_str().to_string()))
            }
            x509_cert::ext::pkix::name::GeneralName::IpAddress(bytes) => {
                let b = bytes.as_bytes();
                match b.len() {
                    4 => {
                        let arr: [u8; 4] = b.try_into().map_err(|_| ())?;
                        Ok(San::Ip(std::net::IpAddr::from(arr)))
                    }
                    16 => {
                        let arr: [u8; 16] = b.try_into().map_err(|_| ())?;
                        Ok(San::Ip(std::net::IpAddr::from(arr)))
                    }
                    _ => Err(()),
                }
            }
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for San {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            San::Dns(d) => write!(f, "{d}"),
            San::Email(m) => write!(f, "{m}"),
            San::Uri(u) => write!(f, "{u}"),
            San::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::San;

    #[test]
    fn parse_classifies() {
        assert_eq!(San::parse("example.com"), San::Dns("example.com".into()));
        assert!(matches!(San::parse("10.0.0.1"), San::Ip(_)));
        assert!(matches!(San::parse("::1"), San::Ip(_)));
        assert_eq!(San::parse("a@b.com"), San::Email("a@b.com".into()));
        assert_eq!(San::parse("spiffe://x/y"), San::Uri("spiffe://x/y".into()));
    }

    #[test]
    fn general_name_roundtrip() {
        for s in ["example.com", "10.0.0.1", "::1", "a@b.com", "https://x/y"] {
            let san = San::parse(s);
            let gn = x509_cert::ext::pkix::name::GeneralName::try_from(&san).unwrap();
            assert_eq!(San::try_from(&gn), Ok(san));
        }
    }
}
