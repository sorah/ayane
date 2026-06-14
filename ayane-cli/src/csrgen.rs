//! Build and sign a PKCS#10 certificate signing request from a local key.

/// Build a PEM CSR for `common_name` with the given SANs, signed by `key`.
pub fn build_csr(
    key: &crate::keypair::KeyPair,
    common_name: &str,
    sans: &[String],
) -> anyhow::Result<String> {
    use const_oid::AssociatedOid;
    use der::{Decode, Encode, EncodePem};

    let spki = spki::SubjectPublicKeyInfoOwned::from_der(&key.public_key_der()?)?;
    let subject = name_with_common_name(common_name)?;

    let attributes = if sans.is_empty() {
        der::asn1::SetOfVec::new()
    } else {
        let general_names = sans
            .iter()
            .map(|s| san_to_general_name(s))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let san = x509_cert::ext::pkix::SubjectAltName(general_names);
        let extension = x509_cert::ext::Extension {
            extn_id: x509_cert::ext::pkix::SubjectAltName::OID,
            critical: false,
            extn_value: der::asn1::OctetString::new(san.to_der()?)?,
        };
        let ext_req = x509_cert::request::ExtensionReq(vec![extension]);
        let value = der::Any::from_der(&ext_req.to_der()?)?;
        let attribute = x509_cert::attr::Attribute {
            oid: x509_cert::request::ExtensionReq::OID,
            values: der::asn1::SetOfVec::try_from(vec![value])?,
        };
        der::asn1::SetOfVec::try_from(vec![attribute])?
    };

    let info = x509_cert::request::CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject,
        public_key: spki,
        attributes,
    };
    let info_der = info.to_der()?;
    let signature = key.sign_der(&info_der)?;

    let csr = x509_cert::request::CertReq {
        info,
        algorithm: key.algorithm_identifier()?,
        signature: der::asn1::BitString::from_bytes(&signature)?,
    };
    Ok(csr.to_pem(der::pem::LineEnding::LF)?)
}

fn name_with_common_name(cn: &str) -> anyhow::Result<x509_cert::name::Name> {
    use der::{Decode, Encode};
    if cn.is_empty() {
        return Ok(x509_cert::name::RdnSequence(Vec::new()));
    }
    let utf8 = der::asn1::Utf8StringRef::new(cn)?;
    let value = der::Any::from_der(&utf8.to_der()?)?;
    let atv = x509_cert::attr::AttributeTypeAndValue {
        oid: const_oid::db::rfc4519::CN,
        value,
    };
    let mut set = der::asn1::SetOfVec::new();
    set.insert(atv)?;
    Ok(x509_cert::name::RdnSequence(vec![
        x509_cert::name::RelativeDistinguishedName(set),
    ]))
}

fn san_to_general_name(s: &str) -> anyhow::Result<x509_cert::ext::pkix::name::GeneralName> {
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        let octets = match ip {
            std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
            std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        return Ok(x509_cert::ext::pkix::name::GeneralName::IpAddress(
            der::asn1::OctetString::new(octets)?,
        ));
    }
    if s.contains("://") {
        return Ok(
            x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
                der::asn1::Ia5String::new(s)?,
            ),
        );
    }
    if s.contains('@') {
        return Ok(x509_cert::ext::pkix::name::GeneralName::Rfc822Name(
            der::asn1::Ia5String::new(s)?,
        ));
    }
    Ok(x509_cert::ext::pkix::name::GeneralName::DnsName(
        der::asn1::Ia5String::new(s)?,
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn builds_parseable_csr() {
        use der::DecodePem;
        let key = crate::keypair::KeyPair::generate("ec256").unwrap();
        let pem = super::build_csr(
            &key,
            "host.example",
            &["host.example".to_string(), "10.0.0.1".to_string()],
        )
        .unwrap();
        let csr = x509_cert::request::CertReq::from_pem(&pem).unwrap();
        // The CSR self-signature must verify.
        use der::Encode;
        let tbs = csr.info.to_der().unwrap();
        let spki = csr.info.public_key.to_der().unwrap();
        // ECDSA P-256 verification.
        use p256::ecdsa::signature::Verifier;
        let vk = <p256::ecdsa::VerifyingKey as spki::DecodePublicKey>::from_public_key_der(&spki)
            .unwrap();
        let sig = p256::ecdsa::Signature::from_der(csr.signature.raw_bytes()).unwrap();
        vk.verify(&tbs, &sig).unwrap();
    }
}
