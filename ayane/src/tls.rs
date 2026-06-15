//! Self-issued serving TLS for the standalone runtime.
//!
//! When enabled (the default outside AWS Lambda), the server mints its own leaf
//! certificate from the configured CA, serves HTTPS with it, and renews it in the
//! background before expiry — mirroring step-ca's self-served TLS. The serving
//! leaf chains to the same root clients already fetch from `GET /v1/roots`, so no
//! new trust anchor is introduced. The serving key is an ephemeral in-memory
//! P-256 key, regenerated on every (re)issue and never written to disk.

/// Resolved serving-TLS parameters plus a handle to the issuing CA.
pub struct SelfIssuer {
    ca: std::sync::Arc<crate::ca::CertificateAuthority>,
    sans: Vec<crate::san::San>,
    validity: std::time::Duration,
    renew_before: std::time::Duration,
    renew_jitter: std::time::Duration,
    template: crate::template::CertificateTemplate,
}

/// A freshly minted serving certificate and the rustls material to serve it.
pub struct ServingCert {
    /// The leaf + chain and its signing key, ready for a `rustls::ServerConfig`.
    pub certified_key: std::sync::Arc<rustls::sign::CertifiedKey>,
    /// The leaf's `notAfter`, used to schedule renewal.
    pub not_after: std::time::SystemTime,
}

/// Resolve the serving certificate's SAN set, in precedence order:
///
/// 1. explicit `dns_names` / `ip_addresses` (combined) when either is non-empty;
/// 2. otherwise the host of `external_url`, if set;
/// 3. otherwise the loopback fallback (`localhost`, `127.0.0.1`, `::1`), matching
///    step-ca's default.
///
/// step-ca declares its serving SANs explicitly (`dnsNames` in `ca.json`) rather
/// than inferring the OS hostname; tier 2 adds an ayane-specific convenience
/// since ayane already configures `server.external_url`.
pub fn resolve_sans(
    tls: &crate::config::TlsConfig,
    external_url: Option<&str>,
) -> crate::error::Result<Vec<crate::san::San>> {
    if !tls.dns_names.is_empty() || !tls.ip_addresses.is_empty() {
        let mut sans = Vec::with_capacity(tls.dns_names.len() + tls.ip_addresses.len());
        for dns in &tls.dns_names {
            sans.push(crate::san::San::Dns(dns.clone()));
        }
        for ip in &tls.ip_addresses {
            let parsed = ip.parse::<std::net::IpAddr>().map_err(|e| {
                crate::error::Error::Config(format!(
                    "server.tls.ip_addresses: invalid IP {ip:?}: {e}"
                ))
            })?;
            sans.push(crate::san::San::Ip(parsed));
        }
        return Ok(sans);
    }

    if let Some(san) = external_url.and_then(|url| {
        url::Url::parse(url).ok().and_then(|parsed| {
            parsed.host().map(|host| match host {
                url::Host::Domain(d) => crate::san::San::Dns(d.to_string()),
                url::Host::Ipv4(a) => crate::san::San::Ip(std::net::IpAddr::V4(a)),
                url::Host::Ipv6(a) => crate::san::San::Ip(std::net::IpAddr::V6(a)),
            })
        })
    }) {
        return Ok(vec![san]);
    }

    Ok(vec![
        crate::san::San::Dns("localhost".to_string()),
        crate::san::San::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        crate::san::San::Ip(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    ])
}

/// The built-in server-auth template for the serving leaf. Kept independent of
/// `config.templates` so the serving identity does not inherit issuance policy.
fn server_template() -> crate::template::CertificateTemplate {
    crate::template::CertificateTemplate {
        key_usage: vec![
            crate::template::KeyUsageName::DigitalSignature,
            crate::template::KeyUsageName::KeyEncipherment,
        ],
        extended_key_usage: vec![crate::template::ExtKeyUsageName::ServerAuth],
        is_ca: false,
        path_len: None,
        set_common_name: true,
        ..Default::default()
    }
}

impl SelfIssuer {
    /// Build from the issuing CA and the resolved serving-TLS config. SAN
    /// resolution happens here (it needs `external_url`).
    pub fn new(
        ca: std::sync::Arc<crate::ca::CertificateAuthority>,
        tls: &crate::config::TlsConfig,
        external_url: Option<&str>,
    ) -> crate::error::Result<Self> {
        Ok(SelfIssuer {
            ca,
            sans: resolve_sans(tls, external_url)?,
            validity: tls.validity.get(),
            renew_before: tls.renew_before(),
            renew_jitter: tls.renew_jitter(),
            template: server_template(),
        })
    }

    /// The resolved SAN set, for logging.
    pub fn sans(&self) -> &[crate::san::San] {
        &self.sans
    }

    /// Generate an ephemeral key and issue a serving leaf for the resolved SANs.
    pub async fn issue_serving(&self) -> crate::error::Result<ServingCert> {
        use der::Decode;
        use pkcs8::EncodePrivateKey;
        use spki::EncodePublicKey;

        let signing = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let public_key = spki::SubjectPublicKeyInfoOwned::from_der(
            signing
                .verifying_key()
                .to_public_key_der()
                .map_err(|e| {
                    crate::error::Error::Internal(format!("encode serving public key: {e}"))
                })?
                .as_bytes(),
        )?;

        let now = std::time::SystemTime::now();
        let not_before = now - std::time::Duration::from_secs(60);
        let not_after = now + self.validity;
        let common_name = self
            .sans
            .iter()
            .find_map(|san| match san {
                crate::san::San::Dns(d) => Some(d.clone()),
                _ => None,
            })
            .unwrap_or_default();

        let issued = self
            .ca
            .issue(crate::ca::IssueParams {
                common_name,
                sans: self.sans.clone(),
                public_key,
                not_before,
                not_after,
                template: &self.template,
                key_usage_override: None,
                extended_key_usage_override: None,
                additional_extensions: Vec::new(),
            })
            .await?;

        let mut certs: Vec<rustls::pki_types::CertificateDer<'static>> = Vec::new();
        let pems = std::iter::once(issued.pem.as_str())
            .chain(self.ca.chain_pem().iter().map(String::as_str));
        for text in pems {
            for block in pem::parse_many(text).map_err(|e| {
                crate::error::Error::Internal(format!("parse serving chain PEM: {e}"))
            })? {
                certs.push(rustls::pki_types::CertificateDer::from(
                    block.into_contents(),
                ));
            }
        }

        let key_der = signing
            .to_pkcs8_der()
            .map_err(|e| crate::error::Error::Internal(format!("encode serving key: {e}")))?;
        let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_der.as_bytes().to_vec()),
        );
        let signing_key = rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&private_key)
            .map_err(|e| crate::error::Error::Internal(format!("load serving key: {e}")))?;

        Ok(ServingCert {
            certified_key: std::sync::Arc::new(rustls::sign::CertifiedKey::new(certs, signing_key)),
            not_after,
        })
    }
}

/// A `rustls` certificate resolver whose certificate can be hot-swapped while the
/// listener is live. SNI is ignored: the server presents a single identity.
#[derive(Debug)]
pub struct SwappableResolver {
    current: std::sync::RwLock<std::sync::Arc<rustls::sign::CertifiedKey>>,
}

impl SwappableResolver {
    /// Wrap an initial certificate.
    pub fn new(initial: std::sync::Arc<rustls::sign::CertifiedKey>) -> std::sync::Arc<Self> {
        std::sync::Arc::new(SwappableResolver {
            current: std::sync::RwLock::new(initial),
        })
    }

    /// Replace the served certificate.
    pub fn store(&self, certified_key: std::sync::Arc<rustls::sign::CertifiedKey>) {
        *self.current.write().expect("resolver lock poisoned") = certified_key;
    }
}

impl rustls::server::ResolvesServerCert for SwappableResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello,
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        Some(self.current.read().expect("resolver lock poisoned").clone())
    }
}

/// Build a `rustls::ServerConfig` backed by `resolver`, using the aws-lc-rs
/// provider explicitly so it coexists with whatever provider other crates link.
pub fn build_server_tls_config(
    resolver: std::sync::Arc<SwappableResolver>,
) -> crate::error::Result<std::sync::Arc<rustls::ServerConfig>> {
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| crate::error::Error::Internal(format!("build TLS config: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(std::sync::Arc::new(config))
}

/// Background task: renew the serving certificate before expiry and hot-swap it
/// into `resolver`. On failure the previous certificate keeps serving and the
/// renewal is retried after a bounded backoff.
pub async fn run_renewer(
    issuer: std::sync::Arc<SelfIssuer>,
    resolver: std::sync::Arc<SwappableResolver>,
    mut not_after: std::time::SystemTime,
) {
    let backoff = std::cmp::min(issuer.renew_before, std::time::Duration::from_secs(60));
    loop {
        tokio::time::sleep(renew_delay(
            not_after,
            issuer.renew_before,
            issuer.renew_jitter,
        ))
        .await;
        match issuer.issue_serving().await {
            Ok(serving) => {
                resolver.store(serving.certified_key);
                not_after = serving.not_after;
                tracing::info!(
                    not_after = %humantime::format_rfc3339_seconds(not_after),
                    "renewed serving certificate"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "serving certificate renewal failed; keeping current certificate"
                );
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

/// Time to wait before renewing: `notAfter - renew_before - rand(0, jitter)`,
/// clamped to zero when already due.
fn renew_delay(
    not_after: std::time::SystemTime,
    renew_before: std::time::Duration,
    renew_jitter: std::time::Duration,
) -> std::time::Duration {
    let jitter = if renew_jitter.is_zero() {
        std::time::Duration::ZERO
    } else {
        std::time::Duration::from_millis(rand::Rng::gen_range(
            &mut rand::rngs::OsRng,
            0..=renew_jitter.as_millis() as u64,
        ))
    };
    let renew_at = not_after
        .checked_sub(renew_before + jitter)
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    renew_at
        .duration_since(std::time::SystemTime::now())
        .unwrap_or(std::time::Duration::ZERO)
}

#[cfg(test)]
mod tests {
    use crate::san::San;

    fn tls_config(dns: &[&str], ips: &[&str]) -> crate::config::TlsConfig {
        crate::config::TlsConfig {
            dns_names: dns.iter().map(|s| s.to_string()).collect(),
            ip_addresses: ips.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn resolve_sans_prefers_explicit() {
        let tls = tls_config(&["a.example", "b.example"], &["10.0.0.1"]);
        let sans = super::resolve_sans(&tls, Some("https://ignored.example")).unwrap();
        assert_eq!(
            sans,
            vec![
                San::Dns("a.example".into()),
                San::Dns("b.example".into()),
                San::Ip("10.0.0.1".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn resolve_sans_from_external_url() {
        let tls = tls_config(&[], &[]);
        assert_eq!(
            super::resolve_sans(&tls, Some("https://ca.example.com:9443/v1")).unwrap(),
            vec![San::Dns("ca.example.com".into())]
        );
        assert_eq!(
            super::resolve_sans(&tls, Some("https://[2001:db8::1]:9443")).unwrap(),
            vec![San::Ip("2001:db8::1".parse().unwrap())]
        );
    }

    #[test]
    fn resolve_sans_loopback_fallback() {
        let tls = tls_config(&[], &[]);
        assert_eq!(
            super::resolve_sans(&tls, None).unwrap(),
            vec![
                San::Dns("localhost".into()),
                San::Ip("127.0.0.1".parse().unwrap()),
                San::Ip("::1".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn resolve_sans_rejects_bad_ip() {
        let tls = tls_config(&["a.example"], &["not-an-ip"]);
        assert!(super::resolve_sans(&tls, None).is_err());
    }

    #[tokio::test]
    async fn issue_serving_mints_a_verifiable_leaf() {
        let testca = crate::testca::ec_p256().await;
        let ca = std::sync::Arc::new(
            crate::ca::CertificateAuthority::new(
                testca.key.clone() as std::sync::Arc<dyn crate::key_provider::KeyProvider>,
                &testca.ca_cert_pem,
                vec![testca.ca_cert_pem.clone()],
                vec![testca.ca_cert_pem.clone()],
            )
            .unwrap(),
        );

        let tls = tls_config(&["ca.example.com"], &["10.0.0.1"]);
        let issuer = super::SelfIssuer::new(ca.clone(), &tls, None).unwrap();
        let serving = issuer.issue_serving().await.unwrap();

        // Leaf + issuer chain present, and the leaf is genuinely CA-signed.
        assert!(serving.certified_key.cert.len() >= 2);
        let leaf =
            <x509_cert::Certificate as der::Decode>::from_der(&serving.certified_key.cert[0])
                .unwrap();
        ca.verify_issued(&leaf).unwrap();

        // notAfter is ~validity ahead (default 24h).
        let remaining = serving
            .not_after
            .duration_since(std::time::SystemTime::now())
            .unwrap();
        assert!(remaining > std::time::Duration::from_secs(23 * 3600));
        assert!(remaining < std::time::Duration::from_secs(25 * 3600));
    }
}
