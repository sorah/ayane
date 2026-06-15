//! Issuance webhooks: external services that gate and/or augment certificate
//! issuance, renewal and rekey.
//!
//! A single webhook receives a typed description of the pending certificate and
//! replies with one typed [`WebhookResponse`]: it may deny the request
//! (`allow = false`) and/or customize the certificate (subject, SANs, validity,
//! key usages, or arbitrary extensions) from the same response — there is no
//! authorizing/enriching distinction. Transport is either HTTPS (optionally
//! HMAC-signed) or a synchronous AWS Lambda invocation.
//!
//! Each applicable webhook is invoked with the *original* request (it does not
//! observe an earlier webhook's customization); their responses are layered onto
//! a [`Customization`] in configuration order, which the caller then turns into
//! the issued certificate.

pub mod http;
pub mod lambda;

/// The operation a webhook is being consulted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// A fresh issuance (`POST /v1/sign`).
    Sign,
    /// A renewal, same key (`POST /v1/renew`).
    Renew,
    /// A rekey, new key (`POST /v1/rekey`).
    Rekey,
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::Sign => write!(f, "sign"),
            Operation::Renew => write!(f, "renew"),
            Operation::Rekey => write!(f, "rekey"),
        }
    }
}

/// The typed payload sent to a webhook. Serialized as the HTTP/Lambda body.
#[serde_with::serde_as]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WebhookRequest {
    /// Timestamp of the call.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// The operation being performed.
    pub operation: Operation,
    /// Provisioner name (for token-authorized issuance).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisioner: Option<String>,
    /// Requested subject common name.
    pub subject: String,
    /// Requested Subject Alternative Names, each tagged with its kind.
    pub sans: Vec<crate::san::San>,
    /// DER of the request CSR (present for `sign` and `rekey`), base64-encoded.
    #[serde_as(
        as = "Option<serde_with::base64::Base64<serde_with::base64::Standard, serde_with::formats::Padded>>"
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csr_der: Option<Vec<u8>>,
    /// DER of the previous certificate (present for `renew` and `rekey`),
    /// base64-encoded.
    #[serde_as(
        as = "Option<serde_with::base64::Base64<serde_with::base64::Standard, serde_with::formats::Padded>>"
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_certificate_der: Option<Vec<u8>>,
    /// Effective notBefore.
    pub not_before: chrono::DateTime<chrono::Utc>,
    /// Effective notAfter.
    pub not_after: chrono::DateTime<chrono::Utc>,
}

/// An arbitrary X.509 extension supplied by a webhook.
#[serde_with::serde_as]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RawExtension {
    /// Dotted-decimal object identifier, e.g. `"1.3.6.1.5.5.7.1.1"`.
    pub oid: String,
    /// DER-encoded extension value (the inner value, not the OCTET STRING
    /// wrapper), base64-encoded.
    #[serde_as(
        as = "serde_with::base64::Base64<serde_with::base64::Standard, serde_with::formats::Padded>"
    )]
    pub value: Vec<u8>,
    /// Whether the extension is critical.
    #[serde(default)]
    pub critical: bool,
}

impl RawExtension {
    fn to_extension(&self) -> crate::error::Result<x509_cert::ext::Extension> {
        let extn_id = self
            .oid
            .parse::<const_oid::ObjectIdentifier>()
            .map_err(|e| {
                crate::error::Error::BadRequest(format!(
                    "webhook extension OID {:?}: {e}",
                    self.oid
                ))
            })?;
        Ok(x509_cert::ext::Extension {
            extn_id,
            critical: self.critical,
            extn_value: der::asn1::OctetString::new(self.value.clone()).map_err(|e| {
                crate::error::Error::Internal(format!("webhook extension value: {e}"))
            })?,
        })
    }
}

/// A webhook's typed reply. Every field is optional: an absent field leaves the
/// corresponding certificate property at its pre-webhook value.
#[serde_with::serde_as]
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct WebhookResponse {
    /// `Some(false)` denies the request; `Some(true)`/`None` permit it.
    pub allow: Option<bool>,
    /// Human-readable denial reason, surfaced when `allow` is `false`.
    pub deny_reason: Option<String>,
    /// Override the subject common name.
    pub subject_common_name: Option<String>,
    /// Replace the SAN set entirely.
    pub sans: Option<Vec<crate::san::San>>,
    /// Add SANs to the (possibly replaced) set.
    pub additional_sans: Vec<crate::san::San>,
    /// Override notBefore.
    pub not_before: Option<chrono::DateTime<chrono::Utc>>,
    /// Override notAfter.
    pub not_after: Option<chrono::DateTime<chrono::Utc>>,
    /// Override the `keyUsage` set.
    pub key_usage: Option<Vec<crate::template::KeyUsageName>>,
    /// Override the `extendedKeyUsage` set.
    pub extended_key_usage: Option<Vec<crate::template::ExtKeyUsageName>>,
    /// Inject arbitrary extensions (replacing any with the same OID).
    pub additional_extensions: Vec<RawExtension>,
}

/// An invokable webhook.
#[async_trait::async_trait]
pub trait WebhookProvider: Send + Sync {
    /// Webhook name.
    fn name(&self) -> &str;

    /// Whether this webhook applies to the named provisioner.
    fn applies_to(&self, provisioner: Option<&str>) -> bool;

    /// Invoke the webhook.
    async fn call(&self, request: &WebhookRequest) -> crate::error::Result<WebhookResponse>;
}

/// Build one configured webhook. Lambda webhooks resolve their client from the
/// shared AWS configuration, loaded lazily on first use.
pub async fn from_config(
    cfg: &crate::config::WebhookConfig,
) -> crate::error::Result<std::sync::Arc<dyn WebhookProvider>> {
    match &cfg.target {
        crate::config::WebhookTarget::Http {
            url,
            secret,
            bearer_token,
        } => Ok(std::sync::Arc::new(crate::webhook::http::HttpWebhook::new(
            cfg.name.clone(),
            cfg.provisioners.clone(),
            url.clone(),
            secret.clone(),
            bearer_token.clone(),
            cfg.timeout.map(crate::duration::ConfigDuration::get),
        )?) as std::sync::Arc<dyn WebhookProvider>),
        crate::config::WebhookTarget::Lambda {
            function_name,
            region,
        } => {
            let client = crate::webhook::lambda::client(region.as_deref()).await;
            Ok(
                std::sync::Arc::new(crate::webhook::lambda::LambdaWebhook::new(
                    cfg.name.clone(),
                    cfg.provisioners.clone(),
                    client,
                    function_name.clone(),
                )) as std::sync::Arc<dyn WebhookProvider>,
            )
        }
    }
}

/// The inputs a webhook is consulted with, owned by the caller.
pub struct Context<'a> {
    /// The operation being performed.
    pub operation: Operation,
    /// Provisioner name, when issuance was token-authorized.
    pub provisioner: Option<&'a str>,
    /// Baseline subject common name.
    pub subject: &'a str,
    /// Baseline SAN set.
    pub sans: Vec<crate::san::San>,
    /// Baseline notBefore.
    pub not_before: std::time::SystemTime,
    /// Baseline notAfter.
    pub not_after: std::time::SystemTime,
    /// DER of the request CSR, for `sign`/`rekey`.
    pub csr_der: Option<&'a [u8]>,
    /// DER of the previous certificate, for `renew`/`rekey`.
    pub previous_certificate_der: Option<&'a [u8]>,
}

/// The effective certificate properties after applying webhook responses,
/// seeded from the [`Context`] baseline.
pub struct Customization {
    /// Override subject common name, or `None` to keep the baseline subject.
    pub subject_common_name: Option<String>,
    /// Effective SAN set.
    pub sans: Vec<crate::san::San>,
    /// Effective notBefore.
    pub not_before: std::time::SystemTime,
    /// Effective notAfter.
    pub not_after: std::time::SystemTime,
    /// Override `keyUsage`, or `None` to keep the baseline.
    pub key_usage: Option<Vec<crate::template::KeyUsageName>>,
    /// Override `extendedKeyUsage`, or `None` to keep the baseline.
    pub extended_key_usage: Option<Vec<crate::template::ExtKeyUsageName>>,
    /// Extra extensions to layer onto the certificate.
    pub additional_extensions: Vec<x509_cert::ext::Extension>,
}

/// Consult every applicable webhook in order, layering their responses onto a
/// [`Customization`]. Returns [`crate::error::Error::Forbidden`] as soon as a
/// webhook denies the request.
pub async fn run(
    webhooks: &[std::sync::Arc<dyn WebhookProvider>],
    ctx: &Context<'_>,
) -> crate::error::Result<Customization> {
    let mut customization = Customization {
        subject_common_name: None,
        sans: ctx.sans.clone(),
        not_before: ctx.not_before,
        not_after: ctx.not_after,
        key_usage: None,
        extended_key_usage: None,
        additional_extensions: Vec::new(),
    };
    if webhooks.is_empty() {
        return Ok(customization);
    }

    let request = WebhookRequest {
        timestamp: chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::now()),
        operation: ctx.operation,
        provisioner: ctx.provisioner.map(str::to_string),
        subject: ctx.subject.to_string(),
        sans: ctx.sans.clone(),
        csr_der: ctx.csr_der.map(<[u8]>::to_vec),
        previous_certificate_der: ctx.previous_certificate_der.map(<[u8]>::to_vec),
        not_before: chrono::DateTime::<chrono::Utc>::from(ctx.not_before),
        not_after: chrono::DateTime::<chrono::Utc>::from(ctx.not_after),
    };

    for webhook in webhooks {
        if !webhook.applies_to(ctx.provisioner) {
            continue;
        }
        let response = webhook.call(&request).await?;
        if response.allow == Some(false) {
            let reason = response
                .deny_reason
                .unwrap_or_else(|| format!("issuance denied by webhook {:?}", webhook.name()));
            return Err(crate::error::Error::Forbidden(reason));
        }
        apply_response(&mut customization, &response)?;
    }
    Ok(customization)
}

/// Layer one webhook response onto the accumulating customization.
fn apply_response(
    customization: &mut Customization,
    response: &WebhookResponse,
) -> crate::error::Result<()> {
    if let Some(cn) = &response.subject_common_name {
        customization.subject_common_name = Some(cn.clone());
    }
    if let Some(sans) = &response.sans {
        customization.sans = sans.clone();
    }
    for san in &response.additional_sans {
        if !customization.sans.contains(san) {
            customization.sans.push(san.clone());
        }
    }
    if let Some(nb) = response.not_before {
        customization.not_before = std::time::SystemTime::from(nb);
    }
    if let Some(na) = response.not_after {
        customization.not_after = std::time::SystemTime::from(na);
    }
    if let Some(ku) = &response.key_usage {
        customization.key_usage = Some(ku.clone());
    }
    if let Some(eku) = &response.extended_key_usage {
        customization.extended_key_usage = Some(eku.clone());
    }
    for raw in &response.additional_extensions {
        customization
            .additional_extensions
            .push(raw.to_extension()?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    fn san(s: &str) -> crate::san::San {
        crate::san::San::parse(s)
    }

    fn base_customization() -> super::Customization {
        super::Customization {
            subject_common_name: None,
            sans: vec![san("example.com")],
            not_before: std::time::SystemTime::UNIX_EPOCH,
            not_after: std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(3600),
            key_usage: None,
            extended_key_usage: None,
            additional_extensions: Vec::new(),
        }
    }

    #[test]
    fn apply_response_replaces_and_adds_sans() {
        let mut c = base_customization();
        let resp = super::WebhookResponse {
            sans: Some(vec![san("a.example")]),
            additional_sans: vec![san("b.example"), san("a.example")],
            ..Default::default()
        };
        super::apply_response(&mut c, &resp).unwrap();
        assert_eq!(c.sans, vec![san("a.example"), san("b.example")]);
    }

    #[test]
    fn apply_response_overrides_subject_and_usages() {
        let mut c = base_customization();
        let resp = super::WebhookResponse {
            subject_common_name: Some("override.example".to_string()),
            key_usage: Some(vec![crate::template::KeyUsageName::DigitalSignature]),
            extended_key_usage: Some(vec![crate::template::ExtKeyUsageName::ClientAuth]),
            ..Default::default()
        };
        super::apply_response(&mut c, &resp).unwrap();
        assert_eq!(c.subject_common_name.as_deref(), Some("override.example"));
        assert!(c.key_usage.is_some());
        assert!(c.extended_key_usage.is_some());
    }

    #[test]
    fn apply_response_parses_raw_extension() {
        let mut c = base_customization();
        let resp = super::WebhookResponse {
            additional_extensions: vec![super::RawExtension {
                oid: "2.5.29.99".to_string(),
                value: vec![0x05, 0x00],
                critical: false,
            }],
            ..Default::default()
        };
        super::apply_response(&mut c, &resp).unwrap();
        assert_eq!(c.additional_extensions.len(), 1);
        assert_eq!(c.additional_extensions[0].extn_id.to_string(), "2.5.29.99");
    }

    #[test]
    fn response_deserializes_snake_case() {
        let json = r#"{
            "allow": true,
            "additional_sans": [{"type": "dns", "value": "x.example"}],
            "subject_common_name": "cn.example",
            "not_after": "2030-01-01T00:00:00Z"
        }"#;
        let resp: super::WebhookResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.allow, Some(true));
        assert_eq!(resp.additional_sans, vec![san("x.example")]);
        assert_eq!(resp.subject_common_name.as_deref(), Some("cn.example"));
        assert!(resp.not_after.is_some());
    }

    #[test]
    fn request_csr_der_round_trips_as_base64() {
        let req = super::WebhookRequest {
            timestamp: chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::UNIX_EPOCH),
            operation: super::Operation::Sign,
            provisioner: Some("acme".to_string()),
            subject: "example.com".to_string(),
            sans: vec![san("example.com")],
            csr_der: Some(vec![1, 2, 3, 4]),
            previous_certificate_der: None,
            not_before: chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::UNIX_EPOCH),
            not_after: chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::UNIX_EPOCH),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["operation"], "sign");
        assert_eq!(json["csr_der"], "AQIDBA==");
        assert!(json.get("previous_certificate_der").is_none());
        let back: super::WebhookRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back.csr_der, Some(vec![1, 2, 3, 4]));
    }
}
