//! Issuance hooks: external services that gate and/or augment certificate
//! issuance, renewal and rekey.
//!
//! A single hook receives a typed description of the pending certificate and
//! replies with one typed [`HookResponse`]: it may deny the request
//! (`allow = false`) and/or customize the certificate (subject, SANs, validity,
//! key usages, or arbitrary extensions) from the same response — there is no
//! authorizing/enriching distinction. Transport is one of: HTTPS (optionally
//! HMAC-signed), a synchronous AWS Lambda invocation, or a local command fed
//! the request on stdin.
//!
//! Each applicable hook is invoked with the *original* request (it does not
//! observe an earlier hook's customization); their responses are layered onto
//! a [`Customization`] in configuration order, which the caller then turns into
//! the issued certificate.

pub mod exec;
pub mod http;
pub mod lambda;

/// The operation a hook is being consulted for.
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

/// The typed payload sent to a hook. Serialized as the HTTP/Lambda body.
#[serde_with::serde_as]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HookRequest {
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
    /// Whether the certificate is renewable so far (from the token, or the
    /// pre-hook default). A hook may only turn this off via
    /// [`HookResponse::renew`], never back on.
    pub renew: bool,
}

/// An arbitrary X.509 extension supplied by a hook.
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
                crate::error::Error::BadRequest(format!("hook extension OID {:?}: {e}", self.oid))
            })?;
        Ok(x509_cert::ext::Extension {
            extn_id,
            critical: self.critical,
            extn_value: der::asn1::OctetString::new(self.value.clone())
                .map_err(|e| crate::error::Error::Internal(format!("hook extension value: {e}")))?,
        })
    }
}

/// A once-per-scope anti-replay constraint asserted by a hook.
///
/// The hook variant of [`ayane_protocol::OnceScope`]: it makes issuance happen
/// at most once per [`scope`](Self::scope) until [`expires_at`](Self::expires_at),
/// namespaced to the asserting hook so distinct hooks never collide. Typical
/// use: an identity-verifying hook (e.g. one that validates an EC2 instance
/// identity document) pins issuance to the backing instance id.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OnceScope {
    /// The uniqueness value, e.g. a backing EC2 instance id.
    pub scope: String,
    /// Expiry of the scope claim. When omitted, the claim is held until the
    /// issued certificate's notAfter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// A resolved anti-replay claim to make before issuance, namespaced so that
/// scopes from different sources never collide. A `None` `expires_at` inherits
/// the issued certificate's notAfter at claim time.
pub struct OnceClaim {
    /// Namespace isolating this scope's keyspace, e.g. `"hook:aws-identity"`.
    pub namespace: String,
    /// The uniqueness value within the namespace.
    pub value: String,
    /// Absolute expiry, or `None` to default to the certificate notAfter.
    pub expires_at: Option<std::time::SystemTime>,
}

/// A hook's typed reply. Every field is optional: an absent field leaves the
/// corresponding certificate property at its pre-hook value.
#[serde_with::serde_as]
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct HookResponse {
    /// `Some(false)` denies the request; `Some(true)`/`None` permit it.
    pub allow: Option<bool>,
    /// `Some(false)` marks the issued certificate non-renewable (it can no
    /// longer be renewed or rekeyed). `Some(true)`/`None` leave renewability at
    /// its pre-hook value: a hook may disable renewal but not re-enable it.
    pub renew: Option<bool>,
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
    /// Anti-replay scopes to claim before issuance: the CA issues at most once
    /// per each `scope` until its `expires_at`. A conflict denies the request as
    /// a replay. Claimed only once every applicable hook has permitted the
    /// request, so a later denial never burns a scope.
    pub once: Vec<OnceScope>,
}

/// An invokable hook.
#[async_trait::async_trait]
pub trait HookProvider: Send + Sync {
    /// Hook name.
    fn name(&self) -> &str;

    /// Whether this hook applies to the named provisioner.
    fn applies_to(&self, provisioner: Option<&str>) -> bool;

    /// Invoke the hook.
    async fn call(&self, request: &HookRequest) -> crate::error::Result<HookResponse>;
}

/// Build one configured hook. Lambda hooks resolve their client from the
/// shared AWS configuration, loaded lazily on first use.
pub async fn from_config(
    cfg: &crate::config::HookConfig,
) -> crate::error::Result<std::sync::Arc<dyn HookProvider>> {
    match &cfg.target {
        crate::config::HookTarget::Http {
            url,
            secret,
            bearer_token,
        } => Ok(std::sync::Arc::new(crate::hook::http::HttpHook::new(
            cfg.name.clone(),
            cfg.provisioners.clone(),
            url.clone(),
            secret.clone(),
            bearer_token.clone(),
            cfg.timeout.map(crate::duration::ConfigDuration::get),
        )?) as std::sync::Arc<dyn HookProvider>),
        crate::config::HookTarget::Lambda {
            function_name,
            region,
        } => {
            let client = crate::hook::lambda::client(region.as_deref()).await;
            Ok(std::sync::Arc::new(crate::hook::lambda::LambdaHook::new(
                cfg.name.clone(),
                cfg.provisioners.clone(),
                client,
                function_name.clone(),
            )) as std::sync::Arc<dyn HookProvider>)
        }
        crate::config::HookTarget::Exec { command } => {
            Ok(std::sync::Arc::new(crate::hook::exec::ExecHook::new(
                cfg.name.clone(),
                cfg.provisioners.clone(),
                command.clone(),
                cfg.timeout.map(crate::duration::ConfigDuration::get),
            )?) as std::sync::Arc<dyn HookProvider>)
        }
    }
}

/// The inputs a hook is consulted with, owned by the caller.
pub struct Context<'a> {
    /// The operation being performed.
    pub operation: Operation,
    /// Whether the credential already authorizes issuance on its own. When
    /// `false`, [`run`] denies unless an applicable hook explicitly allows.
    pub authorized: bool,
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
    /// Baseline renewability: the token's `renew` claim on `sign`, or `true` on
    /// reissue. A hook may only tighten it to non-renewable.
    pub renewable: bool,
}

/// The effective certificate properties after applying hook responses,
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
    /// Anti-replay scopes accumulated from every applicable hook, each already
    /// namespaced to its asserting hook.
    pub once_claims: Vec<OnceClaim>,
    /// Effective renewability after applying hook responses. Starts at the
    /// baseline and latches to `false` once any hook disables it.
    pub renewable: bool,
}

/// Consult every applicable hook in order, layering their responses onto a
/// [`Customization`]. Returns [`crate::error::Error::Forbidden`] as soon as a
/// hook denies the request.
///
/// When [`ctx.authorized`](Context::authorized) is `false` the call is
/// *default-deny*: at least one applicable hook must explicitly grant it
/// (`allow == Some(true)`), otherwise issuance is forbidden. An authorized
/// request is *default-allow*: it proceeds unless a hook denies it.
pub async fn run(
    hooks: &[std::sync::Arc<dyn HookProvider>],
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
        once_claims: Vec::new(),
        renewable: ctx.renewable,
    };
    if hooks.is_empty() {
        return unauthorized_guard(ctx.authorized, false).map(|()| customization);
    }

    let request = HookRequest {
        timestamp: chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::now()),
        operation: ctx.operation,
        provisioner: ctx.provisioner.map(str::to_string),
        subject: ctx.subject.to_string(),
        sans: ctx.sans.clone(),
        csr_der: ctx.csr_der.map(<[u8]>::to_vec),
        previous_certificate_der: ctx.previous_certificate_der.map(<[u8]>::to_vec),
        not_before: chrono::DateTime::<chrono::Utc>::from(ctx.not_before),
        not_after: chrono::DateTime::<chrono::Utc>::from(ctx.not_after),
        renew: ctx.renewable,
    };

    let mut explicitly_allowed = false;
    for hook in hooks {
        if !hook.applies_to(ctx.provisioner) {
            continue;
        }
        let response = hook.call(&request).await?;
        if response.allow == Some(false) {
            let reason = response
                .deny_reason
                .unwrap_or_else(|| format!("issuance denied by hook {:?}", hook.name()));
            return Err(crate::error::Error::Forbidden(reason));
        }
        if response.allow == Some(true) {
            explicitly_allowed = true;
        }
        for scope in &response.once {
            customization.once_claims.push(OnceClaim {
                namespace: format!("hook:{}", hook.name()),
                value: scope.scope.clone(),
                expires_at: scope.expires_at.map(std::time::SystemTime::from),
            });
        }
        apply_response(&mut customization, &response)?;
    }
    unauthorized_guard(ctx.authorized, explicitly_allowed).map(|()| customization)
}

/// Enforce default-deny for an unauthorized credential: unless a hook
/// explicitly allowed it, the request is forbidden.
fn unauthorized_guard(authorized: bool, explicitly_allowed: bool) -> crate::error::Result<()> {
    if authorized || explicitly_allowed {
        Ok(())
    } else {
        Err(crate::error::Error::Forbidden(
            "issuance was not authorized by any hook".into(),
        ))
    }
}

/// Layer one hook response onto the accumulating customization.
fn apply_response(
    customization: &mut Customization,
    response: &HookResponse,
) -> crate::error::Result<()> {
    // Renewability is a one-way switch: a hook may disable it but never
    // re-enable one the token (or an earlier hook) already turned off.
    if response.renew == Some(false) {
        customization.renewable = false;
    }
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
            once_claims: Vec::new(),
            renewable: true,
        }
    }

    #[test]
    fn apply_response_replaces_and_adds_sans() {
        let mut c = base_customization();
        let resp = super::HookResponse {
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
        let resp = super::HookResponse {
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
        let resp = super::HookResponse {
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
        let resp: super::HookResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.allow, Some(true));
        assert_eq!(resp.additional_sans, vec![san("x.example")]);
        assert_eq!(resp.subject_common_name.as_deref(), Some("cn.example"));
        assert!(resp.not_after.is_some());
    }

    #[test]
    fn request_csr_der_round_trips_as_base64() {
        let req = super::HookRequest {
            timestamp: chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::UNIX_EPOCH),
            operation: super::Operation::Sign,
            provisioner: Some("acme".to_string()),
            subject: "example.com".to_string(),
            sans: vec![san("example.com")],
            csr_der: Some(vec![1, 2, 3, 4]),
            previous_certificate_der: None,
            not_before: chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::UNIX_EPOCH),
            not_after: chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::UNIX_EPOCH),
            renew: true,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["operation"], "sign");
        assert_eq!(json["csr_der"], "AQIDBA==");
        assert!(json.get("previous_certificate_der").is_none());
        let back: super::HookRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back.csr_der, Some(vec![1, 2, 3, 4]));
    }

    struct StubHook {
        provisioners: Vec<String>,
        response: super::HookResponse,
    }

    #[async_trait::async_trait]
    impl super::HookProvider for StubHook {
        fn name(&self) -> &str {
            "stub"
        }
        fn applies_to(&self, provisioner: Option<&str>) -> bool {
            if self.provisioners.is_empty() {
                return true;
            }
            matches!(provisioner, Some(p) if self.provisioners.iter().any(|n| n == p))
        }
        async fn call(
            &self,
            _request: &super::HookRequest,
        ) -> crate::error::Result<super::HookResponse> {
            Ok(self.response.clone())
        }
    }

    fn stub(
        provisioners: &[&str],
        response: super::HookResponse,
    ) -> std::sync::Arc<dyn super::HookProvider> {
        std::sync::Arc::new(StubHook {
            provisioners: provisioners.iter().map(|s| s.to_string()).collect(),
            response,
        })
    }

    fn allow() -> super::HookResponse {
        super::HookResponse {
            allow: Some(true),
            ..Default::default()
        }
    }

    fn deny() -> super::HookResponse {
        super::HookResponse {
            allow: Some(false),
            ..Default::default()
        }
    }

    fn ctx(authorized: bool) -> super::Context<'static> {
        super::Context {
            operation: super::Operation::Sign,
            authorized,
            provisioner: Some("p"),
            subject: "example.com",
            sans: vec![san("example.com")],
            not_before: std::time::SystemTime::UNIX_EPOCH,
            not_after: std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(3600),
            csr_der: None,
            previous_certificate_der: None,
            renewable: true,
        }
    }

    fn is_forbidden<T>(r: crate::error::Result<T>) -> bool {
        matches!(r, Err(crate::error::Error::Forbidden(_)))
    }

    #[tokio::test]
    async fn authorized_is_default_allow() {
        assert!(super::run(&[], &ctx(true)).await.is_ok());
        let silent = vec![stub(&[], super::HookResponse::default())];
        assert!(super::run(&silent, &ctx(true)).await.is_ok());
    }

    #[tokio::test]
    async fn authorized_still_honors_denial() {
        let hooks = vec![stub(&[], deny())];
        assert!(is_forbidden(super::run(&hooks, &ctx(true)).await));
    }

    #[tokio::test]
    async fn unauthorized_with_no_hook_is_denied() {
        assert!(is_forbidden(super::run(&[], &ctx(false)).await));
    }

    #[tokio::test]
    async fn unauthorized_requires_explicit_allow() {
        // A silent (default) response does not authorize an unauthorized request.
        let silent = vec![stub(&[], super::HookResponse::default())];
        assert!(is_forbidden(super::run(&silent, &ctx(false)).await));

        // An explicit allow does.
        let granting = vec![stub(&[], allow())];
        assert!(super::run(&granting, &ctx(false)).await.is_ok());
    }

    #[tokio::test]
    async fn unauthorized_denied_when_allowing_hook_does_not_apply() {
        // The only hook that would allow is scoped to a different provisioner.
        let scoped = vec![stub(&["other"], allow())];
        assert!(is_forbidden(super::run(&scoped, &ctx(false)).await));
    }
}
