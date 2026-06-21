//! Request orchestration: the glue that turns an authenticated request into a
//! certificate, applying SAN policy, webhooks, anti-replay and audit events.
//!
//! [`Service`] owns the live providers and exposes one method per HTTP
//! operation. Each method returns wire types from [`ayane_protocol`]; the HTTP
//! layer is a thin adapter over it.

/// Slack added to anti-replay record lifetimes so a `jti` stays on the denylist
/// for at least as long as the validator would still accept the credential
/// (mirrors the authorizer/DPoP clock-skew leeway).
const REPLAY_LEEWAY: std::time::Duration = std::time::Duration::from_secs(60);

/// The assembled certificate service.
pub struct Service {
    authorizer: std::sync::Arc<dyn crate::authorizer::Authorizer>,
    ca: std::sync::Arc<crate::ca::CertificateAuthority>,
    storage: std::sync::Arc<dyn crate::storage::Storage>,
    webhooks: Vec<std::sync::Arc<dyn crate::webhook::WebhookProvider>>,
    events: Vec<std::sync::Arc<dyn crate::event_sink::EventSink>>,
    templates: std::collections::HashMap<String, crate::template::CertificateTemplate>,
    default_template_name: Option<String>,
    fallback_template: crate::template::CertificateTemplate,
    dpop_max_age: std::time::Duration,
    roots_signature_ttl: std::time::Duration,
    external_url: Option<String>,
}

/// Builder inputs for assembling a [`Service`] from already-constructed parts.
pub struct ServiceParts {
    /// Token authorizer.
    pub authorizer: std::sync::Arc<dyn crate::authorizer::Authorizer>,
    /// The issuing CA.
    pub ca: std::sync::Arc<crate::ca::CertificateAuthority>,
    /// Revocation/anti-replay store.
    pub storage: std::sync::Arc<dyn crate::storage::Storage>,
    /// Issuance webhooks.
    pub webhooks: Vec<std::sync::Arc<dyn crate::webhook::WebhookProvider>>,
    /// Audit sinks.
    pub events: Vec<std::sync::Arc<dyn crate::event_sink::EventSink>>,
    /// Named templates.
    pub templates: std::collections::HashMap<String, crate::template::CertificateTemplate>,
    /// Default template name.
    pub default_template_name: Option<String>,
    /// Lifetime of each signed `/v1/roots` artifact.
    pub roots_signature_ttl: std::time::Duration,
    /// Public base URL, used to build an absolute same-origin `x5u` for the roots
    /// signature; when unset, a relative `x5u` is signed instead.
    pub external_url: Option<String>,
}

impl Service {
    /// Assemble a service from constructed parts.
    pub fn new(parts: ServiceParts) -> Self {
        Service {
            authorizer: parts.authorizer,
            ca: parts.ca,
            storage: parts.storage,
            webhooks: parts.webhooks,
            events: parts.events,
            templates: parts.templates,
            default_template_name: parts.default_template_name,
            fallback_template: crate::template::CertificateTemplate::default(),
            dpop_max_age: std::time::Duration::from_secs(300),
            roots_signature_ttl: parts.roots_signature_ttl,
            external_url: parts.external_url,
        }
    }

    /// The issuing CA, for self-issued serving TLS (`crate::tls`).
    pub fn ca(&self) -> std::sync::Arc<crate::ca::CertificateAuthority> {
        std::sync::Arc::clone(&self.ca)
    }

    /// `GET /v1/health`.
    pub fn health(&self) -> ayane_protocol::HealthResponse {
        ayane_protocol::HealthResponse {
            status: "ok".to_string(),
        }
    }

    /// `GET /v1/roots`.
    pub fn roots(&self) -> ayane_protocol::RootsResponse {
        ayane_protocol::RootsResponse {
            certificates: self.ca.roots_pem().to_vec(),
        }
    }

    /// The signer certificate chain served at `GET /v1/roots/signer-chain`, as a
    /// concatenated PEM bundle (leaf-first).
    pub fn signer_chain_pem(&self) -> String {
        self.ca.signer_chain_pem().concat()
    }

    /// `GET /v1/roots`, signed: the JSON body plus the RFC 9421 signature headers
    /// (memoized in storage for `roots_signature_ttl`).
    pub async fn signed_roots(&self) -> crate::error::Result<SignedRoots> {
        let body = serde_json::to_vec(&self.roots())
            .map_err(|e| crate::error::Error::Internal(format!("serialize roots: {e}")))?;
        let digest: [u8; 32] = {
            use sha2::Digest;
            sha2::Sha256::digest(&body).into()
        };
        let content_digest = ayane_protocol::httpsig::content_digest_header(&digest);
        // Salt the cache key with the body so any roots/chain/config change misses
        // the cache and re-signs (its digest would otherwise not match the body).
        let cache_key = format!("roots-sig:v1:{}", hex::encode(digest));

        let now = std::time::SystemTime::now();
        let now_secs = unix_secs(now);
        let refresh_margin =
            (self.roots_signature_ttl / 4).min(std::time::Duration::from_secs(300));

        if let Some(cached) =
            crate::storage::cache_get::<CachedRootsSig>(self.storage.as_ref(), &cache_key).await?
            && now_secs + refresh_margin.as_secs() < cached.expires
        {
            return Ok(SignedRoots {
                body,
                content_type: ayane_protocol::httpsig::ROOTS_CONTENT_TYPE,
                content_digest,
                signature_input: cached.signature_input,
                signature: cached.signature,
                signature_key: cached.signature_key,
            });
        }

        let x5u = format!(
            "{}{}",
            self.external_url.as_deref().unwrap_or(""),
            ayane_protocol::httpsig::SIGNER_CHAIN_PATH
        );
        let x5t = ayane_protocol::httpsig::x5t_from_digest(self.ca.signer_leaf_sha256());
        let signature_key = ayane_protocol::httpsig::signature_key_x509(&x5u, &x5t);

        let created = now_secs;
        let expires = created + self.roots_signature_ttl.as_secs();
        let params = ayane_protocol::httpsig::RootsSigParams {
            created,
            expires,
            alg: self.ca.signing_algorithm().rfc9421_alg().to_string(),
        };
        let base = ayane_protocol::httpsig::roots_signature_base(
            200,
            ayane_protocol::httpsig::ROOTS_CONTENT_TYPE,
            &content_digest,
            &signature_key,
            &params,
        );
        let raw = self.ca.sign_http_message(base.as_bytes()).await?;
        let signature = ayane_protocol::httpsig::signature_header_value(&raw);
        let signature_input = ayane_protocol::httpsig::signature_input_value(&params);

        crate::storage::cache_set(
            self.storage.as_ref(),
            &cache_key,
            &CachedRootsSig {
                created,
                expires,
                signature_key: signature_key.clone(),
                signature: signature.clone(),
                signature_input: signature_input.clone(),
            },
            now + self.roots_signature_ttl,
        )
        .await?;

        Ok(SignedRoots {
            body,
            content_type: ayane_protocol::httpsig::ROOTS_CONTENT_TYPE,
            content_digest,
            signature_input,
            signature,
            signature_key,
        })
    }

    /// `GET /v1/provisioners`.
    pub fn provisioners(&self) -> ayane_protocol::ProvisionersResponse {
        ayane_protocol::ProvisionersResponse {
            provisioners: self.authorizer.provisioners(),
        }
    }

    fn resolve_template(
        &self,
        name: Option<&str>,
    ) -> crate::error::Result<&crate::template::CertificateTemplate> {
        match name.or(self.default_template_name.as_deref()) {
            Some(n) => self
                .templates
                .get(n)
                .ok_or_else(|| crate::error::Error::Config(format!("unknown template {n:?}"))),
            None => Ok(&self.fallback_template),
        }
    }

    async fn emit(&self, event: crate::event_sink::AuditEvent) {
        for sink in &self.events {
            if let Err(e) = sink.emit(&event).await {
                tracing::warn!(error = %e, sink_event = %event.event_type, "audit sink failed");
            }
        }
    }

    /// Atomically claim a one-time `jti`, namespaced by credential `kind`
    /// (`"ott"` vs `"dpop"`) so the two anti-replay spaces never collide. The
    /// `expires_at` is floored to outlive the validator's acceptance window.
    async fn claim_jti(
        &self,
        kind: &str,
        jti: &str,
        expires_at: std::time::SystemTime,
    ) -> crate::error::Result<()> {
        let key = format!("{kind}#{jti}");
        let floor = std::time::SystemTime::now() + REPLAY_LEEWAY;
        let expires_at = expires_at.max(floor);
        match self.storage.claim_token(&key, expires_at).await {
            Ok(()) => Ok(()),
            Err(crate::error::Error::Conflict(_)) => Err(crate::error::Error::Unauthorized(
                "token or proof has already been used".into(),
            )),
            Err(e) => Err(e),
        }
    }

    /// `POST /v1/sign`.
    pub async fn sign(
        &self,
        req: ayane_protocol::SignRequest,
        request_url: &str,
        request_id: Option<String>,
    ) -> crate::error::Result<ayane_protocol::CertificateResponse> {
        match self.try_sign(req, request_url, request_id.clone()).await {
            Ok((resp, event)) => {
                self.emit(event).await;
                Ok(resp)
            }
            Err(e) => {
                self.emit(denial("certificate.issued", &request_id, &e))
                    .await;
                Err(e)
            }
        }
    }

    async fn try_sign(
        &self,
        req: ayane_protocol::SignRequest,
        request_url: &str,
        request_id: Option<String>,
    ) -> crate::error::Result<(
        ayane_protocol::CertificateResponse,
        crate::event_sink::AuditEvent,
    )> {
        let csr = crate::csr::ParsedCsr::from_pem(&req.csr)?;
        csr.verify_signature()?;

        let validated = self.authorizer.validate(&req.token, request_url).await?;
        let claims = &validated.claims;

        // Optional CSR binding via the `cnf` confirmation claim.
        if let Some(cnf) = &claims.cnf
            && let Some(want) = &cnf.x5t_s256
            && *want != csr.fingerprint_b64url()
        {
            return Err(crate::error::Error::Forbidden(
                "token is bound to a different CSR".into(),
            ));
        }

        // SAN authorization: every requested SAN must be permitted by the token.
        let allowed = allowed_sans(claims);
        let mut requested = csr.requested_sans()?;
        if requested.is_empty() {
            requested = allowed.clone();
        }
        for san in &requested {
            if !allowed.contains(san) {
                return Err(crate::error::Error::Forbidden(format!(
                    "SAN {san} is not permitted by the token"
                )));
            }
        }

        let template = self.resolve_template(validated.template.as_deref())?;
        let now = std::time::SystemTime::now();
        let (not_before, not_after) = template.compute_validity(
            now,
            parse_rfc3339(&req.not_before)?,
            parse_rfc3339(&req.not_after)?,
        )?;

        let context = crate::webhook::Context {
            operation: crate::webhook::Operation::Sign,
            provisioner: Some(&validated.provisioner),
            subject: &claims.sub,
            sans: requested,
            not_before,
            not_after,
            csr_der: Some(&csr.der),
            previous_certificate_der: None,
        };
        let mut custom = crate::webhook::run(&self.webhooks, &context).await?;
        // A webhook may adjust the validity window, but must not extend issuance
        // past the template's configured maximum lifetime; re-clamp notAfter to
        // the template ceiling before the collapse check.
        if let Some(ceiling) = template.max_not_after(custom.not_before)
            && custom.not_after > ceiling
        {
            custom.not_after = ceiling;
        }
        if custom.not_after <= custom.not_before {
            return Err(crate::error::Error::Forbidden(
                "certificate validity window collapsed".into(),
            ));
        }

        // Claim the one-time token only after every check has passed and
        // issuance is about to commit, so a transient webhook/template failure
        // never burns a still-valid token. The TTL covers the validator leeway.
        self.claim_jti(
            "ott",
            &claims.jti,
            system_time_from_epoch(claims.exp) + REPLAY_LEEWAY,
        )
        .await?;

        let common_name = custom
            .subject_common_name
            .clone()
            .unwrap_or_else(|| claims.sub.clone());
        let san_strings: Vec<String> = custom.sans.iter().map(ToString::to_string).collect();
        let issued = self
            .ca
            .issue(crate::ca::IssueParams {
                common_name: common_name.clone(),
                sans: custom.sans,
                public_key: csr.public_key().clone(),
                not_before: custom.not_before,
                not_after: custom.not_after,
                template,
                key_usage_override: custom.key_usage,
                extended_key_usage_override: custom.extended_key_usage,
                additional_extensions: custom.additional_extensions,
            })
            .await?;

        // Fail-closed: the issued certificate is committed to the inventory
        // before it is returned, so the registry never misses an issuance.
        self.storage
            .record_certificate(crate::storage::CertificateRecord {
                serial_number: issued.serial_decimal.clone(),
                subject: common_name.clone(),
                sans: san_strings.clone(),
                not_before: rfc3339(custom.not_before),
                not_after: issued.not_after_rfc3339.clone(),
                issued_at: rfc3339(now),
                provisioner: Some(validated.provisioner.clone()),
                operation: "sign".to_string(),
                pem: issued.pem.clone(),
            })
            .await?;

        let mut event = crate::event_sink::AuditEvent::now("certificate.issued", "success");
        event.provisioner = Some(validated.provisioner);
        event.subject = Some(common_name);
        event.serial_number = Some(issued.serial_decimal.clone());
        event.sans = san_strings;
        event.request_id = request_id;

        Ok((self.certificate_response(issued), event))
    }

    /// `POST /v1/renew` (DPoP-authenticated, same key).
    pub async fn renew(
        &self,
        req: ayane_protocol::RenewRequest,
        dpop: Option<&str>,
        request_url: &str,
        request_id: Option<String>,
    ) -> crate::error::Result<ayane_protocol::CertificateResponse> {
        match self
            .try_renew_or_rekey(
                &req.certificate,
                None,
                dpop,
                request_url,
                request_id.clone(),
            )
            .await
        {
            Ok((resp, event)) => {
                self.emit(event).await;
                Ok(resp)
            }
            Err(e) => {
                self.emit(denial("certificate.renewed", &request_id, &e))
                    .await;
                Err(e)
            }
        }
    }

    /// `POST /v1/rekey` (DPoP-authenticated, new key from the CSR).
    pub async fn rekey(
        &self,
        req: ayane_protocol::RekeyRequest,
        dpop: Option<&str>,
        request_url: &str,
        request_id: Option<String>,
    ) -> crate::error::Result<ayane_protocol::CertificateResponse> {
        match self
            .try_renew_or_rekey(
                &req.certificate,
                Some(&req.csr),
                dpop,
                request_url,
                request_id.clone(),
            )
            .await
        {
            Ok((resp, event)) => {
                self.emit(event).await;
                Ok(resp)
            }
            Err(e) => {
                self.emit(denial("certificate.rekeyed", &request_id, &e))
                    .await;
                Err(e)
            }
        }
    }

    async fn try_renew_or_rekey(
        &self,
        certificate_pem: &str,
        new_csr_pem: Option<&str>,
        dpop: Option<&str>,
        request_url: &str,
        request_id: Option<String>,
    ) -> crate::error::Result<(
        ayane_protocol::CertificateResponse,
        crate::event_sink::AuditEvent,
    )> {
        let is_rekey = new_csr_pem.is_some();
        let event_type = if is_rekey {
            "certificate.rekeyed"
        } else {
            "certificate.renewed"
        };

        let dpop =
            dpop.ok_or_else(|| crate::error::Error::Unauthorized("missing DPoP proof".into()))?;
        let cert = crate::x509::certificate_from_pem(certificate_pem)?;
        self.ca.verify_issued(&cert)?;

        let serial = crate::ca::serial_to_decimal(cert.tbs_certificate.serial_number.as_bytes());
        if self.storage.get_revocation(&serial).await?.is_some() {
            return Err(crate::error::Error::Forbidden(
                "certificate is revoked".into(),
            ));
        }

        let now = std::time::SystemTime::now();
        let (cert_nb, cert_na) = cert_validity_window(&cert)?;
        if now >= cert_na {
            return Err(crate::error::Error::Forbidden(
                "certificate has expired and cannot be renewed".into(),
            ));
        }

        let proof = crate::dpop::verify(dpop, &cert, "POST", request_url, self.dpop_max_age, now)?;

        // New key for rekey (and prove possession of it); same key for renew.
        let (public_key, new_csr_der) = match new_csr_pem {
            Some(csr_pem) => {
                let new_csr = crate::csr::ParsedCsr::from_pem(csr_pem)?;
                new_csr.verify_signature()?;
                (new_csr.public_key().clone(), Some(new_csr.der))
            }
            None => (cert.tbs_certificate.subject_public_key_info.clone(), None),
        };

        // Baseline identity and validity are taken from the previous certificate
        // (same effective lifetime, preserved extensions); a webhook may then
        // customize them, or deny, before reissue.
        let baseline_subject =
            subject_common_name(&cert.tbs_certificate.subject).unwrap_or_default();
        let baseline_sans = cert_sans(&cert)?;
        let original_duration = cert_na
            .duration_since(cert_nb)
            .unwrap_or(std::time::Duration::from_secs(0));
        let not_after = now
            .checked_add(original_duration)
            .ok_or_else(|| crate::error::Error::Internal("renewal validity overflow".into()))?;

        let previous_certificate_der = {
            use der::Encode;
            cert.to_der()?
        };
        let context = crate::webhook::Context {
            operation: if is_rekey {
                crate::webhook::Operation::Rekey
            } else {
                crate::webhook::Operation::Renew
            },
            // Reissuance is not tied to a provisioner, so only webhooks that
            // apply to all provisioners are consulted here.
            provisioner: None,
            subject: &baseline_subject,
            sans: baseline_sans,
            not_before: now,
            not_after,
            csr_der: new_csr_der.as_deref(),
            previous_certificate_der: Some(&previous_certificate_der),
        };
        let mut custom = crate::webhook::run(&self.webhooks, &context).await?;
        // A reissue preserves the previous certificate's lifetime: a webhook may
        // shorten it but must not extend issuance beyond the baseline window
        // (there is no template to re-clamp against on reissue).
        if custom.not_after > not_after {
            custom.not_after = not_after;
        }
        if custom.not_after <= custom.not_before {
            return Err(crate::error::Error::Forbidden(
                "certificate validity window collapsed".into(),
            ));
        }

        // Claim the DPoP proof's jti only once issuance is about to commit, so a
        // webhook denial never burns an otherwise-valid proof.
        let proof_exp = proof.issued_at + self.dpop_max_age + REPLAY_LEEWAY;
        self.claim_jti("dpop", &proof.jti, proof_exp).await?;

        let subject = custom
            .subject_common_name
            .clone()
            .unwrap_or_else(|| baseline_subject.clone());
        let san_strings: Vec<String> = custom.sans.iter().map(ToString::to_string).collect();
        let issued = self
            .ca
            .reissue(crate::ca::ReissueParams {
                old: &cert,
                public_key,
                subject_common_name_override: custom.subject_common_name,
                sans: custom.sans,
                not_before: custom.not_before,
                not_after: custom.not_after,
                key_usage_override: custom.key_usage,
                extended_key_usage_override: custom.extended_key_usage,
                additional_extensions: custom.additional_extensions,
            })
            .await?;

        // Fail-closed: record the reissued certificate before returning it, so
        // the inventory captures every renew and rekey too (not tied to a
        // provisioner — these authenticate via DPoP).
        self.storage
            .record_certificate(crate::storage::CertificateRecord {
                serial_number: issued.serial_decimal.clone(),
                subject: subject.clone(),
                sans: san_strings.clone(),
                not_before: rfc3339(custom.not_before),
                not_after: issued.not_after_rfc3339.clone(),
                issued_at: rfc3339(now),
                provisioner: None,
                operation: if is_rekey { "rekey" } else { "renew" }.to_string(),
                pem: issued.pem.clone(),
            })
            .await?;

        let mut event = crate::event_sink::AuditEvent::now(event_type, "success");
        event.subject = if subject.is_empty() {
            None
        } else {
            Some(subject)
        };
        event.serial_number = Some(issued.serial_decimal.clone());
        event.sans = san_strings;
        event.request_id = request_id;

        Ok((self.certificate_response(issued), event))
    }

    /// `POST /v1/revoke`.
    pub async fn revoke(
        &self,
        req: ayane_protocol::RevokeRequest,
        dpop: Option<&str>,
        request_url: &str,
        request_id: Option<String>,
    ) -> crate::error::Result<ayane_protocol::RevokeResponse> {
        match self
            .try_revoke(req, dpop, request_url, request_id.clone())
            .await
        {
            Ok((resp, event)) => {
                self.emit(event).await;
                Ok(resp)
            }
            Err(e) => {
                self.emit(denial("certificate.revoked", &request_id, &e))
                    .await;
                Err(e)
            }
        }
    }

    async fn try_revoke(
        &self,
        req: ayane_protocol::RevokeRequest,
        dpop: Option<&str>,
        request_url: &str,
        request_id: Option<String>,
    ) -> crate::error::Result<(
        ayane_protocol::RevokeResponse,
        crate::event_sink::AuditEvent,
    )> {
        let serial = normalize_serial(&req.serial_number)?;
        let now = std::time::SystemTime::now();

        let provisioner = if let Some(token) = &req.token {
            let validated = self.authorizer.validate(token, request_url).await?;
            let token_serial = normalize_serial(&validated.claims.sub)?;
            if token_serial != serial {
                return Err(crate::error::Error::Forbidden(
                    "token does not authorize this serial number".into(),
                ));
            }
            self.claim_jti(
                "ott",
                &validated.claims.jti,
                system_time_from_epoch(validated.claims.exp) + REPLAY_LEEWAY,
            )
            .await?;
            Some(validated.provisioner)
        } else if let (Some(proof), Some(cert_pem)) = (dpop, &req.certificate) {
            let cert = crate::x509::certificate_from_pem(cert_pem)?;
            self.ca.verify_issued(&cert)?;
            let cert_serial =
                crate::ca::serial_to_decimal(cert.tbs_certificate.serial_number.as_bytes());
            if cert_serial != serial {
                return Err(crate::error::Error::Forbidden(
                    "DPoP certificate serial does not match the requested serial".into(),
                ));
            }
            let verified =
                crate::dpop::verify(proof, &cert, "POST", request_url, self.dpop_max_age, now)?;
            let proof_exp = verified.issued_at + self.dpop_max_age + REPLAY_LEEWAY;
            self.claim_jti("dpop", &verified.jti, proof_exp).await?;
            None
        } else {
            return Err(crate::error::Error::Unauthorized(
                "revocation requires a token, or a DPoP proof with the certificate".into(),
            ));
        };

        self.storage
            .revoke(crate::storage::RevocationRecord {
                serial_number: serial.clone(),
                reason_code: req.reason_code.unwrap_or(0),
                reason: req.reason.clone(),
                revoked_at: rfc3339(now),
                provisioner: provisioner.clone(),
            })
            .await?;

        let mut event = crate::event_sink::AuditEvent::now("certificate.revoked", "success");
        event.provisioner = provisioner;
        event.serial_number = Some(serial);
        event.detail = req.reason;
        event.request_id = request_id;

        Ok((
            ayane_protocol::RevokeResponse {
                status: "revoked".to_string(),
            },
            event,
        ))
    }

    fn certificate_response(
        &self,
        issued: crate::ca::IssuedCertificate,
    ) -> ayane_protocol::CertificateResponse {
        ayane_protocol::CertificateResponse {
            certificate: issued.pem,
            chain: self.ca.chain_pem().to_vec(),
            serial_number: issued.serial_decimal,
            not_after: issued.not_after_rfc3339,
        }
    }
}

/// The signed `GET /v1/roots` response: the exact JSON body plus the four
/// RFC 9421 signature header values to emit alongside it.
pub struct SignedRoots {
    /// Exact JSON body bytes (the same bytes that were digested and signed).
    pub body: Vec<u8>,
    /// `Content-Type` of the body.
    pub content_type: &'static str,
    /// `Content-Digest` header value.
    pub content_digest: String,
    /// `Signature-Input` header value.
    pub signature_input: String,
    /// `Signature` header value.
    pub signature: String,
    /// `Signature-Key` header value.
    pub signature_key: String,
}

/// The cached signature material for a roots body (everything but the body and
/// content-digest, which are recomputed deterministically each request).
#[derive(serde::Serialize, serde::Deserialize)]
struct CachedRootsSig {
    created: u64,
    expires: u64,
    signature_key: String,
    signature: String,
    signature_input: String,
}

fn unix_secs(t: std::time::SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn denial(
    event_type: &str,
    request_id: &Option<String>,
    error: &crate::error::Error,
) -> crate::event_sink::AuditEvent {
    let outcome = match error {
        crate::error::Error::Internal(_) | crate::error::Error::Config(_) => "error",
        _ => "denied",
    };
    let mut event = crate::event_sink::AuditEvent::now(event_type, outcome);
    event.detail = Some(error.to_string());
    event.request_id = request_id.clone();
    event
}

fn allowed_sans(claims: &ayane_protocol::OttClaims) -> Vec<crate::san::San> {
    if claims.sans.is_empty() {
        vec![crate::san::San::parse(&claims.sub)]
    } else {
        claims
            .sans
            .iter()
            .map(|s| crate::san::San::parse(s))
            .collect()
    }
}

fn system_time_from_epoch(epoch_secs: i64) -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::from_secs(epoch_secs.max(0) as u64)
}

fn rfc3339(t: std::time::SystemTime) -> String {
    humantime::format_rfc3339_seconds(t).to_string()
}

fn parse_rfc3339(s: &Option<String>) -> crate::error::Result<Option<std::time::SystemTime>> {
    match s {
        Some(s) => humantime::parse_rfc3339(s)
            .map(Some)
            .map_err(|e| crate::error::Error::BadRequest(format!("invalid timestamp {s:?}: {e}"))),
        None => Ok(None),
    }
}

/// Normalize a serial number string (decimal or `0x`-hex) to decimal.
fn normalize_serial(input: &str) -> crate::error::Result<String> {
    let trimmed = input.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        // Tolerate odd-length hex by left-padding a nibble.
        let padded = if hex.len() % 2 == 1 {
            format!("0{hex}")
        } else {
            hex.to_string()
        };
        let bytes = hex::decode(&padded)
            .map_err(|e| crate::error::Error::BadRequest(format!("invalid hex serial: {e}")))?;
        return Ok(crate::ca::serial_to_decimal(&bytes));
    }
    if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return Err(crate::error::Error::BadRequest(format!(
            "invalid serial number {input:?}"
        )));
    }
    Ok(trimmed.trim_start_matches('0').to_string())
        .map(|s: String| if s.is_empty() { "0".to_string() } else { s })
}

fn subject_common_name(name: &x509_cert::name::Name) -> Option<String> {
    for rdn in name.0.iter() {
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

fn cert_sans(cert: &x509_cert::Certificate) -> crate::error::Result<Vec<crate::san::San>> {
    use const_oid::AssociatedOid;
    use der::Decode;
    let mut out = Vec::new();
    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions {
            if ext.extn_id == x509_cert::ext::pkix::SubjectAltName::OID {
                let san = x509_cert::ext::pkix::SubjectAltName::from_der(ext.extn_value.as_bytes())
                    .map_err(|e| {
                        crate::error::Error::Internal(format!("decode SAN from certificate: {e}"))
                    })?;
                for gn in san.0.iter() {
                    if let Ok(s) = crate::san::San::try_from(gn) {
                        out.push(s);
                    }
                }
            }
        }
    }
    Ok(out)
}

fn cert_validity_window(
    cert: &x509_cert::Certificate,
) -> crate::error::Result<(std::time::SystemTime, std::time::SystemTime)> {
    let nb = cert.tbs_certificate.validity.not_before.to_system_time();
    let na = cert.tbs_certificate.validity.not_after.to_system_time();
    Ok((nb, na))
}

#[cfg(test)]
mod tests {
    #[test]
    fn normalize_serial_decimal_and_hex() {
        assert_eq!(super::normalize_serial("255").unwrap(), "255");
        assert_eq!(super::normalize_serial("0x0a").unwrap(), "10");
        assert_eq!(super::normalize_serial("0X100").unwrap(), "256");
        assert_eq!(super::normalize_serial("007").unwrap(), "7");
        assert!(super::normalize_serial("nope").is_err());
    }
}
