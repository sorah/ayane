//! Webhook gating and enrichment across `sign` and `renew`.

use super::*;

/// A webhook that records the last request and replays a fixed sequence of
/// responses (clamping to the last once exhausted).
struct TestWebhook {
    responses: Vec<crate::webhook::WebhookResponse>,
    calls: std::sync::atomic::AtomicUsize,
    last_request: std::sync::Mutex<Option<crate::webhook::WebhookRequest>>,
}

impl TestWebhook {
    fn new(responses: Vec<crate::webhook::WebhookResponse>) -> std::sync::Arc<TestWebhook> {
        std::sync::Arc::new(TestWebhook {
            responses,
            calls: std::sync::atomic::AtomicUsize::new(0),
            last_request: std::sync::Mutex::new(None),
        })
    }

    fn call_count(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn last_request(&self) -> crate::webhook::WebhookRequest {
        self.last_request
            .lock()
            .unwrap()
            .clone()
            .expect("webhook was called")
    }
}

#[async_trait::async_trait]
impl crate::webhook::WebhookProvider for TestWebhook {
    fn name(&self) -> &str {
        "test"
    }

    fn applies_to(&self, _provisioner: Option<&str>) -> bool {
        true
    }

    async fn call(
        &self,
        request: &crate::webhook::WebhookRequest,
    ) -> crate::error::Result<crate::webhook::WebhookResponse> {
        *self.last_request.lock().unwrap() = Some(request.clone());
        let index = self
            .calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .min(self.responses.len() - 1);
        Ok(self.responses[index].clone())
    }
}

fn cert_not_after_unix(cert: &x509_cert::Certificate) -> i64 {
    cert.tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs() as i64
}

fn cert_san_strings(cert: &x509_cert::Certificate) -> Vec<String> {
    use const_oid::AssociatedOid;
    use der::Decode;
    let mut out = Vec::new();
    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts {
            if ext.extn_id == x509_cert::ext::pkix::SubjectAltName::OID {
                let san = x509_cert::ext::pkix::SubjectAltName::from_der(ext.extn_value.as_bytes())
                    .unwrap();
                for gn in san.0.iter() {
                    if let Ok(s) = crate::san::San::try_from(gn) {
                        out.push(s.to_string());
                    }
                }
            }
        }
    }
    out
}

#[tokio::test]
async fn webhook_enriches_sign_with_additional_san() {
    let webhook = TestWebhook::new(vec![crate::webhook::WebhookResponse {
        additional_sans: vec![crate::san::San::parse("extra.example")],
        ..Default::default()
    }]);
    let webhooks: Vec<std::sync::Arc<dyn crate::webhook::WebhookProvider>> = vec![webhook.clone()];
    let h = setup_with_webhooks(webhooks).await;
    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let issued = h
        .service
        .sign(
            ayane_protocol::SignRequest {
                csr: make_csr(&leaf, "host.example", &["host.example"]),
                token: make_token(
                    &h.provisioner_pem,
                    SIGN_URL,
                    "host.example",
                    &["host.example"],
                ),
                not_before: None,
                not_after: None,
            },
            SIGN_URL,
            None,
        )
        .await
        .expect("issue succeeds");

    let cert = crate::x509::certificate_from_pem(&issued.certificate).unwrap();
    let sans = cert_san_strings(&cert);
    assert!(sans.contains(&"host.example".to_string()));
    assert!(sans.contains(&"extra.example".to_string()));

    let request = webhook.last_request();
    assert_eq!(request.operation, crate::webhook::Operation::Sign);
    assert!(request.csr_der.is_some());
    assert!(request.previous_certificate_der.is_none());
}

#[tokio::test]
async fn webhook_denial_does_not_burn_token() {
    // Deny on the first call, permit on the second.
    let webhook = TestWebhook::new(vec![
        crate::webhook::WebhookResponse {
            allow: Some(false),
            deny_reason: Some("denied by policy".to_string()),
            ..Default::default()
        },
        crate::webhook::WebhookResponse::default(),
    ]);
    let webhooks: Vec<std::sync::Arc<dyn crate::webhook::WebhookProvider>> = vec![webhook.clone()];
    let h = setup_with_webhooks(webhooks).await;
    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let csr = make_csr(&leaf, "host.example", &["host.example"]);
    let token = make_token(
        &h.provisioner_pem,
        SIGN_URL,
        "host.example",
        &["host.example"],
    );
    let request = || ayane_protocol::SignRequest {
        csr: csr.clone(),
        token: token.clone(),
        not_before: None,
        not_after: None,
    };

    let err = h.service.sign(request(), SIGN_URL, None).await;
    assert!(matches!(err, Err(crate::error::Error::Forbidden(_))));

    // The denied attempt never claimed the one-time token, so retrying with the
    // same token succeeds once the webhook permits.
    let issued = h.service.sign(request(), SIGN_URL, None).await;
    assert!(issued.is_ok(), "token must survive a webhook denial");
    assert_eq!(webhook.call_count(), 2);
}

#[tokio::test]
async fn webhook_runs_on_renew_with_previous_certificate() {
    let webhook = TestWebhook::new(vec![crate::webhook::WebhookResponse::default()]);
    let webhooks: Vec<std::sync::Arc<dyn crate::webhook::WebhookProvider>> = vec![webhook.clone()];
    let h = setup_with_webhooks(webhooks).await;
    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let issued = h
        .service
        .sign(
            ayane_protocol::SignRequest {
                csr: make_csr(&leaf, "host.example", &["host.example"]),
                token: make_token(
                    &h.provisioner_pem,
                    SIGN_URL,
                    "host.example",
                    &["host.example"],
                ),
                not_before: None,
                not_after: None,
            },
            SIGN_URL,
            None,
        )
        .await
        .expect("issue succeeds");

    let renewed = h
        .service
        .renew(
            ayane_protocol::RenewRequest {
                certificate: issued.certificate.clone(),
            },
            Some(&make_dpop(&leaf, RENEW_URL)),
            RENEW_URL,
            None,
        )
        .await
        .expect("renew succeeds");
    assert_ne!(renewed.serial_number, issued.serial_number);

    // The webhook fired on both sign and renew; the renew call carried the
    // previous certificate and no CSR.
    assert_eq!(webhook.call_count(), 2);
    let request = webhook.last_request();
    assert_eq!(request.operation, crate::webhook::Operation::Renew);
    assert!(request.previous_certificate_der.is_some());
    assert!(request.csr_der.is_none());
}

#[tokio::test]
async fn webhook_cannot_extend_sign_past_template_max() {
    // The webhook demands a year-long certificate; the fallback template caps
    // validity at 24h, so issuance must re-clamp notAfter to the template max.
    let webhook = TestWebhook::new(vec![crate::webhook::WebhookResponse {
        not_after: Some(chrono::Utc::now() + chrono::Duration::days(365)),
        ..Default::default()
    }]);
    let webhooks: Vec<std::sync::Arc<dyn crate::webhook::WebhookProvider>> = vec![webhook.clone()];
    let h = setup_with_webhooks(webhooks).await;
    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let issued = h
        .service
        .sign(
            ayane_protocol::SignRequest {
                csr: make_csr(&leaf, "host.example", &["host.example"]),
                token: make_token(
                    &h.provisioner_pem,
                    SIGN_URL,
                    "host.example",
                    &["host.example"],
                ),
                not_before: None,
                not_after: None,
            },
            SIGN_URL,
            None,
        )
        .await
        .expect("issue succeeds");

    // Without the clamp the cert would last ~365 days; the 24h max + 60s
    // backdate ceiling keeps it far below a generous one-day-plus bound.
    let cert = crate::x509::certificate_from_pem(&issued.certificate).unwrap();
    assert!(
        cert_not_after_unix(&cert) <= unix_now() + 24 * 3600 + 120,
        "webhook notAfter must be clamped to the template max_validity"
    );
}

#[tokio::test]
async fn webhook_cannot_extend_renewal_past_original_lifetime() {
    // On reissue there is no template to clamp against; a webhook must not be
    // able to extend the renewed certificate beyond the previous lifetime.
    let webhook = TestWebhook::new(vec![
        crate::webhook::WebhookResponse::default(),
        crate::webhook::WebhookResponse {
            not_after: Some(chrono::Utc::now() + chrono::Duration::days(365)),
            ..Default::default()
        },
    ]);
    let webhooks: Vec<std::sync::Arc<dyn crate::webhook::WebhookProvider>> = vec![webhook.clone()];
    let h = setup_with_webhooks(webhooks).await;
    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let issued = h
        .service
        .sign(
            ayane_protocol::SignRequest {
                csr: make_csr(&leaf, "host.example", &["host.example"]),
                token: make_token(
                    &h.provisioner_pem,
                    SIGN_URL,
                    "host.example",
                    &["host.example"],
                ),
                not_before: None,
                not_after: None,
            },
            SIGN_URL,
            None,
        )
        .await
        .expect("issue succeeds");

    let renewed = h
        .service
        .renew(
            ayane_protocol::RenewRequest {
                certificate: issued.certificate.clone(),
            },
            Some(&make_dpop(&leaf, RENEW_URL)),
            RENEW_URL,
            None,
        )
        .await
        .expect("renew succeeds");

    let cert = crate::x509::certificate_from_pem(&renewed.certificate).unwrap();
    assert!(
        cert_not_after_unix(&cert) <= unix_now() + 24 * 3600 + 120,
        "webhook notAfter must be clamped to the original certificate lifetime"
    );
}
