//! Hook gating and enrichment across `sign` and `renew`.

use super::*;

/// A hook that records the last request and replays a fixed sequence of
/// responses (clamping to the last once exhausted).
struct TestHook {
    responses: Vec<crate::hook::HookResponse>,
    calls: std::sync::atomic::AtomicUsize,
    last_request: std::sync::Mutex<Option<crate::hook::HookRequest>>,
}

impl TestHook {
    fn new(responses: Vec<crate::hook::HookResponse>) -> std::sync::Arc<TestHook> {
        std::sync::Arc::new(TestHook {
            responses,
            calls: std::sync::atomic::AtomicUsize::new(0),
            last_request: std::sync::Mutex::new(None),
        })
    }

    fn call_count(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn last_request(&self) -> crate::hook::HookRequest {
        self.last_request
            .lock()
            .unwrap()
            .clone()
            .expect("hook was called")
    }
}

#[async_trait::async_trait]
impl crate::hook::HookProvider for TestHook {
    fn name(&self) -> &str {
        "test"
    }

    fn applies_to(&self, _provisioner: Option<&str>) -> bool {
        true
    }

    async fn call(
        &self,
        request: &crate::hook::HookRequest,
    ) -> crate::error::Result<crate::hook::HookResponse> {
        *self.last_request.lock().unwrap() = Some(request.clone());
        let index = self
            .calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .min(self.responses.len() - 1);
        Ok(self.responses[index].clone())
    }
}

#[tokio::test]
async fn hook_enriches_sign_with_additional_san() {
    let hook = TestHook::new(vec![crate::hook::HookResponse {
        additional_sans: vec![crate::san::San::parse("extra.example")],
        ..Default::default()
    }]);
    let hooks: Vec<std::sync::Arc<dyn crate::hook::HookProvider>> = vec![hook.clone()];
    let h = setup_with_hooks(hooks).await;
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

    let request = hook.last_request();
    assert_eq!(request.operation, crate::hook::Operation::Sign);
    assert!(request.csr_der.is_some());
    assert!(request.previous_certificate_der.is_none());
}

#[tokio::test]
async fn hook_denial_does_not_burn_token() {
    // Deny on the first call, permit on the second.
    let hook = TestHook::new(vec![
        crate::hook::HookResponse {
            allow: Some(false),
            deny_reason: Some("denied by policy".to_string()),
            ..Default::default()
        },
        crate::hook::HookResponse::default(),
    ]);
    let hooks: Vec<std::sync::Arc<dyn crate::hook::HookProvider>> = vec![hook.clone()];
    let h = setup_with_hooks(hooks).await;
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
    // same token succeeds once the hook permits.
    let issued = h.service.sign(request(), SIGN_URL, None).await;
    assert!(issued.is_ok(), "token must survive a hook denial");
    assert_eq!(hook.call_count(), 2);
}

#[tokio::test]
async fn hook_runs_on_renew_with_previous_certificate() {
    let hook = TestHook::new(vec![crate::hook::HookResponse::default()]);
    let hooks: Vec<std::sync::Arc<dyn crate::hook::HookProvider>> = vec![hook.clone()];
    let h = setup_with_hooks(hooks).await;
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

    // The hook fired on both sign and renew; the renew call carried the
    // previous certificate and no CSR.
    assert_eq!(hook.call_count(), 2);
    let request = hook.last_request();
    assert_eq!(request.operation, crate::hook::Operation::Renew);
    assert!(request.previous_certificate_der.is_some());
    assert!(request.csr_der.is_none());
}

#[tokio::test]
async fn hook_cannot_extend_sign_past_template_max() {
    // The hook demands a year-long certificate; the fallback template caps
    // validity at 24h, so issuance must re-clamp notAfter to the template max.
    let hook = TestHook::new(vec![crate::hook::HookResponse {
        not_after: Some(chrono::Utc::now() + chrono::Duration::days(365)),
        ..Default::default()
    }]);
    let hooks: Vec<std::sync::Arc<dyn crate::hook::HookProvider>> = vec![hook.clone()];
    let h = setup_with_hooks(hooks).await;
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
        "hook notAfter must be clamped to the template max_validity"
    );
}

#[tokio::test]
async fn unauthorized_provisioner_denied_without_hook_allow() {
    // A silent hook does not grant an unauthorized provisioner.
    let hook = TestHook::new(vec![crate::hook::HookResponse::default()]);
    let hooks: Vec<std::sync::Arc<dyn crate::hook::HookProvider>> = vec![hook.clone()];
    let h = setup_with_hooks_authorized(Some(false), hooks).await;
    let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let err = h
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
        .await;
    assert!(matches!(err, Err(crate::error::Error::Forbidden(_))));
}

#[tokio::test]
async fn unauthorized_provisioner_issues_when_hook_allows() {
    let hook = TestHook::new(vec![crate::hook::HookResponse {
        allow: Some(true),
        ..Default::default()
    }]);
    let hooks: Vec<std::sync::Arc<dyn crate::hook::HookProvider>> = vec![hook.clone()];
    let h = setup_with_hooks_authorized(Some(false), hooks).await;
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
        .expect("issue succeeds once the hook authorizes");

    let cert = crate::x509::certificate_from_pem(&issued.certificate).unwrap();
    assert!(cert_san_strings(&cert).contains(&"host.example".to_string()));
}

#[tokio::test]
async fn hook_once_scope_limits_issuance_to_one_per_scope() {
    // A hook that pins issuance to a backing instance id: at most one
    // certificate per that id.
    let hook = TestHook::new(vec![crate::hook::HookResponse {
        once: vec![crate::hook::OnceScope {
            scope: "i-0abc".to_string(),
            expires_at: None,
        }],
        ..Default::default()
    }]);
    let hooks: Vec<std::sync::Arc<dyn crate::hook::HookProvider>> = vec![hook.clone()];
    let h = setup_with_hooks(hooks).await;

    let sign = async |h: &Harness| {
        let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
        h.service
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
    };

    sign(&h)
        .await
        .expect("first issuance for the instance succeeds");
    // A second, independent request (fresh token and key) for the same instance
    // is rejected as a replay of the scope.
    let replay = sign(&h).await;
    assert!(
        matches!(replay, Err(crate::error::Error::Unauthorized(_))),
        "second issuance for the same scope must be rejected"
    );
}

#[tokio::test]
async fn token_once_scope_limits_issuance_to_one_per_scope() {
    // The scope may instead be carried by the provisioner token itself.
    let h = setup().await;

    async fn sign(
        h: &Harness,
        scope: &str,
    ) -> crate::error::Result<ayane_protocol::CertificateResponse> {
        let leaf = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let token = make_token_with_once(
            &h.provisioner_pem,
            SIGN_URL,
            "host.example",
            ayane_protocol::OnceScope {
                scope: scope.to_string(),
                exp: None,
            },
        );
        h.service
            .sign(
                ayane_protocol::SignRequest {
                    csr: make_csr(&leaf, "host.example", &["host.example"]),
                    token,
                    not_before: None,
                    not_after: None,
                },
                SIGN_URL,
                None,
            )
            .await
    }

    sign(&h, "i-1")
        .await
        .expect("first issuance for i-1 succeeds");
    let replay = sign(&h, "i-1").await;
    assert!(
        matches!(replay, Err(crate::error::Error::Unauthorized(_))),
        "second issuance for i-1 must be rejected as a replay"
    );
    sign(&h, "i-2")
        .await
        .expect("a distinct scope value still issues");
}

#[tokio::test]
async fn hook_cannot_extend_renewal_past_original_lifetime() {
    // On reissue there is no template to clamp against; a hook must not be
    // able to extend the renewed certificate beyond the previous lifetime.
    let hook = TestHook::new(vec![
        crate::hook::HookResponse::default(),
        crate::hook::HookResponse {
            not_after: Some(chrono::Utc::now() + chrono::Duration::days(365)),
            ..Default::default()
        },
    ]);
    let hooks: Vec<std::sync::Arc<dyn crate::hook::HookProvider>> = vec![hook.clone()];
    let h = setup_with_hooks(hooks).await;
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
        "hook notAfter must be clamped to the original certificate lifetime"
    );
}
