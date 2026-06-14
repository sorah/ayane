//! HTTP(S) webhook transport with optional HMAC-SHA256 request signing.

/// An HTTP(S) webhook: POSTs the request JSON, optionally HMAC-signed and/or
/// bearer-authenticated, and parses the JSON reply.
pub struct HttpWebhook {
    name: String,
    provisioners: Vec<String>,
    url: String,
    hmac_key: Option<Vec<u8>>,
    bearer_token: Option<String>,
    client: reqwest::Client,
}

impl HttpWebhook {
    /// Build an HTTP webhook transport.
    ///
    /// `secret_b64` is the standard-base64 encoding of the HMAC-SHA256 key; a
    /// decode failure is reported as a configuration error. `timeout`, when set,
    /// bounds each request.
    pub fn new(
        name: String,
        provisioners: Vec<String>,
        url: String,
        secret_b64: Option<String>,
        bearer_token: Option<String>,
        timeout: Option<std::time::Duration>,
    ) -> crate::error::Result<HttpWebhook> {
        use base64::Engine;
        let hmac_key = match secret_b64 {
            Some(s) => Some(
                base64::engine::general_purpose::STANDARD
                    .decode(s.as_bytes())
                    .map_err(|e| {
                        crate::error::Error::Config(format!("webhook secret base64: {e}"))
                    })?,
            ),
            None => None,
        };
        let mut builder = reqwest::Client::builder();
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        let client = builder
            .build()
            .map_err(|e| crate::error::Error::Config(format!("webhook http client: {e}")))?;
        Ok(HttpWebhook {
            name,
            provisioners,
            url,
            hmac_key,
            bearer_token,
            client,
        })
    }

    /// Compute the lowercase hex HMAC-SHA256 of `body` under `key`.
    fn sign(key: &[u8], body: &[u8]) -> String {
        use hmac::Mac;
        type HmacSha256 = hmac::Hmac<sha2::Sha256>;
        let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }
}

#[async_trait::async_trait]
impl crate::webhook::WebhookProvider for HttpWebhook {
    fn name(&self) -> &str {
        &self.name
    }

    fn applies_to(&self, provisioner: Option<&str>) -> bool {
        if self.provisioners.is_empty() {
            return true;
        }
        match provisioner {
            Some(p) => self.provisioners.iter().any(|name| name == p),
            None => false,
        }
    }

    async fn call(
        &self,
        request: &crate::webhook::WebhookRequest,
    ) -> crate::error::Result<crate::webhook::WebhookResponse> {
        let body = serde_json::to_vec(request)
            .map_err(|e| crate::error::Error::Internal(format!("webhook request encode: {e}")))?;
        let mut builder = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json");
        if let Some(key) = &self.hmac_key {
            builder = builder.header("X-Ayane-Signature", HttpWebhook::sign(key, &body));
        }
        if let Some(token) = &self.bearer_token {
            builder = builder.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let resp = builder
            .body(body)
            .send()
            .await
            .map_err(|e| crate::error::Error::Internal(format!("webhook request: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(crate::error::Error::Internal(format!(
                "webhook {} returned HTTP {}",
                self.name, status
            )));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| crate::error::Error::Internal(format!("webhook response body: {e}")))?;
        serde_json::from_slice::<crate::webhook::WebhookResponse>(&bytes)
            .map_err(|e| crate::error::Error::Internal(format!("webhook response decode: {e}")))
    }
}

#[cfg(test)]
mod tests {
    fn sample_request() -> crate::webhook::WebhookRequest {
        crate::webhook::WebhookRequest {
            timestamp: "2026-06-14T00:00:00Z".parse().unwrap(),
            operation: crate::webhook::Operation::Sign,
            provisioner: Some("acme".to_string()),
            subject: "example.com".to_string(),
            sans: vec!["example.com".to_string(), "www.example.com".to_string()],
            csr_der: None,
            previous_certificate_der: None,
            not_before: "2026-06-14T00:00:00Z".parse().unwrap(),
            not_after: "2026-09-14T00:00:00Z".parse().unwrap(),
        }
    }

    fn webhook(provisioners: Vec<String>) -> super::HttpWebhook {
        super::HttpWebhook::new(
            "test".to_string(),
            provisioners,
            "https://webhook.invalid/hook".to_string(),
            None,
            None,
            None,
        )
        .expect("construct webhook")
    }

    #[test]
    fn applies_to_empty_matches_all() {
        use crate::webhook::WebhookProvider;
        let w = webhook(vec![]);
        assert!(w.applies_to(Some("anything")));
        assert!(w.applies_to(None));
    }

    #[test]
    fn applies_to_filters_by_provisioner() {
        use crate::webhook::WebhookProvider;
        let w = webhook(vec!["acme".to_string(), "jwk".to_string()]);
        assert!(w.applies_to(Some("acme")));
        assert!(w.applies_to(Some("jwk")));
        assert!(!w.applies_to(Some("other")));
        assert!(!w.applies_to(None));
    }

    #[test]
    fn invalid_secret_base64_is_config_error() {
        let result = super::HttpWebhook::new(
            "test".to_string(),
            vec![],
            "https://webhook.invalid/hook".to_string(),
            Some("not valid base64!!!".to_string()),
            None,
            None,
        );
        assert!(matches!(result, Err(crate::error::Error::Config(_))));
    }

    #[test]
    fn hmac_signature_is_deterministic_and_well_formed() {
        let key = b"secret-key";
        let body = b"{\"hello\":\"world\"}";
        let sig = super::HttpWebhook::sign(key, body);
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(sig, super::HttpWebhook::sign(key, body));
    }

    #[test]
    fn hmac_signature_matches_reference_vector() {
        // RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
        let sig = super::HttpWebhook::sign(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            sig,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn request_serializes_to_expected_shape() {
        let json = serde_json::to_value(sample_request()).expect("serialize");
        assert_eq!(json["operation"], "sign");
        assert_eq!(json["provisioner"], "acme");
        assert_eq!(json["subject"], "example.com");
        assert_eq!(json["sans"][1], "www.example.com");
        assert_eq!(json["not_after"], "2026-09-14T00:00:00Z");
        // csr_der is skipped when None.
        assert!(json.get("csr_der").is_none());
    }
}
