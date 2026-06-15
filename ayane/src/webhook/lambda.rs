//! AWS Lambda webhook transport (synchronous invocation).

/// Build a Lambda client from the shared AWS configuration, applying an optional
/// region override.
pub(crate) async fn client(region: Option<&str>) -> aws_sdk_lambda::Client {
    let mut builder = aws_sdk_lambda::config::Builder::from(crate::aws::shared_config().await);
    if let Some(region) = region {
        builder = builder.region(aws_sdk_lambda::config::Region::new(region.to_string()));
    }
    aws_sdk_lambda::Client::from_conf(builder.build())
}

/// A Lambda-backed webhook: invokes a function synchronously with the request
/// JSON as the payload and decodes the returned payload as the reply.
pub struct LambdaWebhook {
    name: String,
    provisioners: Vec<String>,
    client: aws_sdk_lambda::Client,
    function_name: String,
}

impl LambdaWebhook {
    /// Build a Lambda webhook transport over an already-configured client.
    pub fn new(
        name: String,
        provisioners: Vec<String>,
        client: aws_sdk_lambda::Client,
        function_name: String,
    ) -> LambdaWebhook {
        LambdaWebhook {
            name,
            provisioners,
            client,
            function_name,
        }
    }
}

#[async_trait::async_trait]
impl crate::webhook::WebhookProvider for LambdaWebhook {
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
        let payload = serde_json::to_vec(request)
            .map_err(|e| crate::error::Error::Internal(format!("webhook request encode: {e}")))?;
        let resp = self
            .client
            .invoke()
            .function_name(&self.function_name)
            .invocation_type(aws_sdk_lambda::types::InvocationType::RequestResponse)
            .payload(aws_smithy_types::Blob::new(payload))
            .send()
            .await
            .map_err(|e| crate::error::Error::Internal(format!("lambda invoke: {e}")))?;
        let status = resp.status_code();
        if !(200..300).contains(&status) {
            return Err(crate::error::Error::Internal(format!(
                "lambda invoke returned status {status}"
            )));
        }
        if let Some(err) = resp.function_error() {
            return Err(crate::error::Error::Internal(format!(
                "lambda webhook error: {err}"
            )));
        }
        let body = resp
            .payload()
            .ok_or_else(|| crate::error::Error::Internal("empty lambda response".into()))?;
        serde_json::from_slice::<crate::webhook::WebhookResponse>(body.as_ref())
            .map_err(|e| crate::error::Error::Internal(format!("webhook response decode: {e}")))
    }
}

#[cfg(test)]
mod tests {
    fn sample_request() -> crate::webhook::WebhookRequest {
        crate::webhook::WebhookRequest {
            timestamp: "2026-06-14T00:00:00Z".parse().unwrap(),
            operation: crate::webhook::Operation::Sign,
            provisioner: None,
            subject: "example.com".to_string(),
            sans: vec![crate::san::San::parse("example.com")],
            csr_der: None,
            previous_certificate_der: None,
            not_before: "2026-06-14T00:00:00Z".parse().unwrap(),
            not_after: "2026-09-14T00:00:00Z".parse().unwrap(),
        }
    }

    fn webhook(client: aws_sdk_lambda::Client, provisioners: Vec<String>) -> super::LambdaWebhook {
        super::LambdaWebhook::new(
            "test".to_string(),
            provisioners,
            client,
            "ayane-webhook".to_string(),
        )
    }

    #[test]
    fn applies_to_filters_by_provisioner() {
        use crate::webhook::WebhookProvider;
        let dummy = aws_sdk_lambda::Client::from_conf(
            aws_sdk_lambda::Config::builder()
                .behavior_version(aws_sdk_lambda::config::BehaviorVersion::latest())
                .region(aws_sdk_lambda::config::Region::new("us-east-1"))
                .build(),
        );
        let w = webhook(dummy, vec!["acme".to_string()]);
        assert!(w.applies_to(Some("acme")));
        assert!(!w.applies_to(Some("other")));
        assert!(!w.applies_to(None));
    }

    #[tokio::test]
    async fn call_decodes_allow_response() {
        use crate::webhook::WebhookProvider;
        let payload = serde_json::to_vec(&serde_json::json!({"allow": true})).unwrap();
        let rule = aws_smithy_mocks::mock!(aws_sdk_lambda::Client::invoke)
            .match_requests(|req| req.function_name() == Some("ayane-webhook"))
            .then_output(move || {
                aws_sdk_lambda::operation::invoke::InvokeOutput::builder()
                    .status_code(200)
                    .payload(aws_smithy_types::Blob::new(payload.clone()))
                    .build()
            });
        let client = aws_smithy_mocks::mock_client!(
            aws_sdk_lambda,
            aws_smithy_mocks::RuleMode::MatchAny,
            [&rule]
        );
        let w = webhook(client, vec![]);
        let resp = w.call(&sample_request()).await.expect("call succeeds");
        assert_eq!(resp.allow, Some(true));
    }

    #[tokio::test]
    async fn call_propagates_function_error() {
        use crate::webhook::WebhookProvider;
        let payload = serde_json::to_vec(&serde_json::json!({"errorMessage": "boom"})).unwrap();
        let rule = aws_smithy_mocks::mock!(aws_sdk_lambda::Client::invoke).then_output(move || {
            aws_sdk_lambda::operation::invoke::InvokeOutput::builder()
                .status_code(200)
                .function_error("Unhandled")
                .payload(aws_smithy_types::Blob::new(payload.clone()))
                .build()
        });
        let client = aws_smithy_mocks::mock_client!(
            aws_sdk_lambda,
            aws_smithy_mocks::RuleMode::MatchAny,
            [&rule]
        );
        let w = webhook(client, vec![]);
        let err = w.call(&sample_request()).await.expect_err("function error");
        assert!(matches!(err, crate::error::Error::Internal(_)));
    }
}
