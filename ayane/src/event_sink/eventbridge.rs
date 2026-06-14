//! An [`EventSink`](crate::event_sink::EventSink) that publishes audit events to an
//! AWS EventBridge event bus.

/// Build an EventBridge client from the shared AWS configuration, applying an
/// optional region override.
pub(crate) async fn client(region: Option<&str>) -> aws_sdk_eventbridge::Client {
    let mut builder = aws_sdk_eventbridge::config::Builder::from(crate::aws::shared_config().await);
    if let Some(region) = region {
        builder = builder.region(aws_sdk_eventbridge::config::Region::new(region.to_string()));
    }
    aws_sdk_eventbridge::Client::from_conf(builder.build())
}

/// Publishes audit events to an EventBridge event bus via `PutEvents`.
///
/// Each event becomes one `PutEventsRequestEntry` whose `detail` is the
/// JSON-serialized [`AuditEvent`](crate::event_sink::AuditEvent).
pub struct EventBridgeSink {
    client: aws_sdk_eventbridge::Client,
    event_bus_name: String,
    source: String,
}

impl EventBridgeSink {
    /// Build a sink that publishes to `event_bus_name` with the given `source`.
    pub fn new(
        client: aws_sdk_eventbridge::Client,
        event_bus_name: String,
        source: String,
    ) -> EventBridgeSink {
        EventBridgeSink {
            client,
            event_bus_name,
            source,
        }
    }
}

#[async_trait::async_trait]
impl crate::event_sink::EventSink for EventBridgeSink {
    async fn emit(&self, event: &crate::event_sink::AuditEvent) -> crate::error::Result<()> {
        let detail = serde_json::to_string(event)?;
        let entry = aws_sdk_eventbridge::types::PutEventsRequestEntry::builder()
            .source(&self.source)
            .detail_type(&event.event_type)
            .detail(detail)
            .event_bus_name(&self.event_bus_name)
            .build();
        let resp = self
            .client
            .put_events()
            .entries(entry)
            .send()
            .await
            .map_err(|e| {
                crate::error::Error::Internal(format!("eventbridge put_events failed: {e}"))
            })?;
        let failed = resp.failed_entry_count();
        if failed > 0 {
            return Err(crate::error::Error::Internal(format!(
                "eventbridge put_events reported {failed} failed entries"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn emits_via_mocked_eventbridge() {
        use crate::event_sink::EventSink;

        let put =
            aws_smithy_mocks::mock!(aws_sdk_eventbridge::Client::put_events).then_output(|| {
                aws_sdk_eventbridge::operation::put_events::PutEventsOutput::builder()
                    .failed_entry_count(0)
                    .build()
            });
        let client = aws_smithy_mocks::mock_client!(
            aws_sdk_eventbridge,
            aws_smithy_mocks::RuleMode::MatchAny,
            [&put]
        );

        let sink =
            super::EventBridgeSink::new(client, "audit-bus".to_string(), "ayane.ca".to_string());
        let event = crate::event_sink::AuditEvent::now("certificate.issued", "success");
        sink.emit(&event).await.unwrap();
    }

    #[tokio::test]
    async fn errors_on_failed_entries() {
        use crate::event_sink::EventSink;

        let put =
            aws_smithy_mocks::mock!(aws_sdk_eventbridge::Client::put_events).then_output(|| {
                aws_sdk_eventbridge::operation::put_events::PutEventsOutput::builder()
                    .failed_entry_count(1)
                    .build()
            });
        let client = aws_smithy_mocks::mock_client!(
            aws_sdk_eventbridge,
            aws_smithy_mocks::RuleMode::MatchAny,
            [&put]
        );

        let sink =
            super::EventBridgeSink::new(client, "audit-bus".to_string(), "ayane.ca".to_string());
        let event = crate::event_sink::AuditEvent::now("certificate.issued", "success");
        let err = sink.emit(&event).await.unwrap_err();
        assert!(matches!(err, crate::error::Error::Internal(_)));
    }
}
