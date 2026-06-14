//! An [`EventSink`](crate::event_sink::EventSink) that writes one compact JSON line
//! per event to standard output.

/// Emits audit events as compact JSON lines on stdout.
#[derive(Debug, Default)]
pub struct StdoutSink;

impl StdoutSink {
    /// Construct a new stdout sink.
    pub fn new() -> StdoutSink {
        StdoutSink
    }
}

#[async_trait::async_trait]
impl crate::event_sink::EventSink for StdoutSink {
    async fn emit(&self, event: &crate::event_sink::AuditEvent) -> crate::error::Result<()> {
        let line = serde_json::to_string(event)?;
        println!("{line}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn emits_without_error() {
        use crate::event_sink::EventSink;

        let sink = super::StdoutSink::new();
        let event = crate::event_sink::AuditEvent::now("certificate.issued", "success");
        sink.emit(&event).await.unwrap();
    }

    #[test]
    fn default_constructs() {
        let _sink: super::StdoutSink = Default::default();
    }
}
