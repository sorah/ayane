//! Audit event emission.
//!
//! Every authorization decision and certificate operation produces an
//! [`AuditEvent`], fanned out to the configured [`EventSink`]s (stdout, file,
//! AWS EventBridge). Emission is best-effort: a sink failure is logged but never
//! fails the certificate operation.

pub mod eventbridge;
pub mod file;
pub mod stdout;

/// Build one configured audit event sink.
///
/// AWS-backed sinks resolve their clients from the shared AWS configuration,
/// loaded lazily on first use.
pub async fn from_config(
    cfg: &crate::config::EventConfig,
) -> crate::error::Result<std::sync::Arc<dyn EventSink>> {
    match cfg {
        crate::config::EventConfig::Stdout => Ok(std::sync::Arc::new(
            crate::event_sink::stdout::StdoutSink::new(),
        ) as std::sync::Arc<dyn EventSink>),
        crate::config::EventConfig::File { path } => Ok(std::sync::Arc::new(
            crate::event_sink::file::FileSink::new(path.clone()).await?,
        ) as std::sync::Arc<dyn EventSink>),
        crate::config::EventConfig::EventBridge {
            event_bus_name,
            source,
            region,
        } => {
            let client = crate::event_sink::eventbridge::client(region.as_deref()).await;
            Ok(
                std::sync::Arc::new(crate::event_sink::eventbridge::EventBridgeSink::new(
                    client,
                    event_bus_name
                        .clone()
                        .unwrap_or_else(|| "default".to_string()),
                    source.clone().unwrap_or_else(|| "ayane".to_string()),
                )) as std::sync::Arc<dyn EventSink>,
            )
        }
    }
}

/// A structured audit record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEvent {
    /// Dotted event type, e.g. `"certificate.issued"`, `"certificate.revoked"`,
    /// `"authorization.denied"`.
    pub event_type: String,
    /// RFC 3339 timestamp.
    pub timestamp: String,
    /// `"success"`, `"denied"` or `"error"`.
    pub outcome: String,
    /// Provisioner involved, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisioner: Option<String>,
    /// Certificate subject, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Certificate serial number, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    /// Subject Alternative Names, if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sans: Vec<String>,
    /// Free-form detail (e.g. a denial reason).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Correlating request id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl AuditEvent {
    /// Build an event stamped with the current time.
    pub fn now(event_type: impl Into<String>, outcome: impl Into<String>) -> Self {
        AuditEvent {
            event_type: event_type.into(),
            timestamp: humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string(),
            outcome: outcome.into(),
            provisioner: None,
            subject: None,
            serial_number: None,
            sans: Vec::new(),
            detail: None,
            request_id: None,
        }
    }
}

/// A destination for audit events.
#[async_trait::async_trait]
pub trait EventSink: Send + Sync {
    /// Emit one event.
    async fn emit(&self, event: &AuditEvent) -> crate::error::Result<()>;
}
