//! An [`EventSink`](crate::event_sink::EventSink) that appends one compact JSON line
//! per event to a file opened for the lifetime of the sink.

/// Appends audit events as compact JSON lines to a file.
///
/// The file is opened (creating it if absent) when the sink is constructed, and
/// every emission appends a single line under a mutex so that concurrent writes
/// do not interleave.
pub struct FileSink {
    file: tokio::sync::Mutex<tokio::fs::File>,
}

impl FileSink {
    /// Open (or create) `path` for appending and build a sink around it.
    pub async fn new(path: impl Into<std::path::PathBuf>) -> crate::error::Result<FileSink> {
        let path = path.into();
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .map_err(|e| {
                crate::error::Error::Internal(format!(
                    "failed to open audit file {}: {e}",
                    path.display()
                ))
            })?;
        Ok(FileSink {
            file: tokio::sync::Mutex::new(file),
        })
    }
}

#[async_trait::async_trait]
impl crate::event_sink::EventSink for FileSink {
    async fn emit(&self, event: &crate::event_sink::AuditEvent) -> crate::error::Result<()> {
        use tokio::io::AsyncWriteExt;

        let mut line = serde_json::to_string(event)?;
        line.push('\n');
        let mut file = self.file.lock().await;
        file.write_all(line.as_bytes()).await.map_err(|e| {
            crate::error::Error::Internal(format!("failed to write audit line: {e}"))
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn appends_json_lines() {
        use crate::event_sink::EventSink;

        let mut path = std::env::temp_dir();
        path.push(format!(
            "ayane-audit-test-{}-{}.jsonl",
            std::process::id(),
            humantime::format_rfc3339_nanos(std::time::SystemTime::now())
                .to_string()
                .replace(':', "-")
        ));

        let sink = super::FileSink::new(&path).await.unwrap();
        let mut first = crate::event_sink::AuditEvent::now("certificate.issued", "success");
        first.subject = Some("CN=one".to_string());
        let mut second = crate::event_sink::AuditEvent::now("authorization.denied", "denied");
        second.subject = Some("CN=two".to_string());
        sink.emit(&first).await.unwrap();
        sink.emit(&second).await.unwrap();
        drop(sink);

        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        tokio::fs::remove_file(&path).await.ok();

        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        let parsed_first: crate::event_sink::AuditEvent = serde_json::from_str(lines[0]).unwrap();
        let parsed_second: crate::event_sink::AuditEvent = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(parsed_first.subject.as_deref(), Some("CN=one"));
        assert_eq!(parsed_second.subject.as_deref(), Some("CN=two"));
        assert_eq!(parsed_second.outcome, "denied");
    }
}
