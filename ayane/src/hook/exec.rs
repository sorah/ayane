//! Local-command hook transport: runs a subprocess with the request JSON on
//! stdin and decodes its stdout as the reply.

/// An exec hook: spawns a local command, writes the request JSON to its stdin,
/// and decodes its stdout as the reply. The command is run directly (no shell).
/// A non-zero exit, a spawn failure, or a timeout aborts issuance (fail closed);
/// stderr is inherited so the command's diagnostics reach ayane's logs.
pub struct ExecHook {
    name: String,
    provisioners: Vec<String>,
    command: Vec<String>,
    timeout: Option<std::time::Duration>,
}

impl ExecHook {
    /// Build an exec hook transport. `command` is the program followed by its
    /// arguments; an empty command is a configuration error. `timeout`, when
    /// set, bounds the whole call and kills the process on expiry.
    pub fn new(
        name: String,
        provisioners: Vec<String>,
        command: Vec<String>,
        timeout: Option<std::time::Duration>,
    ) -> crate::error::Result<ExecHook> {
        if command.is_empty() {
            return Err(crate::error::Error::Config(format!(
                "hook {name:?}: exec command must not be empty"
            )));
        }
        Ok(ExecHook {
            name,
            provisioners,
            command,
            timeout,
        })
    }

    /// Run the command with `body` on stdin, returning its stdout on success.
    async fn invoke(&self, body: Vec<u8>) -> crate::error::Result<Vec<u8>> {
        use tokio::io::AsyncWriteExt;
        let mut child = tokio::process::Command::new(&self.command[0])
            .args(&self.command[1..])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                crate::error::Error::Internal(format!(
                    "hook {}: spawn {:?}: {e}",
                    self.name, self.command[0]
                ))
            })?;

        let mut stdin = child.stdin.take().expect("stdin is piped");
        // Feed stdin and drain stdout concurrently: a large reply could fill the
        // stdout pipe and block the child before it finished reading stdin,
        // deadlocking a write-then-read sequence. Write errors (e.g. the command
        // never reads stdin) are non-fatal here — dropping `stdin` closes the
        // pipe, and the exit status below is the source of truth.
        let feed = async move {
            let _ = stdin.write_all(&body).await;
            let _ = stdin.shutdown().await;
        };
        let run = async {
            let (_, output) = tokio::join!(feed, child.wait_with_output());
            output
        };

        let output = match self.timeout {
            Some(timeout) => tokio::time::timeout(timeout, run).await.map_err(|_| {
                crate::error::Error::Internal(format!(
                    "hook {} timed out after {timeout:?}",
                    self.name
                ))
            })?,
            None => run.await,
        }
        .map_err(|e| crate::error::Error::Internal(format!("hook {}: wait: {e}", self.name)))?;

        if !output.status.success() {
            return Err(crate::error::Error::Internal(format!(
                "hook {} exited with {}",
                self.name, output.status
            )));
        }
        Ok(output.stdout)
    }
}

#[async_trait::async_trait]
impl crate::hook::HookProvider for ExecHook {
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
        request: &crate::hook::HookRequest,
    ) -> crate::error::Result<crate::hook::HookResponse> {
        let body = serde_json::to_vec(request)
            .map_err(|e| crate::error::Error::Internal(format!("hook request encode: {e}")))?;
        let stdout = self.invoke(body).await?;
        serde_json::from_slice::<crate::hook::HookResponse>(&stdout)
            .map_err(|e| crate::error::Error::Internal(format!("hook response decode: {e}")))
    }
}

#[cfg(test)]
mod tests {
    fn sample_request() -> crate::hook::HookRequest {
        crate::hook::HookRequest {
            timestamp: "2026-06-14T00:00:00Z".parse().unwrap(),
            operation: crate::hook::Operation::Sign,
            provisioner: Some("acme".to_string()),
            subject: "example.com".to_string(),
            sans: vec![crate::san::San::parse("example.com")],
            csr_der: None,
            previous_certificate_der: None,
            not_before: "2026-06-14T00:00:00Z".parse().unwrap(),
            not_after: "2026-09-14T00:00:00Z".parse().unwrap(),
            renew: true,
        }
    }

    fn hook(command: Vec<&str>, provisioners: Vec<String>) -> super::ExecHook {
        super::ExecHook::new(
            "test".to_string(),
            provisioners,
            command.into_iter().map(str::to_string).collect(),
            None,
        )
        .expect("construct hook")
    }

    #[test]
    fn empty_command_is_config_error() {
        let result = super::ExecHook::new("test".to_string(), vec![], vec![], None);
        assert!(matches!(result, Err(crate::error::Error::Config(_))));
    }

    #[test]
    fn applies_to_filters_by_provisioner() {
        use crate::hook::HookProvider;
        let w = hook(vec!["true"], vec!["acme".to_string()]);
        assert!(w.applies_to(Some("acme")));
        assert!(!w.applies_to(Some("other")));
        assert!(!w.applies_to(None));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn call_delivers_stdin_and_decodes_stdout() {
        use crate::hook::HookProvider;
        // grep exits 0 only if the request JSON (which contains the subject)
        // actually reached stdin; then a fixed allow reply is emitted.
        let w = hook(
            vec![
                "sh",
                "-c",
                "grep -q example.com && printf '{\"allow\": true}'",
            ],
            vec![],
        );
        let resp = w.call(&sample_request()).await.expect("call succeeds");
        assert_eq!(resp.allow, Some(true));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn nonzero_exit_is_error() {
        use crate::hook::HookProvider;
        let w = hook(vec!["sh", "-c", "exit 3"], vec![]);
        let err = w.call(&sample_request()).await.expect_err("nonzero exit");
        assert!(matches!(err, crate::error::Error::Internal(_)));
    }

    #[tokio::test]
    async fn missing_program_is_error() {
        use crate::hook::HookProvider;
        let w = hook(vec!["/nonexistent/ayane-hook-binary"], vec![]);
        let err = w.call(&sample_request()).await.expect_err("spawn failure");
        assert!(matches!(err, crate::error::Error::Internal(_)));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_kills_a_slow_command() {
        use crate::hook::HookProvider;
        let w = super::ExecHook::new(
            "test".to_string(),
            vec![],
            vec!["sleep".to_string(), "5".to_string()],
            Some(std::time::Duration::from_millis(100)),
        )
        .expect("construct hook");
        let err = w.call(&sample_request()).await.expect_err("times out");
        assert!(matches!(err, crate::error::Error::Internal(_)));
    }
}
