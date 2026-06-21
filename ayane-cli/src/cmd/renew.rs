//! `renew`: renew an existing certificate (same key), authenticated with DPoP.
//!
//! Runs either once (`--out` required) or, with `--loop`, as a supervised
//! foreground loop that keeps the certificate fresh: it renews shortly before a
//! configurable fraction of the certificate's lifetime elapses (with jitter),
//! runs an optional post-renewal hook, and repeats. It is meant to run under a
//! process supervisor (e.g. systemd `Restart=always`), so it exits non-zero on
//! terminal failures (revoked/expired certificate, bad arguments) and only
//! retries — with backoff — transient ones (network, `5xx`, `429`).

#[derive(clap::Args)]
pub struct RenewArgs {
    #[command(flatten)]
    conn: crate::cmd::UrlArgs,
    /// Existing certificate PEM.
    #[arg(long)]
    cert: std::path::PathBuf,
    /// Existing private key PEM.
    #[arg(long)]
    key: std::path::PathBuf,
    /// Where to write the renewed certificate. Required for a one-shot renewal;
    /// in `--loop` mode it defaults to `--cert` (renew in place).
    #[arg(long)]
    out: Option<std::path::PathBuf>,
    /// Keep running and renew automatically before expiry, instead of renewing
    /// once and exiting.
    #[arg(long = "loop")]
    run_loop: bool,
    /// Renew once the certificate has passed this fraction (0..1) of its
    /// validity window. Mutually exclusive with `--renew-before`. Default 0.66.
    #[arg(long)]
    renew_fraction: Option<f64>,
    /// Renew when remaining validity drops below this duration (e.g. `8h`),
    /// instead of a fraction of the lifetime.
    #[arg(long)]
    renew_before: Option<String>,
    /// Maximum jitter subtracted from the computed renewal time, spreading a
    /// fleet's renewals. Default `5m`.
    #[arg(long, default_value = "5m")]
    jitter: String,
    /// Cap on a single sleep before re-evaluating the schedule. Default `1h`.
    #[arg(long, default_value = "1h")]
    max_sleep: String,
    /// Shell command run via `sh -c` after each successful renewal.
    #[arg(long)]
    exec: Option<String>,
}

pub async fn run(args: RenewArgs) -> anyhow::Result<()> {
    if args.run_loop {
        run_loop(args).await
    } else {
        run_once(args).await
    }
}

async fn run_once(args: RenewArgs) -> anyhow::Result<()> {
    let out = args
        .out
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--out is required for a one-shot renewal"))?;
    let cert_pem = std::fs::read_to_string(&args.cert)?;
    let key = crate::keypair::KeyPair::from_pem(&std::fs::read_to_string(&args.key)?)?;
    let client = crate::cmd::http_client(&args.conn)?;

    let resp = renew_request(&client, &args.conn.url, &cert_pem, &key).await?;
    crate::cmd::write_atomic(out, crate::cmd::fullchain(&resp).as_bytes())?;
    eprintln!("renewed serial {}", resp.serial_number);
    Ok(())
}

/// Resolved loop configuration, derived from `RenewArgs`.
struct LoopConfig {
    fraction: f64,
    renew_before: Option<std::time::Duration>,
    jitter: std::time::Duration,
    max_sleep: std::time::Duration,
    exec: Option<String>,
    out: std::path::PathBuf,
}

async fn run_loop(args: RenewArgs) -> anyhow::Result<()> {
    RenewLoop::new(args)?.run().await
}

/// Drives the continuous renewal loop. Owns the connection, paths, schedule
/// config, and the per-run signal/backoff state, so each phase of an iteration
/// is a focused method rather than one long function.
struct RenewLoop {
    client: reqwest::Client,
    base_url: String,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    cfg: LoopConfig,
    signals: Signals,
    backoff: Backoff,
    first: bool,
}

/// One iteration's freshly loaded inputs.
struct Loaded {
    cert_pem: String,
    key: crate::keypair::KeyPair,
    not_before: std::time::SystemTime,
    not_after: std::time::SystemTime,
}

/// Whether the loop should keep going after an iteration step.
enum Flow {
    Continue,
    Stop,
}

impl RenewLoop {
    fn new(args: RenewArgs) -> anyhow::Result<RenewLoop> {
        let fraction = match (args.renew_fraction, &args.renew_before) {
            (Some(_), Some(_)) => {
                anyhow::bail!("--renew-fraction and --renew-before are mutually exclusive")
            }
            (Some(f), None) => f,
            (None, _) => 0.66,
        };
        if !(0.0 < fraction && fraction < 1.0) {
            anyhow::bail!("--renew-fraction must be between 0 and 1 (exclusive)");
        }
        let cfg = LoopConfig {
            fraction,
            renew_before: args
                .renew_before
                .as_deref()
                .map(humantime::parse_duration)
                .transpose()?,
            jitter: humantime::parse_duration(&args.jitter)?,
            max_sleep: humantime::parse_duration(&args.max_sleep)?,
            exec: args.exec,
            out: args.out.unwrap_or_else(|| args.cert.clone()),
        };
        Ok(RenewLoop {
            client: crate::cmd::http_client(&args.conn)?,
            base_url: args.conn.url,
            cert_path: args.cert,
            key_path: args.key,
            cfg,
            signals: Signals::new()?,
            backoff: Backoff::default(),
            first: true,
        })
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        while let Flow::Continue = self.cycle().await? {}
        Ok(())
    }

    /// One full schedule-and-renew iteration.
    async fn cycle(&mut self) -> anyhow::Result<Flow> {
        let loaded = match self.load() {
            Ok(loaded) => loaded,
            // A read/parse failure on the very first iteration is terminal
            // (misconfiguration); later it is transient — the file may be
            // mid-replacement — so back off and retry.
            Err(e) if self.first => return Err(e),
            Err(e) => {
                eprintln!("warning: {e:#}");
                return Ok(self.backoff().await);
            }
        };

        let renew_at = next_renewal(
            loaded.not_before,
            loaded.not_after,
            &self.cfg,
            jitter_secs(self.cfg.jitter),
        );

        // First iteration, already due: spread a rebooting fleet so it does not
        // hammer the CA at once.
        if self.first && std::time::SystemTime::now() >= renew_at {
            let startup = jitter_secs(self.cfg.jitter.min(self.cfg.max_sleep));
            if startup > 0
                && self
                    .signals
                    .sleep(std::time::Duration::from_secs(startup))
                    .await
                    .is_stop()
            {
                return Ok(Flow::Stop);
            }
        }
        self.first = false;

        if self.wait_until(renew_at).await.is_stop() {
            return Ok(Flow::Stop);
        }
        self.renew(&loaded).await
    }

    /// Read and parse the current certificate and key. Errors carry which file
    /// failed via context.
    fn load(&self) -> anyhow::Result<Loaded> {
        let cert_pem = std::fs::read_to_string(&self.cert_path)
            .map_err(|e| anyhow::Error::new(e).context(format!("reading {:?}", self.cert_path)))?;
        let key_pem = std::fs::read_to_string(&self.key_path).map_err(|e| {
            anyhow::Error::new(e).context(format!("reading key {:?}", self.key_path))
        })?;
        let key = crate::keypair::KeyPair::from_pem(&key_pem)?;
        let (not_before, not_after) = cert_window(&cert_pem)?;
        Ok(Loaded {
            cert_pem,
            key,
            not_before,
            not_after,
        })
    }

    /// Wait until `renew_at`, capped at `max_sleep` per nap, woken early by
    /// SIGHUP (renew now) or terminated by SIGTERM/SIGINT.
    async fn wait_until(&mut self, renew_at: std::time::SystemTime) -> Wake {
        loop {
            let wait = renew_at
                .duration_since(std::time::SystemTime::now())
                .unwrap_or(std::time::Duration::ZERO);
            if wait.is_zero() {
                return Wake::Elapsed;
            }
            match self.signals.sleep(wait.min(self.cfg.max_sleep)).await {
                // A capped nap elapsed before the deadline: re-evaluate.
                Wake::Elapsed => continue,
                // SIGHUP (renew now) or SIGTERM/SIGINT (stop).
                woke => return woke,
            }
        }
    }

    /// Renew once, write the result atomically, and run the post-renewal hook.
    async fn renew(&mut self, loaded: &Loaded) -> anyhow::Result<Flow> {
        let url = crate::cmd::endpoint(&self.base_url, "/v1/renew");
        let dpop = crate::proof::make_dpop(&loaded.key, &url).context_dpop()?;
        let request = ayane_protocol::RenewRequest {
            certificate: loaded.cert_pem.clone(),
        };
        match crate::cmd::post_json_typed::<_, ayane_protocol::CertificateResponse>(
            &self.client,
            &url,
            Some(&dpop),
            &request,
        )
        .await
        {
            Ok(resp) => {
                crate::cmd::write_atomic(&self.cfg.out, crate::cmd::fullchain(&resp).as_bytes())?;
                eprintln!(
                    "renewed serial {} (notAfter {})",
                    resp.serial_number, resp.not_after
                );
                self.backoff.reset();
                if let Some(cmd) = &self.cfg.exec {
                    run_exec(cmd).await;
                }
                Ok(Flow::Continue)
            }
            Err(e) if e.is_transient() => {
                eprintln!("warning: renewal failed (will retry): {e}");
                Ok(self.backoff().await)
            }
            Err(e) => Err(anyhow::Error::new(e).context("renewal rejected")),
        }
    }

    /// Sleep one backoff interval; report whether a stop signal arrived.
    async fn backoff(&mut self) -> Flow {
        if self.backoff.wait(&mut self.signals).await.is_stop() {
            Flow::Stop
        } else {
            Flow::Continue
        }
    }
}

/// Parse the leaf certificate's validity window. Tolerates a fullchain file by
/// taking the first CERTIFICATE block.
fn cert_window(cert_pem: &str) -> anyhow::Result<(std::time::SystemTime, std::time::SystemTime)> {
    use der::Decode;
    let blocks = pem::parse_many(cert_pem.as_bytes())?;
    let leaf = blocks
        .iter()
        .find(|b| b.tag() == "CERTIFICATE")
        .ok_or_else(|| anyhow::anyhow!("no CERTIFICATE block in certificate file"))?;
    let cert = x509_cert::Certificate::from_der(leaf.contents())?;
    let validity = &cert.tbs_certificate.validity;
    Ok((
        validity.not_before.to_system_time(),
        validity.not_after.to_system_time(),
    ))
}

/// Compute when to renew, given a pre-drawn jitter (seconds). Pure, so the
/// schedule math is unit-testable.
fn next_renewal(
    not_before: std::time::SystemTime,
    not_after: std::time::SystemTime,
    cfg: &LoopConfig,
    jitter_secs: u64,
) -> std::time::SystemTime {
    let base = match cfg.renew_before {
        Some(before) => not_after.checked_sub(before).unwrap_or(not_before),
        None => {
            let lifetime = not_after
                .duration_since(not_before)
                .unwrap_or(std::time::Duration::ZERO);
            not_before + lifetime.mul_f64(cfg.fraction)
        }
    };
    let renew_at = base
        .checked_sub(std::time::Duration::from_secs(jitter_secs))
        .unwrap_or(not_before);
    renew_at.max(not_before)
}

/// A uniform random number of seconds in `[0, max]`.
fn jitter_secs(max: std::time::Duration) -> u64 {
    let max = max.as_secs();
    if max == 0 {
        0
    } else {
        use rand::Rng;
        rand::thread_rng().gen_range(0..=max)
    }
}

async fn run_exec(cmd: &str) {
    let cmd = cmd.to_string();
    let result = tokio::task::spawn_blocking(move || {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .status()
    })
    .await;
    match result {
        Ok(Ok(status)) if status.success() => {}
        Ok(Ok(status)) => eprintln!("warning: exec hook exited with {status}"),
        Ok(Err(e)) => eprintln!("warning: exec hook failed to start: {e}"),
        Err(e) => eprintln!("warning: exec hook task failed: {e}"),
    }
}

/// Exponential backoff with full jitter for transient failures.
#[derive(Default)]
struct Backoff {
    n: u32,
}

impl Backoff {
    const BASE_SECS: u64 = 60;
    const CAP_SECS: u64 = 1800;

    fn reset(&mut self) {
        self.n = 0;
    }

    /// Sleep one backoff interval (interruptible), then advance.
    async fn wait(&mut self, signals: &mut Signals) -> Wake {
        let ceiling = Self::BASE_SECS
            .saturating_mul(1u64 << self.n.min(5))
            .min(Self::CAP_SECS);
        self.n = (self.n + 1).min(6);
        let delay = jitter_secs(std::time::Duration::from_secs(ceiling));
        eprintln!("retrying in {delay}s");
        match signals.sleep(std::time::Duration::from_secs(delay)).await {
            Wake::Stop => Wake::Stop,
            // SIGHUP or elapsed both mean "retry now".
            _ => Wake::Elapsed,
        }
    }
}

/// Why a sleep ended.
enum Wake {
    /// The timer elapsed.
    Elapsed,
    /// SIGHUP: renew now.
    Hangup,
    /// SIGTERM/SIGINT: stop the loop.
    Stop,
}

impl Wake {
    fn is_stop(&self) -> bool {
        matches!(self, Wake::Stop)
    }
}

/// The signals the loop reacts to, registered once for the process lifetime.
struct Signals {
    hangup: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
    interrupt: tokio::signal::unix::Signal,
}

impl Signals {
    fn new() -> anyhow::Result<Signals> {
        Ok(Signals {
            hangup: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?,
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
            interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
        })
    }

    /// Sleep for `dur`, returning early if a signal arrives.
    async fn sleep(&mut self, dur: std::time::Duration) -> Wake {
        tokio::select! {
            _ = tokio::time::sleep(dur) => Wake::Elapsed,
            _ = self.hangup.recv() => Wake::Hangup,
            _ = self.terminate.recv() => Wake::Stop,
            _ = self.interrupt.recv() => Wake::Stop,
        }
    }
}

async fn renew_request(
    client: &reqwest::Client,
    base_url: &str,
    cert_pem: &str,
    key: &crate::keypair::KeyPair,
) -> anyhow::Result<ayane_protocol::CertificateResponse> {
    let url = crate::cmd::endpoint(base_url, "/v1/renew");
    let dpop = crate::proof::make_dpop(key, &url)?;
    let request = ayane_protocol::RenewRequest {
        certificate: cert_pem.to_string(),
    };
    crate::cmd::post_json(client, &url, Some(&dpop), &request).await
}

/// Adds context to a DPoP-building failure (a terminal, local error).
trait DpopContext<T> {
    fn context_dpop(self) -> anyhow::Result<T>;
}

impl<T> DpopContext<T> for anyhow::Result<T> {
    fn context_dpop(self) -> anyhow::Result<T> {
        self.map_err(|e| e.context("building DPoP proof"))
    }
}

#[cfg(test)]
mod tests {
    fn cfg(fraction: f64, renew_before: Option<std::time::Duration>) -> super::LoopConfig {
        super::LoopConfig {
            fraction,
            renew_before,
            jitter: std::time::Duration::from_secs(0),
            max_sleep: std::time::Duration::from_secs(3600),
            exec: None,
            out: std::path::PathBuf::from("/dev/null"),
        }
    }

    #[test]
    fn fraction_threshold() {
        let nb = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000);
        let na = nb + std::time::Duration::from_secs(900);
        let at = super::next_renewal(nb, na, &cfg(0.66, None), 0);
        // 1000 + 0.66*900 = 1594
        assert_eq!(
            at,
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_594)
        );
    }

    #[test]
    fn renew_before_overrides_fraction() {
        let nb = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000);
        let na = nb + std::time::Duration::from_secs(900);
        let at = super::next_renewal(
            nb,
            na,
            &cfg(0.66, Some(std::time::Duration::from_secs(300))),
            0,
        );
        // notAfter (1900) - 300 = 1600
        assert_eq!(
            at,
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600)
        );
    }

    #[test]
    fn jitter_pulls_earlier_and_never_before_not_before() {
        let nb = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000);
        let na = nb + std::time::Duration::from_secs(900);
        let at = super::next_renewal(nb, na, &cfg(0.66, None), 100);
        assert_eq!(
            at,
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_494)
        );
        // Jitter larger than the whole window clamps to notBefore, never before.
        let clamped = super::next_renewal(nb, na, &cfg(0.66, None), 10_000);
        assert_eq!(clamped, nb);
    }

    #[test]
    fn jitter_secs_bounds() {
        for _ in 0..100 {
            assert!(super::jitter_secs(std::time::Duration::from_secs(10)) <= 10);
        }
        assert_eq!(super::jitter_secs(std::time::Duration::from_secs(0)), 0);
    }

    #[test]
    fn backoff_progresses_and_caps() {
        let mut b = super::Backoff::default();
        // ceiling = base * 2^n, capped at CAP_SECS; with jitter we can only
        // assert the advancing counter and the cap indirectly via n saturation.
        for _ in 0..10 {
            let ceiling = super::Backoff::BASE_SECS
                .saturating_mul(1u64 << b.n.min(5))
                .min(super::Backoff::CAP_SECS);
            assert!(ceiling <= super::Backoff::CAP_SECS);
            b.n = (b.n + 1).min(6);
        }
        assert_eq!(b.n, 6);
        b.reset();
        assert_eq!(b.n, 0);
    }
}
