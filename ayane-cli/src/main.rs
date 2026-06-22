//! `ayane`: a command-line client for the ayane certificate authority.
//!
//! Acquires and manages certificates: minting issuance tokens, requesting and
//! renewing/rekeying certificates (proving key possession with RFC 9449 DPoP),
//! and revoking them.

mod cmd;
mod csrgen;
mod httpsig;
mod keypair;
mod proof;

#[derive(clap::Parser)]
#[command(
    name = "ayane",
    version,
    about = "Client for the ayane certificate authority"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Mint an issuance token (OTT) signed by a provisioner key.
    Token(cmd::token::TokenArgs),
    /// Request a new certificate using an issuance token.
    Certificate(cmd::certificate::CertificateArgs),
    /// Renew an existing certificate (same key), authenticated with DPoP.
    Renew(cmd::renew::RenewArgs),
    /// Rekey an existing certificate (new key), authenticated with DPoP.
    Rekey(cmd::rekey::RekeyArgs),
    /// Revoke a certificate by serial number.
    Revoke(cmd::revoke::RevokeArgs),
    /// Fetch the CA root certificate(s).
    Roots(cmd::UrlArgs),
    /// Check CA health.
    Health(cmd::UrlArgs),
    /// List configured provisioners.
    Provisioners(cmd::UrlArgs),
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = <Cli as clap::Parser>::parse();
    if let Err(e) = run(cli).await {
        eprintln!("error: {e:#}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Token(a) => cmd::token::run(a),
        Command::Certificate(a) => cmd::certificate::run(a).await,
        Command::Renew(a) => cmd::renew::run(a).await,
        Command::Rekey(a) => cmd::rekey::run(a).await,
        Command::Revoke(a) => cmd::revoke::run(a).await,
        Command::Roots(a) => cmd::roots::run(a).await,
        Command::Health(a) => cmd::health::run(a).await,
        Command::Provisioners(a) => cmd::provisioners::run(a).await,
    }
}
