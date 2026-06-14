//! Lazily-loaded, process-wide AWS SDK configuration.
//!
//! Providers that talk to AWS (KMS, DynamoDB, EventBridge, Lambda) resolve their
//! clients through [`shared_config`], so the base credential/region chain is
//! loaded at most once and only when a provider actually needs it. A
//! file/memory/stdout-only deployment never triggers the AWS credential chain.

/// The shared base AWS configuration, loaded on first use and cached for the
/// lifetime of the process.
pub async fn shared_config() -> &'static aws_config::SdkConfig {
    static CONFIG: tokio::sync::OnceCell<aws_config::SdkConfig> =
        tokio::sync::OnceCell::const_new();
    CONFIG
        .get_or_init(|| aws_config::load_defaults(aws_config::BehaviorVersion::latest()))
        .await
}
