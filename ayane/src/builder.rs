//! Construct a live [`Service`](crate::service::Service) from [`Config`].
//!
//! This bridges configuration data to concrete providers. Each abstraction owns
//! its own construction via a `from_config` entry point, and AWS-backed
//! providers resolve their clients lazily and internally (see [`crate::aws`]).
//! This module therefore never touches the AWS SDK, so a file/sqlite/stdout-only
//! deployment never loads the AWS credential chain.

/// Build a service from configuration.
pub async fn build_service(
    config: &crate::config::Config,
) -> crate::error::Result<crate::service::Service> {
    // Fail fast on dangling template references rather than 500-ing at runtime.
    let referenced = config.default_template.iter().chain(
        config
            .provisioners
            .iter()
            .filter_map(|p| p.template.as_ref()),
    );
    for name in referenced {
        if !config.templates.contains_key(name) {
            return Err(crate::error::Error::Config(format!(
                "referenced template {name:?} is not defined under `templates`"
            )));
        }
    }
    crate::config::validate_provisioner_authorization(config)?;

    let key = crate::key_provider::from_config(&config.ca.key).await?;
    let issuer_pem = config.ca.certificate.load()?;
    let mut chain = vec![issuer_pem.clone()];
    for source in &config.ca.chain {
        chain.push(source.load()?);
    }
    let mut roots = Vec::new();
    for source in &config.ca.roots {
        roots.push(source.load()?);
    }
    if roots.is_empty() {
        roots.push(issuer_pem.clone());
    }
    let ca = std::sync::Arc::new(crate::ca::CertificateAuthority::new(
        key,
        &issuer_pem,
        chain,
        roots,
    )?);

    let authorizer: std::sync::Arc<dyn crate::authorizer::Authorizer> = std::sync::Arc::new(
        crate::authorizer::ProvisionerAuthorizer::from_configs(&config.provisioners)?,
    );

    let storage = crate::storage::from_config(&config.storage).await?;

    let mut events = Vec::new();
    for event in &config.events {
        events.push(crate::event_sink::from_config(event).await?);
    }

    let mut webhooks = Vec::new();
    for webhook in &config.webhooks {
        webhooks.push(crate::webhook::from_config(webhook).await?);
    }

    Ok(crate::service::Service::new(crate::service::ServiceParts {
        authorizer,
        ca,
        storage,
        webhooks,
        events,
        templates: config.templates.clone(),
        default_template_name: config.default_template.clone(),
        roots_signature_ttl: config.ca.roots_signature.ttl.get(),
        external_url: config.server.external_url.clone(),
    }))
}
