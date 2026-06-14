//! `provisioners`: list configured provisioners.

pub async fn run(args: crate::cmd::UrlArgs) -> anyhow::Result<()> {
    crate::cmd::simple_get(args, "/v1/provisioners").await
}
