//! `roots`: fetch the CA root certificate(s).

pub async fn run(args: crate::cmd::UrlArgs) -> anyhow::Result<()> {
    let client = crate::cmd::http_client(&args)?;
    let url = crate::cmd::endpoint(&args.url, "/v1/roots");
    let resp: ayane_protocol::RootsResponse = crate::cmd::get_json(&client, &url).await?;
    for cert in resp.certificates {
        print!("{cert}");
    }
    Ok(())
}
