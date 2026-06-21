//! `roots`: fetch the CA root certificate(s), verifying the response signature.
//!
//! The `GET /v1/roots` response is signed with the CA key (RFC 9421). Because the
//! endpoint may be served behind a third-party TLS certificate, we always verify
//! that signature against the pinned `--root` bundle before trusting any root in
//! the response — so `--root` is required here.

pub async fn run(args: crate::cmd::UrlArgs) -> anyhow::Result<()> {
    let root = args.root.clone().ok_or_else(|| {
        anyhow::anyhow!("--root is required: the roots response signature is verified against it")
    })?;
    let known_roots = std::fs::read(&root)?;

    let client = crate::cmd::http_client(&args)?;
    let roots_url = crate::cmd::endpoint(&args.url, "/v1/roots");

    let resp = client.get(&roots_url).send().await?;
    let status = resp.status();
    let headers = extract_headers(resp.headers())?;
    let body = resp.bytes().await?;
    if !status.is_success() {
        anyhow::bail!("CA returned {status} for {roots_url}");
    }

    // Resolve x5u to a same-origin URL and fetch the signer chain. Constraining
    // it to the request origin means a tampered x5u cannot redirect the fetch.
    let (x5u, _x5t) = ayane_protocol::httpsig::parse_signature_key_x509(&headers.signature_key)?;
    let signer_chain_url = resolve_same_origin(&roots_url, &x5u)?;
    let signer_chain = client
        .get(signer_chain_url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    crate::httpsig::verify_roots_response(
        &body,
        &headers,
        &signer_chain,
        &known_roots,
        now_secs(),
    )?;

    let resp: ayane_protocol::RootsResponse = serde_json::from_slice(&body)?;
    for cert in resp.certificates {
        print!("{cert}");
    }
    Ok(())
}

fn extract_headers(
    headers: &reqwest::header::HeaderMap,
) -> anyhow::Result<crate::httpsig::ResponseHeaders> {
    let get = |name: &str| -> anyhow::Result<String> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("roots response is missing the {name} header"))
    };
    Ok(crate::httpsig::ResponseHeaders {
        content_digest: get(ayane_protocol::httpsig::CONTENT_DIGEST_HEADER)?,
        signature_input: get(ayane_protocol::httpsig::SIGNATURE_INPUT_HEADER)?,
        signature: get(ayane_protocol::httpsig::SIGNATURE_HEADER)?,
        signature_key: get(ayane_protocol::httpsig::SIGNATURE_KEY_HEADER)?,
    })
}

/// Resolve `reference` (relative or absolute) against `base`, requiring the
/// result to share `base`'s origin.
fn resolve_same_origin(base: &str, reference: &str) -> anyhow::Result<reqwest::Url> {
    let base = reqwest::Url::parse(base)?;
    let resolved = base.join(reference)?;
    if resolved.origin() != base.origin() {
        anyhow::bail!("signer chain URL {resolved} is not on the CA origin");
    }
    Ok(resolved)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
