# ayane documentation index

ayane is an AWS-native, [step-ca](https://smallstep.com/docs/step-ca/)-style X.509 certificate authority written in Rust. It issues short-lived leaf certificates against a one-time issuance token (OTT) JWT, lets key holders renew, rekey, and self-revoke their own certificates by proving key possession with [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) DPoP, and is designed to run either as a standalone HTTP server or behind an AWS Lambda Function URL.

## At a glance

- **JWT one-time tokens** — issuance is gated by an OTT signed by a configured provisioner; the JWT algorithm is pinned to the provisioner's key type (alg-confusion-safe), and each `jti` is single-use.
- **DPoP self-service lifecycle** — renew, rekey, and self-revoke require an RFC 9449 proof verified directly against the presented certificate's public key, so no second secret is needed.
- **Pluggable AWS-native backends** — CA key in a file or AWS KMS, audit events to stdout / file / Amazon EventBridge, revocation and anti-replay state in SQLite (file or in-memory) or Amazon DynamoDB.
- **Webhooks** — HTTP or AWS Lambda webhooks gate and customize issuance from a single typed response.
- **Certificate templates** — declarative key usage, extended key usage, CA/path-length, and validity policy.
- **Dual deployment** — one `axum` router served standalone over tokio, or via `lambda_http` behind a Function URL, with TLS terminated externally.
- **RFC 7807 errors** — every failure is an `application/problem+json` body.

## How a request flows

ayane exposes a small JSON API under the `/v1` prefix. There are two authentication models, depending on whether you are creating a brand-new certificate or operating on one you already hold.

### Issuance (`POST /v1/sign`)

1. A provisioner (an entity holding a private key whose public JWK is configured on the server) mints an **OTT**: a JWT whose `iss` is the provisioner name, `sub` is the subject/CN, `sans` lists the permitted Subject Alternative Names, and `aud` is the request endpoint URL. The token may carry a `cnf` claim binding it to the SHA-256 thumbprint of a specific CSR.
2. The client generates a key pair and a CSR, then POSTs `{csr, token}` (optionally `not_before` / `not_after`) to `/v1/sign`.
3. The server validates the token signature against the provisioner JWK (with the alg pinned to the key type), checks `aud`/`nbf`/`exp` (60s leeway), confirms the requested SANs are permitted, claims the `jti` once for anti-replay, runs any webhooks, applies the template, and signs the leaf.
4. The response is `201` with `{certificate, chain, serial_number, not_after}`.

### Lifecycle (`POST /v1/renew`, `/v1/rekey`, `/v1/revoke`)

For these operations the client proves possession of the existing certificate's private key with a **DPoP** proof carried in the `DPoP` request header — a JWS with `typ=dpop+jwt`, `htm=POST`, `htu` equal to the full request URL, plus single-use `jti` and a freshness window. The proof is verified directly against the presented certificate's public key, and the certificate must additionally have been issued by this CA, be unrevoked, and be unexpired. Revocation can alternatively be authorized by an OTT (`operation: revoke`).

```bash
# Mint a token and request a certificate in one go (see the CLI page for details)
ayane token --key provisioner.pem --issuer my-jwk --url https://ca.example \
  --subject leaf.example --san leaf.example > token.jwt

ayane certificate --url https://ca.example --token-file token.jwt \
  --subject leaf.example --san leaf.example \
  --key-out leaf.key --out leaf.crt
```

The equivalent raw call:

```bash
curl -sS -X POST https://ca.example/v1/sign \
  -H 'Content-Type: application/json' \
  -d '{"csr":"-----BEGIN CERTIFICATE REQUEST-----\n...","token":"eyJ..."}'
```

```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...",
  "chain": ["-----BEGIN CERTIFICATE-----\n..."],
  "serial_number": "1234567890",
  "not_after": "2026-06-15T00:00:00Z"
}
```

## API surface

All endpoints are rooted at `/v1`. PEM fields are standard armored text; timestamps are RFC 3339; serial numbers are decimal strings (revocation also accepts `0x`-hex on input).

| Method & path | Auth | Request | Success |
| --- | --- | --- | --- |
| `GET /v1/health` | none | — | `200` `{"status":"ok"}` |
| `GET /v1/roots` | none | — | `200` `{"certificates":[...]}` |
| `GET /v1/provisioners` | none | — | `200` `{"provisioners":[...]}` |
| `POST /v1/sign` | OTT (`token`) | `{csr, token, not_before?, not_after?}` | `201` `CertificateResponse` |
| `POST /v1/renew` | DPoP header | `{certificate}` | `201` `CertificateResponse` |
| `POST /v1/rekey` | DPoP header | `{certificate, csr}` | `201` `CertificateResponse` |
| `POST /v1/revoke` | OTT or DPoP | `{serial_number, reason?, reason_code?, token?, certificate?}` | `200` `{"status":"revoked"}` |

Errors are RFC 7807 `application/problem+json` with `{type, title, status, detail?, instance?}`. The status map is `BadRequest` 400, `Unauthorized` 401, `Forbidden` 403, `NotFound` 404, `Conflict` 409, and `Config`/`Internal` 500 (whose `detail` is suppressed). See the [API reference](api.md) for full field tables.

## Architecture

The server core lives in the `ayane` crate, organized as a set of pluggable abstractions around a central certificate-building engine (`ca::CertificateAuthority`) and the request orchestration in `service`:

| Abstraction | Module | Implementations |
| --- | --- | --- |
| Key provider | `key_provider` | file key, AWS KMS |
| Authorizer | `authorizer` | JWT one-time token (OTT) |
| Webhook | `webhook` | HTTP, AWS Lambda |
| Event destination | `event` | stdout, file, AWS EventBridge |
| Storage | `storage` | SQLite, DynamoDB |

The HTTP layer (`http`) is a thin adapter that turns the same `axum` router into both a standalone tokio server and a Lambda Function URL handler (`server`).

### Crates

ayane is a Cargo workspace of three crates:

| Crate | Role |
| --- | --- |
| `ayane-protocol` | Wire types shared by client and server: request/response bodies, OTT claims, and the `DPoP` header constant. |
| `ayane` | Server core plus the `ayane-server` binary; provides the pluggable abstractions and the dual standalone-axum / AWS Lambda runtime. |
| `ayane-cli` | The `ayane` client binary: mint tokens, request, renew, rekey, and revoke certificates. |

## Documentation

| Page | Description |
| --- | --- |
| [Getting started](getting-started.md) | Stand up a CA, mint a token, and issue your first certificate end to end. |
| [Configuration](configuration.md) | The full `ayane.json` schema: `ca`, `provisioners`, `templates`, `storage`, `server`, and more. |
| [API reference](api.md) | Every `/v1` endpoint with request/response field tables and RFC 7807 error semantics. |
| [Provisioners and tokens](provisioners.md) | Configuring JWK provisioners and the OTT claim set (`iss`, `aud`, `sub`, `sans`, `cnf`, ...). |
| [DPoP and the certificate lifecycle](renewal-revocation.md) | Renew, rekey, and self-revoke with RFC 9449 proof of possession. |
| [Certificate templates](templates.md) | Key usage, extended key usage, CA constraints, and validity policy. |
| [Webhooks](webhooks.md) | HTTP or AWS Lambda webhooks that gate and customize issuance. |
| [Audit events](events.md) | Emitting issuance/revocation events to stdout, a file, or Amazon EventBridge. |
| [Storage](storage.md) | SQLite and DynamoDB backends for revocation records and anti-replay state. |
| [Deployment](deployment.md) | Running `ayane-server` standalone or as an AWS Lambda Function URL, and `external_url`. |
| [Security model](security.md) | Trust boundaries, alg pinning, anti-replay, DPoP binding, and hardening guidance. |
| [CLI reference](cli.md) | The `ayane` client commands: `token`, `certificate`, `renew`, `rekey`, `revoke`, `roots`, `health`, `provisioners`. |

## See also

- [Getting started](getting-started.md)
- [Configuration](configuration.md)
- [API reference](api.md)
- [docs index](README.md)
