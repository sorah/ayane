# ayane

**ayane** is an AWS-native, [step-ca](https://smallstep.com/docs/step-ca/)-style X.509 certificate authority. It issues short-lived leaf certificates against a one-time issuance token (OTT) JWT, and lets key holders **renew, rekey, and self-revoke** their own certificates by proving possession of the private key with an [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) DPoP proof.

It supports multiple cloud environments, such as on AWS (KMS, Lambda, Function URL, EventBridge, DynamoDB) or on-premises (file based key, standalone HTTPS, sqlite3).

## Features

- **JWT one-time tokens** — issuance is gated by an OTT signed by a configured provisioner. The JWT algorithm is pinned to the provisioner's key type (alg-confusion-safe), and each `jti` is single-use.
- **DPoP self-service lifecycle** — renew, rekey, and self-revoke are authenticated by an RFC 9449 proof verified directly against the presented certificate's public key.
- **Pluggable, AWS-native backends** — CA key in a file or AWS KMS; audit events to stdout, a file, or Amazon EventBridge; revocation and anti-replay state in SQLite or Amazon DynamoDB.
- **Issuance webhooks** — gate and/or customize certificates from an external HTTP or AWS Lambda service via a single typed response.
- **Certificate templates** — declarative key usage, extended key usage, CA/path-length constraints, and validity policy.

## Quick start

Build the two binaries — `ayane-server` (the CA) and `ayane` (the client CLI):

```bash
cargo build --release
# -> target/release/ayane-server  and  target/release/ayane
```

Write a minimal `ayane.json` (see [examples/ayane.example.json](examples/ayane.example.json) and the [getting-started guide](docs/getting-started.md) for a full local setup with a file-based CA key and in-memory SQLite), then run the server:

```bash
./target/release/ayane-server ayane.json
```

Mint an issuance token with a provisioner key and exchange it for a certificate:

```bash
# Mint a one-time token scoped to a subject and its SANs
ayane token --key provisioner.pem --issuer my-jwk --url http://127.0.0.1:9443 \
  --subject leaf.example --san leaf.example > token.jwt

# Generate a key + CSR and request the certificate
ayane certificate --url http://127.0.0.1:9443 --token-file token.jwt \
  --subject leaf.example --san leaf.example \
  --key-out leaf.key.pem --out leaf.crt
```

Later, renew it by proving possession of `leaf.key.pem` (no new token needed):

```bash
ayane renew --url http://127.0.0.1:9443 --cert leaf.crt --key leaf.key.pem --out leaf.crt
```

## API surface

All endpoints are rooted at `/v1`. PEM fields are standard armored text, timestamps are RFC 3339, and serial numbers are decimal strings.

| Method & path | Auth | Success |
| --- | --- | --- |
| `GET /v1/health` | none | `200 {"status":"ok"}` |
| `GET /v1/roots` | none | `200 {"certificates":[...]}` |
| `GET /v1/provisioners` | none | `200 {"provisioners":[...]}` |
| `POST /v1/sign` | OTT token | `201` certificate |
| `POST /v1/renew` | DPoP header | `201` certificate |
| `POST /v1/rekey` | DPoP header | `201` certificate |
| `POST /v1/revoke` | OTT or DPoP | `200 {"status":"revoked"}` |

See the [API reference](docs/api.md) for full request/response field tables and error semantics.

## Documentation

Full documentation lives in [`docs/`](docs/README.md):

- [Getting started](docs/getting-started.md) — stand up a CA and issue your first certificate end to end.
- [Configuration](docs/configuration.md) — the complete `ayane.json` schema.
- [API reference](docs/api.md) — every `/v1` endpoint and RFC 7807 error semantics.
- [Provisioners and tokens](docs/provisioners.md) — JWK provisioners and the OTT claim set.
- [DPoP and the certificate lifecycle](docs/renewal-revocation.md) — renew, rekey, and self-revoke.
- [Certificate templates](docs/templates.md) — key usage, EKU, CA constraints, validity policy.
- [Webhooks](docs/webhooks.md) · [Audit events](docs/events.md) · [Storage](docs/storage.md)
- [Deployment](docs/deployment.md) — standalone or AWS Lambda Function URL.
- [Security model](docs/security.md) — trust boundaries, alg pinning, anti-replay, DPoP binding.
- [CLI reference](docs/cli.md) — the `ayane` client commands.

## Project layout

A Cargo workspace of three crates:

| Crate | Role |
| --- | --- |
| [`ayane-protocol`](ayane-protocol) | Wire types shared by client and server: request/response bodies, OTT claims, and the `DPoP` header constant. |
| [`ayane`](ayane) | Server core plus the `ayane-server` binary; the pluggable abstractions and the dual standalone-axum / AWS Lambda runtime. |
| [`ayane-cli`](ayane-cli) | The `ayane` client binary: mint tokens and request, renew, rekey, and revoke certificates. |

## Development

```bash
cargo test        # run the test suite
cargo clippy --all-targets
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE.txt). Copyright © Sorah Fukumori.
