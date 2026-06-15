# Deployment

ayane ships as a single binary, `ayane-server`, that can run either as a standalone HTTP server (behind your own TLS-terminating reverse proxy) or as an AWS Lambda function fronted by a Lambda Function URL. The same binary picks its mode automatically at runtime, so the only thing that changes between the two deployments is the surrounding infrastructure and a handful of configuration fields.

This page covers both run modes, the AWS-native backends (KMS signing keys, DynamoDB state, EventBridge audit, Lambda webhooks), and a minimal IAM policy. For the full configuration schema see [configuration](configuration.md); for the state table and revocation/replay semantics see [storage](storage.md).

## The `ayane-server` binary

The server reads its configuration path from, in order of precedence:

1. The first command-line argument.
2. The `AYANE_CONFIG` environment variable.
3. The default `ayane.json` in the working directory.

```bash
# Explicit path
ayane-server /etc/ayane/ayane.json

# Via environment variable
AYANE_CONFIG=/etc/ayane/ayane.json ayane-server
```

Logging uses `tracing` with an env-filter; set `RUST_LOG` to control verbosity (defaults to `info`).

```bash
RUST_LOG=ayane=debug,info ayane-server /etc/ayane/ayane.json
```

On a fatal error during startup or serving, the process logs `error=... fatal` and exits with a non-zero status. Configuration is validated eagerly: a `provisioners[].template` or `default_template` that does not exist under `templates` fails startup rather than 500-ing at request time.

### Run-mode selection

The mode is chosen by the presence of the `AWS_LAMBDA_RUNTIME_API` environment variable, which the Lambda execution environment always sets:

| `AWS_LAMBDA_RUNTIME_API` | Mode | Transport |
| --- | --- | --- |
| unset | Standalone | `axum` HTTP server bound to `server.listen` |
| set | Lambda | `lambda_http` runtime serving Lambda Function URL events |

In Lambda mode the server also sets `AWS_LAMBDA_HTTP_IGNORE_STAGE_IN_PATH=true` so that no stage prefix is stripped from request paths. You do not set this yourself.

## Standalone deployment

In standalone mode the server binds a TCP listener on `server.listen`. By default it serves **HTTPS with a certificate it self-issues from its own CA** (see [Self-issued serving TLS](#self-issued-serving-tls) below). To instead terminate TLS at a reverse proxy (nginx, Caddy, an ALB, Envoy, etc.), disable serving TLS with `server.tls.enabled = false` and the listener speaks plaintext HTTP.

### `server` configuration

| Field | Default | Description |
| --- | --- | --- |
| `server.listen` | `"0.0.0.0:9443"` | Listen address for the standalone server. |
| `server.external_url` | unset | Public base URL of the CA. Used to validate token `aud` and DPoP `htu`, and to derive the serving certificate's SAN. |
| `server.tls` | enabled | Self-issued serving TLS. See [below](#self-issued-serving-tls) and the [configuration reference](configuration.md#tlsconfig). |

```json
{
  "server": {
    "listen": "0.0.0.0:9443",
    "external_url": "https://ca.example.com",
    "tls": { "enabled": true, "dns_names": ["ca.example.com"] }
  }
}
```

### Self-issued serving TLS

Because `ayane-server` is itself a CA, the standalone server can serve its own HTTPS without an external certificate: it mints a short-lived leaf from the configured CA, serves it, and renews it in the background before expiry (the same self-served-TLS pattern as step-ca). The serving leaf chains to the same root clients fetch from `GET /v1/roots`, so a client that already trusts the CA root trusts the API endpoint with no extra configuration. The serving private key is ephemeral and in-memory only.

This is **on by default**. The serving SANs are resolved from `server.tls.dns_names`/`ip_addresses`, else from the host of `server.external_url`, else a loopback fallback (`localhost`, `127.0.0.1`, `::1`) — ayane never infers the OS hostname. Set `external_url` or explicit SANs for any non-local deployment, otherwise the default loopback certificate will not match a public hostname. Full schema and renewal knobs (`validity`, `renew_before`, `renew_jitter`) are in the [configuration reference](configuration.md#tlsconfig).

To put ayane behind a TLS-terminating reverse proxy instead, set:

```json
{ "server": { "tls": { "enabled": false } } }
```

The listener then speaks plaintext HTTP and the proxy handles TLS, as in earlier versions. Note that this changes the previous default: a standalone deployment that relied on plaintext HTTP must now set `tls.enabled = false` explicitly.

### Why `external_url` matters

Issuance tokens (OTT) and DPoP proofs are bound to the request URL: the token `aud` must match the endpoint URL, and the DPoP `htu` must match the full request URL. The server needs to know its own public URL to perform these checks.

- When `server.external_url` is set, audiences and DPoP `htu` are derived from that trusted base URL.
- When `server.external_url` is unset, the server logs a warning at startup and derives them from the incoming request's `Host` / `X-Forwarded-*` headers.

Deriving the public URL from request headers is only safe when the proxy in front of ayane is trusted to set those headers correctly. For any deployment reachable through an untrusted proxy, set `external_url` to the public base URL. The startup warning reads:

```
server.external_url is not set; token audiences and DPoP htu will be derived from
request Host/X-Forwarded headers. Set external_url to a trusted public base URL for
any deployment reachable through an untrusted proxy.
```

### Reverse-proxy notes

- Forward the original scheme/host so that header-derived URLs are correct when `external_url` is unset. Prefer setting `external_url` explicitly and treating the proxy as a pure TLS terminator.
- ayane serves the `/v1` API prefix. Proxy `https://ca.example.com/v1/*` straight through to the upstream listener; do not rewrite the path.
- A `GET /v1/health` endpoint returns `{"status":"ok"}` and is suitable as a load-balancer health check. See [API reference](api.md).

### systemd example

```ini
[Unit]
Description=ayane CA
After=network.target

[Service]
Environment=AYANE_CONFIG=/etc/ayane/ayane.json
Environment=RUST_LOG=info
ExecStart=/usr/local/bin/ayane-server
Restart=on-failure
# AWS credentials via instance role or environment

[Install]
WantedBy=multi-user.target
```

## AWS Lambda deployment

When `AWS_LAMBDA_RUNTIME_API` is present, `ayane-server` runs under the `lambda_http` runtime and handles Lambda Function URL events. TLS is terminated by the Function URL itself, so no reverse proxy is required and `server.listen` is ignored. `server.tls` is also ignored under Lambda (the process never sees the handshake) — it is a silent no-op there, not an error, so the same config can be shared between standalone and Lambda deployments.

Set `server.external_url` to the Function URL's public base (for example `https://abc123.lambda-url.us-east-1.on.aws` or a custom domain in front of it) so token audiences and DPoP `htu` are validated against a fixed, trusted URL.

```json
{
  "server": {
    "external_url": "https://ca.example.com"
  }
}
```

Packaging notes:

- Build the binary for the Lambda runtime (a static or `provided.al2023`-compatible build) and deploy it as a custom-runtime function whose handler is `ayane-server`.
- Bundle the configuration alongside the binary and point `AYANE_CONFIG` at its in-package path, or reference a config baked into the image.
- Lambda functions are stateless and may run many concurrent instances, so use a durable, shared backend (DynamoDB) for state. The default in-memory storage does not share revocations or one-time-token claims across instances and must not be used in Lambda. See [storage](storage.md).
- The function's execution role supplies AWS credentials for KMS, DynamoDB, EventBridge, and Lambda webhook calls.

## AWS-native backends

AWS clients are constructed lazily: the default credential chain is only touched when some provider actually needs AWS. A deployment using only file keys, memory/file storage, and stdout/file events never loads AWS configuration. AWS is loaded when any of the following is configured: a KMS signing key, DynamoDB storage, an EventBridge event sink, or a Lambda webhook target.

Each AWS-backed provider accepts an optional `region` field that overrides the region from the default chain for that client only.

### KMS signing key

Set `ca.key` to a KMS asymmetric key so the CA private key never leaves KMS. The to-be-signed certificate body is hashed locally and signed via `kms:Sign` in `DIGEST` mode; the public key is fetched once at startup via `kms:GetPublicKey`.

```json
{
  "ca": {
    "certificate": { "file": "ca/intermediate.crt" },
    "key": {
      "type": "kms",
      "key_id": "alias/ayane-intermediate",
      "algorithm": "ECDSA_SHA256",
      "region": "us-east-1"
    },
    "chain": [{ "file": "ca/intermediate.crt" }],
    "roots": [{ "file": "ca/root.crt" }]
  }
}
```

| Field | Required | Description |
| --- | --- | --- |
| `type` | yes | `"kms"`. |
| `key_id` | yes | KMS key id, ARN, or alias (e.g. `alias/ayane-intermediate`). |
| `algorithm` | yes | Signature algorithm; must match the KMS key's key spec (see below). |
| `region` | no | Region override for the KMS client. |

The `algorithm` value is parsed case-insensitively and accepts the canonical name or its JOSE alias. The KMS provider supports these algorithms and they must be paired with a compatible KMS key spec:

| `algorithm` (canonical) | Alias | KMS `SigningAlgorithmSpec` | Compatible KMS key spec |
| --- | --- | --- | --- |
| `ECDSA_SHA256` | `ES256` | `ECDSA_SHA_256` | `ECC_NIST_P256` |
| `ECDSA_SHA384` | `ES384` | `ECDSA_SHA_384` | `ECC_NIST_P384` |
| `RSA_PKCS1_SHA256` | `RS256` | `RSASSA_PKCS1_V1_5_SHA_256` | `RSA_2048` / `RSA_3072` / `RSA_4096` |
| `RSA_PKCS1_SHA384` | `RS384` | `RSASSA_PKCS1_V1_5_SHA_384` | `RSA_2048` / `RSA_3072` / `RSA_4096` |
| `RSA_PKCS1_SHA512` | `RS512` | `RSASSA_PKCS1_V1_5_SHA_512` | `RSA_2048` / `RSA_3072` / `RSA_4096` |

The KMS key must have key usage `SIGN_VERIFY`. EdDSA is not available for KMS-backed CA keys; use a file key (see [configuration](configuration.md)) if you need EdDSA signing.

Create a key for the example above with:

```bash
aws kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY \
  --description "ayane intermediate CA"
aws kms create-alias --alias-name alias/ayane-intermediate \
  --target-key-id <key-id>
```

### DynamoDB storage

DynamoDB is the durable backend for the issued-certificate inventory, revocation records, and the one-time-token anti-replay denylist. Use it for any multi-instance or Lambda deployment.

```json
{
  "storage": {
    "type": "dynamodb",
    "table_name": "ayane-state",
    "region": "us-east-1"
  }
}
```

| Field | Required | Description |
| --- | --- | --- |
| `type` | yes | `"dynamodb"`. |
| `table_name` | yes | Name of the single state table. |
| `region` | no | Region override for the DynamoDB client. |

#### Table schema

A single table holds all three concerns under a composite primary key — a String partition key `pk` and a String sort key `sk` (a type marker). An inverted global secondary index named `inverted` (partition `sk`, sort `pk`) serves listing.

| Item kind | `pk` value | `sk` value | Other attributes |
| --- | --- | --- | --- |
| Certificate | `certificate:<serial>` | `certificate` | `serial_number` (S), `subject` (S), `sans` (L of S), `not_before` (S), `not_after` (S), `issued_at` (S), `provisioner` (S, optional), `operation` (S), `pem` (S) |
| Revocation | `revocation:<serial>` | `revocation` | `serial_number` (S), `reason_code` (N), `reason` (S, optional), `revoked_at` (S, RFC 3339), `provisioner` (S, optional) |
| Token claim | `token:<jti>` | `token` | `ttl` (N, epoch seconds) |

All writes use a conditional `attribute_not_exists(pk)` put. For certificate records this rejects a serial collision; for revocation it makes `revoke` idempotent (a conflicting put is treated as success, keeping the original record); for token claims a conflict means a replay and is rejected. The serial number in the certificate and revocation keys is the decimal string form. See [storage](storage.md) for the full semantics.

#### Creating the table

The key schema defines `pk`/`sk` plus the `inverted` GSI; all other attributes are written ad hoc.

```bash
aws dynamodb create-table \
  --table-name ayane-state \
  --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE \
  --global-secondary-indexes \
    'IndexName=inverted,KeySchema=[{AttributeName=sk,KeyType=HASH},{AttributeName=pk,KeyType=RANGE}],Projection={ProjectionType=ALL}' \
  --billing-mode PAY_PER_REQUEST
```

#### Enable TTL on `ttl`

Token-claim items carry a numeric `ttl` attribute (epoch seconds) so DynamoDB reaps expired claims automatically. Certificate and revocation items have no `ttl` and are retained indefinitely. Enable TTL on the `ttl` attribute:

```bash
aws dynamodb update-time-to-live \
  --table-name ayane-state \
  --time-to-live-specification "Enabled=true,AttributeName=ttl"
```

DynamoDB TTL deletion is best-effort and may lag the timestamp by up to ~48 hours; this is harmless because anti-replay correctness comes from the conditional put while the token is still within its validity window, and the `ttl` only governs eventual cleanup.

### EventBridge audit events

Add an EventBridge sink to `events` to publish audit events via `PutEvents`. Emission is best-effort: a sink failure is logged and never fails issuance.

```json
{
  "events": [
    {
      "type": "event_bridge",
      "event_bus_name": "default",
      "source": "ayane",
      "region": "us-east-1"
    }
  ]
}
```

| Field | Default | Description |
| --- | --- | --- |
| `type` | — | `"event_bridge"`. |
| `event_bus_name` | `"default"` | Target event bus. |
| `source` | `"ayane"` | EventBridge `source` on each entry. |
| `region` | from chain | Region override for the EventBridge client. |

Each entry sets `source`, `detail_type` to the event type (e.g. `certificate.issued`), and `detail` to the event JSON. See [events](events.md) for the event schema and other destinations.

### Lambda webhooks

A webhook `target` of type `lambda` invokes an AWS Lambda function synchronously to gate and/or customize issuance.

```json
{
  "webhooks": [
    {
      "name": "enrich-from-lambda",
      "target": {
        "type": "lambda",
        "function_name": "ayane-enrich",
        "region": "us-east-1"
      }
    }
  ]
}
```

| Field | Required | Description |
| --- | --- | --- |
| `type` | yes | `"lambda"`. |
| `function_name` | yes | Function name or ARN. |
| `region` | no | Region override for the Lambda client. |

See [webhooks](webhooks.md) for the request/response payloads and the gate/customize semantics.

## Minimal IAM policy

Grant only the actions the configured backends require. The policy below covers all four AWS-native backends; drop the statements for backends you do not use. Scope each `Resource` to the specific key, table, event bus, and function in your account.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Sign",
      "Effect": "Allow",
      "Action": [
        "kms:Sign",
        "kms:GetPublicKey"
      ],
      "Resource": "arn:aws:kms:us-east-1:111122223333:key/abcd1234-..."
    },
    {
      "Sid": "State",
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem",
        "dynamodb:GetItem",
        "dynamodb:Query"
      ],
      "Resource": [
        "arn:aws:dynamodb:us-east-1:111122223333:table/ayane-state",
        "arn:aws:dynamodb:us-east-1:111122223333:table/ayane-state/index/inverted"
      ]
    },
    {
      "Sid": "Audit",
      "Effect": "Allow",
      "Action": "events:PutEvents",
      "Resource": "arn:aws:events:us-east-1:111122223333:event-bus/default"
    },
    {
      "Sid": "Webhook",
      "Effect": "Allow",
      "Action": "lambda:InvokeFunction",
      "Resource": "arn:aws:lambda:us-east-1:111122223333:function:ayane-enrich"
    }
  ]
}
```

Notes:

- KMS: ayane calls `kms:Sign` on every issuance and `kms:GetPublicKey` once at startup. No `kms:Encrypt`/`Decrypt` is needed.
- DynamoDB: `PutItem` and `GetItem` on the table, plus `Query` on the table and its `inverted` index (used to list issued certificates and revocations). No `Scan`, `UpdateItem`, or `DeleteItem` (claim expiry is handled by DynamoDB TTL).
- EventBridge and Lambda statements are needed only when an `event_bridge` event sink or a `lambda` webhook is configured.
- Attach this policy to the standalone host's instance role or the Lambda execution role. Credentials are resolved through the standard AWS default chain.

## Full reference deployment

A complete example wiring KMS signing, DynamoDB storage, EventBridge audit, and HTTP/Lambda webhooks together lives at `examples/ayane.example.json` in the repository. Use it as a starting point and adjust the key id, table name, region, and provisioner keys.

## See also

- [configuration](configuration.md) — full configuration schema and the `ca` / `provisioners` blocks
- [storage](storage.md) — DynamoDB state table, revocation, and anti-replay semantics
- [events](events.md) — audit event schema and destinations including EventBridge
- [docs index](README.md)
