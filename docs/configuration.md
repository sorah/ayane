# Configuration reference

ayane is configured by a single JSON document (default `ayane.json`, overridable with a path argument to `ayane-server`, the `AYANE_CONFIG` environment variable, or — passed inline as base64url-encoded JSON — the `AYANE_CONFIG_BASE64URL` environment variable; see [deployment](deployment.md) for the full precedence). This page is the exhaustive reference for every top-level key, the nested types they reference, and the boot-time validation ayane performs before it starts serving.

The document is parsed by [`Config::from_json`](../ayane/src/config.rs) and turned into live providers by `build_service` in [`builder.rs`](../ayane/src/builder.rs). The top-level object and most nested structs use `#[serde(deny_unknown_fields)]`, so an unknown or misspelled key is a hard parse error, not a silently ignored field.

## Top-level document

```json
{
  "ca": { "...": "..." },
  "provisioners": [],
  "templates": {},
  "default_template": null,
  "webhooks": [],
  "events": [],
  "storage": { "type": "sqlite", "path": ":memory:" },
  "server": { "listen": "0.0.0.0:9443" }
}
```

| Field | Type | Required / default | Description |
| --- | --- | --- | --- |
| `ca` | object ([CaConfig](#ca)) | required | The issuing certificate authority: issuing certificate, signing key, chain, and roots. |
| `provisioners` | array of [ProvisionerConfig](#provisioners) | default `[]` | Token-issuing provisioners. With none configured, no token can be validated and `/v1/sign` cannot succeed. |
| `templates` | object map `name` -> [CertificateTemplate](#templates) | default `{}` | Named certificate templates. |
| `default_template` | string | default `null` | Name of the template applied when a provisioner does not select one. Validated at boot. |
| `webhooks` | array of [WebhookConfig](#webhooks) | default `[]` | Issuance webhooks that gate and/or customize certificates. |
| `events` | array of [EventConfig](#events) | default `[]` | Audit-event destinations. |
| `storage` | object ([StorageConfig](#storage)) | default `{"type":"sqlite","path":":memory:"}` | Issued-certificate inventory, revocation, and anti-replay storage backend. |
| `server` | object ([ServerConfig](#server)) | default (see [server](#server)) | HTTP server settings. |

A minimal valid document only needs `ca`; every other key defaults:

```json
{
  "ca": {
    "certificate": { "file": "ca.crt" },
    "key": { "type": "file", "file": "ca.key" }
  }
}
```

This starts with no provisioners, in-process SQLite storage, no events or webhooks, and listens on `0.0.0.0:9443`.

## PemSource

A `PemSource` is the small object used wherever ayane needs a PEM document (the issuing certificate, chain certificates, roots). Exactly one of the two fields supplies the PEM.

| Field | Type | Required / default | Description |
| --- | --- | --- | --- |
| `pem` | string | optional | Inline PEM text. Takes precedence when both fields are set. |
| `file` | string | optional | Path to a PEM file, read at startup. |

Resolution order in [`PemSource::load`](../ayane/src/config.rs): if `pem` is present it is used; otherwise `file` is read; if neither is set, startup fails with `PEM source requires \`pem\` or \`file\``.

```json
{ "file": "ca/intermediate.crt" }
```

```json
{ "pem": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n" }
```

## ca

The issuing certificate authority. This object has `deny_unknown_fields`.

| Field | Type | Required / default | Description |
| --- | --- | --- | --- |
| `certificate` | [PemSource](#pemsource) | required | The issuing (intermediate or root) certificate that signs leaf certificates. |
| `key` | object ([KeyConfig](#keyconfig)) | required | The signing key backend. |
| `chain` | array of [PemSource](#pemsource) | default `[]` | Additional issuer-side certificates returned to clients alongside the leaf. Normally the issuer's parents ordered up the chain; may also carry cross-signed intermediates (see below). Also served as the signer chain at `GET /v1/roots/signer-chain`. |
| `roots` | array of [PemSource](#pemsource) | default `[]` | Trusted root certificate(s) served at `GET /v1/roots`. |
| `roots_signature` | object ([RootsSignatureConfig](#rootssignatureconfig)) | default `{}` | Settings for the RFC 9421 signature applied to the `GET /v1/roots` response. |

Chain and root handling (see [`build_service`](../ayane/src/builder.rs)):

- The fullchain returned to clients always begins with the issuing `certificate`, then each entry of `chain` in order, served verbatim. You do not list the issuing certificate again in `chain`; it is prepended automatically. (The bundled `examples/ayane.example.json` does repeat it in `chain`, which would duplicate the issuer in the served chain — list only the parents of the issuer here.)
- `chain` is not restricted to a single linear path. To support cross-root trust during a CA migration, append a cross-signed copy of the issuing intermediate — one bearing the same subject/key but signed by the *old* root — after the normal parents. Clients that still trust only the old root can then build a path to it from the fullchain, while clients trusting the new root use the canonical path. This mirrors step-ca, where the intermediate is a PEM bundle and any extra (incl. cross-signed) certificates are returned as-is.
- `roots` may list more than one root. During a root rotation, serve both the old and new roots here so relying parties fetching `GET /v1/roots` trust certificates issued under either. If `roots` is empty, ayane serves the issuing `certificate` itself as the sole root.

```json
{
  "certificate": { "file": "ca/intermediate.crt" },
  "key": {
    "type": "aws_kms",
    "key_id": "alias/ayane-intermediate",
    "algorithm": "ECDSA_SHA256",
    "region": "us-east-1"
  },
  "roots": [{ "file": "ca/root.crt" }]
}
```

### RootsSignatureConfig

Settings for the [RFC 9421 signature](api.md#roots-response-signature) over the
`GET /v1/roots` response. This object has `deny_unknown_fields`.

| Field | Type | Required / default | Description |
| --- | --- | --- | --- |
| `ttl` | [duration](#durations) | default `24h` | Lifetime of each signed roots artifact (`expires = created + ttl`). The server re-signs before expiry; clients reject a signature once `now >= expires`. Shorter values narrow the replay window at the cost of more frequent signing (the CA key may be AWS KMS); signatures are cached in [storage](storage.md) for the lifetime, so a short `ttl` mainly increases re-signing frequency, not per-request cost. |

```json
{
  "roots_signature": { "ttl": "24h" }
}
```

### KeyConfig

The signing key is an internally tagged enum keyed on `type`, with snake_case variant names: `"file"` or `"aws_kms"`.

#### `type: "file"` — local PEM private key

| Field | Type | Required / default | Description |
| --- | --- | --- | --- |
| `type` | string | required | Literal `"file"`. |
| `file` | string | optional | Path to the PEM private key. |
| `pem` | string | optional | Inline PEM private key. Takes precedence over `file`. |
| `algorithm` | string | optional | Signature-algorithm override (meaningful for RSA, where the digest is not implied by the key). See [algorithm values](#algorithm-values). |

Exactly one of `pem` / `file` must be present; otherwise startup fails with `file key requires \`pem\` or \`file\``. The key type (EC vs RSA) is inferred from the PEM; for ECDSA keys the curve fixes the digest, so `algorithm` is normally only needed to select an RSA digest.

```json
{ "type": "file", "file": "ca/intermediate.key" }
```

```json
{ "type": "file", "file": "ca/intermediate.key", "algorithm": "RSA_PKCS1_SHA256" }
```

#### `type: "aws_kms"` — AWS KMS asymmetric key

| Field | Type | Required / default | Description |
| --- | --- | --- | --- |
| `type` | string | required | Literal `"aws_kms"`. |
| `key_id` | string | required | KMS key id, ARN, or alias (e.g. `alias/ayane-intermediate`). |
| `algorithm` | string | required | Signature algorithm matching the KMS key. See [algorithm values](#algorithm-values). |
| `region` | string | optional | Region override for the KMS client. Defaults to the ambient AWS configuration. |

```json
{
  "type": "aws_kms",
  "key_id": "alias/ayane-intermediate",
  "algorithm": "ECDSA_SHA256",
  "region": "us-east-1"
}
```

#### algorithm values

The `algorithm` string is parsed by [`SignatureAlgorithm::parse`](../ayane/src/crypto.rs). Each canonical name has a JOSE-style alias that resolves to the same algorithm:

| Canonical value | Alias | Algorithm |
| --- | --- | --- |
| `ECDSA_SHA256` | `ES256` | ECDSA over P-256 with SHA-256 |
| `ECDSA_SHA384` | `ES384` | ECDSA over P-384 with SHA-384 |
| `RSA_PKCS1_SHA256` | `RS256` | RSASSA-PKCS1-v1_5 with SHA-256 |
| `RSA_PKCS1_SHA384` | `RS384` | RSASSA-PKCS1-v1_5 with SHA-384 |
| `RSA_PKCS1_SHA512` | `RS512` | RSASSA-PKCS1-v1_5 with SHA-512 |

Any other value fails startup with `unknown signature algorithm: <value>`.

## provisioners

Each provisioner verifies one-time issuance tokens (OTT JWTs) presented to `POST /v1/sign`. This object has `deny_unknown_fields`. See [authentication](provisioners.md) for the full token-validation rules.

| Field | Type | Required / default | Description |
| --- | --- | --- | --- |
| `name` | string | required | Provisioner name. Must equal the token `iss` claim. |
| `type` | string | default `"jwk"` | Provisioner kind. Only `"jwk"` is supported. |
| `key` | JWK object | required | The provisioner's public verification key, as a JSON Web Key. The JWK's key type pins the accepted JWT `alg` (alg-confusion-safe). |
| `audiences` | array of string | default `[]` | Additional accepted token `aud` values. The server's own endpoint URL is always accepted; this list adds more. |
| `template` | string | default `null` | Name of the [template](#templates) used for certificates issued through this provisioner. Validated at boot. |

```json
{
  "name": "ci-issuer",
  "type": "jwk",
  "audiences": ["https://ca.example.com/v1/sign"],
  "template": "server",
  "key": {
    "kty": "EC",
    "crv": "P-256",
    "alg": "ES256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
  }
}
```

## templates

`templates` is a map of template name to a `CertificateTemplate`. A template declares the shape of issued certificates: key usages, extended key usages, basic constraints, and the validity policy. It is structured, not a free-form text template; the per-request subject and SANs are supplied at issuance. The struct has `deny_unknown_fields`. Defined in [`template.rs`](../ayane/src/template.rs).

| Field | Type | Required / default | Description |
| --- | --- | --- | --- |
| `key_usage` | array of [key-usage name](#key-usage-names) | default `["digital_signature"]` | `keyUsage` bits. An empty array omits the extension. Marked critical when present. |
| `extended_key_usage` | array of [EKU name](#extended-key-usage-names) | default `["server_auth"]` | `extendedKeyUsage` purposes. An empty array omits the extension. |
| `is_ca` | bool | default `false` | `basicConstraints` CA flag. Leaf templates leave this `false`. |
| `path_len` | integer (u8) | default `null` | `basicConstraints` pathLenConstraint. Only emitted when `is_ca` is `true`. |
| `set_common_name` | bool | default `true` | Set the subject `commonName` from the token subject. |
| `default_validity` | [duration](#durations) | default `"24h"` | Lifetime applied when the request does not pin `notAfter`. |
| `min_validity` | [duration](#durations) | default `"60s"` | Minimum acceptable lifetime; a shorter request is rejected with `400`. |
| `max_validity` | [duration](#durations) | default `"24h"` | Maximum acceptable lifetime; a longer request is clamped down to this. |
| `backdate` | [duration](#durations) | default `"60s"` | Amount subtracted from `notBefore` to tolerate clock skew. |

Validity is computed by `compute_validity`: `notBefore` is the requested time (or now) minus `backdate`; the requested lifetime is rejected when below `min_validity` and clamped to `max_validity` (plus `backdate`) when above.

```json
{
  "server": {
    "key_usage": ["digital_signature", "key_encipherment"],
    "extended_key_usage": ["server_auth"],
    "default_validity": "24h",
    "min_validity": "5m",
    "max_validity": "168h",
    "backdate": "1m"
  },
  "client": {
    "key_usage": ["digital_signature"],
    "extended_key_usage": ["client_auth"],
    "default_validity": "24h",
    "max_validity": "24h"
  }
}
```

### key-usage names

JSON values are snake_case. One value accepts an alias.

| Value | Alias | `keyUsage` bit |
| --- | --- | --- |
| `digital_signature` | | digitalSignature |
| `content_commitment` | `non_repudiation` | contentCommitment (a.k.a. nonRepudiation) |
| `key_encipherment` | | keyEncipherment |
| `data_encipherment` | | dataEncipherment |
| `key_agreement` | | keyAgreement |
| `key_cert_sign` | | keyCertSign |
| `crl_sign` | | cRLSign |
| `encipher_only` | | encipherOnly |
| `decipher_only` | | decipherOnly |

### extended-key-usage names

| Value | Purpose |
| --- | --- |
| `server_auth` | TLS server authentication |
| `client_auth` | TLS client authentication |
| `code_signing` | Code signing |
| `email_protection` | Email protection (S/MIME) |
| `time_stamping` | Time stamping |
| `ocsp_signing` | OCSP signing |

### durations

Duration values are strings of a single integer followed by a unit, parsed by [`duration::parse`](../ayane/src/duration.rs). There is no whitespace between number and unit, and compound values such as `"1h30m"` are not supported.

| Unit | Meaning |
| --- | --- |
| `s` | seconds |
| `m` | minutes |
| `h` | hours |
| `d` | days (86400s) |
| `w` | weeks (604800s) |

Examples: `"60s"`, `"5m"`, `"24h"`, `"90d"`, `"1w"`. A value with no unit (`"10"`) or an unknown unit (`"10y"`) fails to parse.

## default_template

A string naming the template to apply when a provisioner does not set its own `template`. When neither the provisioner nor `default_template` selects a template, ayane uses a built-in fallback (the default `CertificateTemplate`: `["digital_signature"]` / `["server_auth"]`, 24h validity).

```json
"default_template": "server"
```

### Template reference validation at boot

`build_service` checks every referenced template name before loading any AWS clients. The set of referenced names is `default_template` plus each provisioner's `template`. If any referenced name is absent from `templates`, startup fails immediately:

```
referenced template "server" is not defined under `templates`
```

This fails fast at boot rather than returning a `500` at issuance time. (The fallback used when no template is named is a built-in default and is never looked up by name, so leaving `default_template` unset is valid.)

## webhooks

Webhooks let an external service gate and/or customize issuance for `sign`, `renew`, and `rekey`. A single typed response can both deny the request and customize the certificate — there is no `kind` distinction. The config struct has `deny_unknown_fields`. See [webhooks](webhooks.md) for the request/response payloads and signing.

| Field | Type | Required / default | Description |
| --- | --- | --- | --- |
| `name` | string | required | Unique webhook name. |
| `target` | object ([WebhookTarget](#webhooktarget)) | required | Where the webhook is invoked. |
| `provisioners` | array of string | default `[]` | Provisioner names this webhook applies to. Empty means all provisioners. |
| `timeout` | [duration](#durations) | default `null` | Per-call timeout. |

The webhook reply is a single typed response: `allow: false` denies issuance (`403`), while a non-2xx status, a Lambda error, or a transport failure fails closed (`500`-class). Any other reply permits the request and may customize the certificate (subject, SANs, validity, key usages, extensions). See [webhooks](webhooks.md) for the full response schema.

### WebhookTarget

An internally tagged enum keyed on `type`: `"http"` or `"lambda"`.

#### `type: "http"`

| Field | Type | Required / default | Description |
| --- | --- | --- | --- |
| `type` | string | required | Literal `"http"`. |
| `url` | string | required | Endpoint URL the request is POSTed to. |
| `secret` | string | optional | Base64-encoded HMAC-SHA256 key. When set, requests carry an `X-Ayane-Signature` header (hex HMAC over the exact body bytes). |
| `bearer_token` | string | optional | Sent as `Authorization: Bearer <token>`. |

#### `type: "lambda"`

| Field | Type | Required / default | Description |
| --- | --- | --- | --- |
| `type` | string | required | Literal `"lambda"`. |
| `function_name` | string | required | Lambda function name or ARN, invoked synchronously. |
| `region` | string | optional | Region override for the Lambda client. |

```json
[
  {
    "name": "policy-gate",
    "provisioners": ["ci-issuer"],
    "timeout": "5s",
    "target": {
      "type": "http",
      "url": "https://policy.internal.example.com/ayane",
      "secret": "c2VjcmV0LWhtYWMta2V5"
    }
  },
  {
    "name": "enrich-from-lambda",
    "target": {
      "type": "lambda",
      "function_name": "ayane-enrich",
      "region": "us-east-1"
    }
  }
]
```

## events

Audit-event destinations. Each entry is an internally tagged enum keyed on `type`. Emission is best-effort: a sink failure is logged and never fails issuance. See [audit events](events.md) for the event schema.

| `type` | Fields | Description |
| --- | --- | --- |
| `stdout` | (none) | Write each event as a JSON line to stdout. |
| `file` | `path` (string, required) | Append each event as a JSON line to the file at `path`. |
| `event_bridge` | `event_bus_name`, `source`, `region` (all optional) | Publish events to AWS EventBridge via `PutEvents`. |

For `event_bridge`, `event_bus_name` defaults to `"default"` and `source` defaults to `"ayane"`; `region` overrides the EventBridge client region.

```json
[
  { "type": "stdout" },
  {
    "type": "event_bridge",
    "event_bus_name": "default",
    "source": "ayane",
    "region": "us-east-1"
  }
]
```

## storage

Backend for the issued-certificate inventory, revocation records, and the anti-replay (one-time-token) denylist. An internally tagged enum keyed on `type`, defaulting to an in-process SQLite database. See [storage](storage.md) for the item layout.

| `type` | Fields | Description |
| --- | --- | --- |
| `sqlite` (default) | `path` (string, default `":memory:"`) | A SQLite database. `:memory:` is in-process and non-durable (development and tests); a filesystem path is durable for a single node. `memory` is accepted as an alias for `:memory:`. |
| `dynamodb` | `table_name` (string, required), `region` (string, optional) | A single AWS DynamoDB table. |

```json
{ "type": "sqlite", "path": ":memory:" }
```

```json
{
  "type": "dynamodb",
  "table_name": "ayane-state",
  "region": "us-east-1"
}
```

## server

HTTP server settings. This object has `deny_unknown_fields`.

| Field | Type | Required / default | Description |
| --- | --- | --- | --- |
| `listen` | string | default `"0.0.0.0:9443"` | Listen address for the standalone (non-Lambda) server. |
| `external_url` | string | default `null` | Public base URL, used to validate token `aud` and DPoP `htu`. |
| `tls` | object ([TlsConfig](#tlsconfig)) | default (enabled) | Self-issued serving TLS for the standalone server. |

When `external_url` is unset, the server logs a warning and derives the token audience and DPoP `htu` from the request `Host` / `X-Forwarded-*` headers. Set `external_url` to the public base URL (for example `https://ca.example.com`) in production so that audience and proof-of-possession binding are not attacker-influenceable. Under AWS Lambda (`AWS_LAMBDA_RUNTIME_API` set), `listen` is ignored and `external_url` plays the same role. See [deployment](deployment.md).

```json
{
  "listen": "0.0.0.0:9443",
  "external_url": "https://ca.example.com",
  "tls": { "enabled": true, "dns_names": ["ca.example.com"] }
}
```

### TlsConfig

Self-issued serving TLS for the **standalone** server. When enabled (the default), the server mints a leaf certificate from its own configured CA, serves HTTPS with it, and renews it in the background before expiry — the same self-served-TLS pattern as step-ca. The serving leaf chains to the same root clients fetch from `GET /v1/roots`, so no separate serving certificate is needed. The serving private key is an ephemeral in-memory P-256 key, regenerated on every (re)issue and never written to disk. This object has `deny_unknown_fields`.

Under AWS Lambda the Function URL terminates TLS, so this block is **silently ignored** there (no error). To terminate TLS at a fronting proxy instead, set `enabled: false` and serve plaintext HTTP.

| Field | Type | Required / default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | default `true` | Serve HTTPS. When `false`, the standalone server serves plaintext HTTP. |
| `dns_names` | array of string | default `[]` | Explicit DNS SANs (see SAN resolution below). |
| `ip_addresses` | array of string | default `[]` | Explicit IP SANs. Each must parse as an IP address or boot fails. |
| `validity` | [duration](#durations) | default `"24h"` | Lifetime of each self-issued serving certificate. |
| `renew_before` | [duration](#durations) | default `validity / 3` | Re-issue this long before expiry (renews at ~2/3 of the lifetime). Must be shorter than `validity` or boot fails. |
| `renew_jitter` | [duration](#durations) | default `validity / 20` | Maximum random amount subtracted from the renewal instant, to de-sync a fleet. |

**SAN resolution.** Like step-ca, ayane does not infer the OS hostname; the serving SANs are resolved at startup in precedence order:

1. **Explicit** — if `dns_names` or `ip_addresses` is set, the combined list is used verbatim.
2. **From `external_url`** — otherwise the host of `server.external_url` becomes a single SAN (DNS, or IP if the host is an IP literal; the port is dropped).
3. **Loopback fallback** — otherwise `localhost`, `127.0.0.1`, `::1` (step-ca's default).

The subject `commonName` is the first DNS SAN. Note that with the default `listen` of `0.0.0.0:9443` and no `external_url` or explicit SANs, the loopback-only certificate will not match a remote client connecting by public name — set `external_url` or `dns_names` for any non-local deployment.

```json
{
  "listen": "0.0.0.0:9443",
  "external_url": "https://ca.example.com",
  "tls": {
    "enabled": true,
    "dns_names": ["ca.example.com"],
    "validity": "24h"
  }
}
```

## Full example

A complete configuration combining a KMS-backed CA, a JWK provisioner, templates, both webhook kinds, two event sinks, DynamoDB storage, and an external URL is shipped at [`examples/ayane.example.json`](../examples/ayane.example.json).

## See also

- [Authentication: tokens and DPoP](provisioners.md)
- [Webhooks](webhooks.md)
- [Deployment](deployment.md)
- [docs index](README.md)
