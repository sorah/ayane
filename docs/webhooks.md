# Issuance webhooks

Issuance webhooks let an external service gate and/or customize certificate issuance. Before ayane signs (or reissues) a certificate it can call out to one or more webhooks, each of which replies with a single typed response that may **deny** the request and/or **customize** the certificate (subject, SANs, validity, key usages, or arbitrary extensions). There is no separate "authorizing" vs "enriching" kind — one response does both. Webhooks are configured under the top-level `webhooks` key and are invoked over HTTPS (optionally HMAC-signed) or a synchronous AWS Lambda invocation.

Webhooks run for the `sign`, `renew`, and `rekey` operations. The `operation` field in the request body tells the webhook which one is in progress. For `renew`/`rekey` the request is not tied to a provisioner, so only webhooks that apply to all provisioners (an empty `provisioners` filter) are consulted.

## Configuration

Webhooks are listed under `webhooks` in the [configuration](configuration.md) file. Each entry is a `WebhookConfig`:

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `name` | string | yes | — | Unique webhook name; appears in denial errors and logs |
| `target` | object | yes | — | Transport, tagged by `type` (see below) |
| `provisioners` | array of string | no | `[]` (all) | Provisioner names this webhook applies to; empty means every provisioner |
| `timeout` | duration string | no | none | Per-call timeout (e.g. `"5s"`). HTTP only; bounds each request |

The configuration struct rejects unknown fields (`deny_unknown_fields`), so a typo in a key fails startup rather than being silently ignored.

### Provisioner filtering

`provisioners` selects which token-issued requests trigger the webhook. The matching rule (`applies_to`) is:

- Empty list — the webhook applies to **all** requests.
- Non-empty list — the webhook applies only when the request's provisioner name is in the list. A request with no provisioner (`None`) does **not** match a non-empty filter. Because `renew`/`rekey` carry no provisioner, a non-empty filter excludes them.

### `target` — HTTP

```json
{
  "type": "http",
  "url": "https://policy.internal.example.com/ayane",
  "secret": "c2VjcmV0LWhtYWMta2V5",
  "bearer_token": "optional-static-bearer"
}
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `type` | `"http"` | yes | Selects the HTTP transport |
| `url` | string | yes | Endpoint that receives the `POST` |
| `secret` | string | no | **Standard base64** of the HMAC-SHA256 key. When set, requests carry `X-Ayane-Signature`. A base64 decode failure is a startup configuration error |
| `bearer_token` | string | no | Sent verbatim as `Authorization: Bearer <token>` |

### `target` — Lambda

```json
{
  "type": "lambda",
  "function_name": "ayane-enrich",
  "region": "us-east-1"
}
```

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `type` | `"lambda"` | yes | Selects the Lambda transport |
| `function_name` | string | yes | Function name or ARN, invoked synchronously (`RequestResponse`) |
| `region` | string | no | Region override; defaults to the ambient AWS configuration |

The request JSON is the Lambda invocation payload, and the function's returned payload is decoded as the reply. A non-2xx Lambda status code, a `FunctionError` in the response, or an empty payload is treated as a failure.

### Example

```json
{
  "webhooks": [
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
}
```

Webhooks run in configuration order. Each applicable webhook receives the **original** request (it does not observe an earlier webhook's customization); their responses are layered in order onto the pending certificate. Any webhook may deny, and the first denial short-circuits the chain. When multiple webhooks set the same scalar field (subject, validity, key usages) the last one wins; `additional_sans` and `additional_extensions` accumulate across all of them.

## Request body

ayane POSTs the same JSON document to every webhook (HTTP body or Lambda payload). It describes the certificate that is about to be issued, after the provisioner token (for `sign`) or the previous certificate (for `renew`/`rekey`) and the certificate template have been applied, but before any webhook customization. Field names are snake_case.

| Field | Type | Always present | Description |
| --- | --- | --- | --- |
| `timestamp` | string (RFC 3339) | yes | Time of the call |
| `operation` | string | yes | `"sign"`, `"renew"`, or `"rekey"` |
| `provisioner` | string | no | Provisioner name; omitted for `renew`/`rekey` and when there is none |
| `subject` | string | yes | Baseline subject common name |
| `sans` | array of string | yes | Baseline Subject Alternative Names as strings |
| `csr_der` | string | no | **Standard base64** of the CSR DER; present for `sign` and `rekey` |
| `previous_certificate_der` | string | no | **Standard base64** of the previous certificate DER; present for `renew` and `rekey` |
| `not_before` | string (RFC 3339) | yes | Baseline notBefore |
| `not_after` | string (RFC 3339) | yes | Baseline notAfter |

`provisioner`, `csr_der`, and `previous_certificate_der` are omitted entirely when absent (they are not sent as `null`). Example body:

```json
{
  "timestamp": "2026-06-14T00:00:00Z",
  "operation": "sign",
  "provisioner": "ci-issuer",
  "subject": "example.com",
  "sans": ["example.com", "www.example.com"],
  "csr_der": "MIIB...",
  "not_before": "2026-06-14T00:00:00Z",
  "not_after": "2026-06-15T00:00:00Z"
}
```

### HMAC signing and bearer auth (HTTP)

For HTTP targets the request always carries `Content-Type: application/json`. When `secret` is configured, ayane computes a lowercase hex HMAC-SHA256 over the **exact body bytes** that are sent and adds it as a header:

```
X-Ayane-Signature: <lowercase-hex-hmac-sha256-of-body>
```

The HMAC key is the raw bytes obtained by **standard-base64-decoding** the configured `secret`. Receivers must verify the signature over the raw request body before parsing it (any reserialization may change byte order or whitespace and break the comparison). Use a constant-time comparison.

When `bearer_token` is configured it is sent as:

```
Authorization: Bearer <bearer_token>
```

## Response body

The webhook replies with a single JSON object. Every field is optional; an absent field leaves the corresponding certificate property at its pre-webhook (baseline) value. Field names are snake_case (matching the request body).

| Field | Type | Meaning |
| --- | --- | --- |
| `allow` | bool | `false` always denies. For an authorized provisioner, `true`/absent permits; for an unauthorized one, `true` is required to permit (see [Deny semantics](#deny-semantics)) |
| `deny_reason` | string | Human-readable denial reason, surfaced when `allow` is `false` |
| `subject_common_name` | string | Override the subject common name |
| `sans` | array of string | Replace the SAN set entirely |
| `additional_sans` | array of string | Add SANs to the (possibly replaced) set; duplicates are skipped |
| `not_before` | string (RFC 3339) | Override notBefore |
| `not_after` | string (RFC 3339) | Override notAfter (re-clamped, see below) |
| `key_usage` | array of [key-usage name](configuration.md#key-usage-names) | Override the `keyUsage` set |
| `extended_key_usage` | array of [EKU name](configuration.md#extended-key-usage-names) | Override the `extendedKeyUsage` set |
| `additional_extensions` | array of object | Inject arbitrary extensions (replacing any with the same OID) |

Each `additional_extensions` entry is `{ "oid": "1.2.3.4", "value": "<standard-base64 of the DER extension value>", "critical": false }`. `value` is the inner extension value, not the surrounding OCTET STRING. The subject and authority key identifiers are always recomputed last, so they cannot be overridden by `additional_extensions`.

### Deny semantics

The default direction depends on the provisioner's [`authorized`](provisioners.md#authorization-authorized) flag:

- **Authorized provisioner (default-allow)** — the common case (`jwk`). A request is denied only when a webhook returns `allow` exactly `false`. A reply of `{"allow": true}`, `{}`, or one where `allow` is missing **permits** it. No webhook is required.
- **Unauthorized provisioner (default-deny)** — a provisioner with `authorized: false` (the default for `jwks`). The token only authenticates; issuance is refused **unless** an applicable webhook returns `allow` exactly `true`. A silent reply (`{}` / `allow` absent) is *not* enough, and if no webhook applies at all the request is denied. This is where the webhook grants access and typically also sets the certificate's `subject_common_name`/`sans`.

In both directions an explicit `allow: false` denies immediately and short-circuits the chain. A denial returns `403 Forbidden`; the detail is `deny_reason` when provided, otherwise `issuance denied by webhook "<name>"` (or `issuance was not authorized by any webhook` when an unauthorized request received no explicit grant).

### Validity semantics

A webhook may override `notBefore`/`notAfter`, but the result is re-clamped before issuance so a webhook can never extend issuance past policy:

- On `sign`, `notAfter` is bounded by the resolved template's `max_validity` (plus the skew backdate). A webhook may move `notAfter` earlier, or later **up to** the template maximum — never beyond it.
- On `renew`/`rekey`, there is no template to clamp against, so `notAfter` may not exceed the previous certificate's lifetime (the baseline window). A webhook may only shorten it.

A malformed `notAfter` that fails RFC 3339 parsing is rejected as a bad request. After re-clamping, if the validity window has collapsed (`notAfter <= notBefore`), issuance fails with `403 Forbidden` and the detail `certificate validity window collapsed`.

Example reply that adds a SAN and shortens the lifetime:

```json
{
  "allow": true,
  "additional_sans": ["alt.example.com", "192.0.2.10"],
  "not_after": "2026-06-14T12:00:00Z"
}
```

## Fail-closed behavior

Webhooks run before the one-time issuance token (or DPoP proof) is consumed and before the certificate is signed, so a webhook failure aborts issuance cleanly without burning the credential. Failures fail closed:

- **Denial**: a reply with `allow: false` denies the request (`403 Forbidden`).
- **Transport failure**: a non-2xx HTTP status, a request/connection error, a timeout, a Lambda `FunctionError` or non-2xx status code, an empty Lambda payload, or a response that cannot be decoded all propagate as an error and abort issuance. For these internal/transport failures the surface error is `500`-class; only an explicit `allow: false` yields `403`.

Because responses are applied in order and any webhook may deny, the first failure short-circuits the chain. No partial certificate is ever issued.

## Worked example: HTTP webhook with HMAC verification

Configure the webhook with a base64-encoded key:

```bash
# Generate a key and base64-encode it for the config "secret" field.
KEY=$(openssl rand 32)
printf '%s' "$KEY" | base64
# -> put this value in target.secret
```

A minimal Ruby receiver that verifies `X-Ayane-Signature` over the raw body before trusting it:

```ruby
require "sinatra"
require "openssl"
require "json"
require "base64"

# The same value placed in target.secret, base64-decoded back to raw bytes.
HMAC_KEY = Base64.strict_decode64(ENV.fetch("AYANE_WEBHOOK_SECRET_B64"))

post "/ayane" do
  body = request.body.read
  expected = OpenSSL::HMAC.hexdigest("SHA256", HMAC_KEY, body)
  got = request.env["HTTP_X_AYANE_SIGNATURE"].to_s
  halt 401 unless got.bytesize == expected.bytesize &&
                  OpenSSL.secure_compare(got, expected)

  req = JSON.parse(body)
  # Only allow names under example.com; deny otherwise.
  ok = req["sans"].all? { |s| s.end_with?(".example.com") || s == "example.com" }
  content_type :json
  ok ? { allow: true }.to_json : { allow: false, deny_reason: "name outside example.com" }.to_json
end
```

Run it and point the config `url` at it:

```bash
AYANE_WEBHOOK_SECRET_B64="c2VjcmV0LWhtYWMta2V5" ruby receiver.rb
```

To verify the signature on the command line against a captured body:

```bash
# raw key bytes from the base64 secret
echo -n "c2VjcmV0LWhtYWMta2V5" | base64 -d > /tmp/hmac.key
# recompute over the exact bytes ayane sent (stored in body.json)
openssl dgst -sha256 -mac HMAC -macopt hexkey:"$(xxd -p -c256 /tmp/hmac.key)" body.json
```

## Worked example: Lambda customizing webhook

A Lambda function receives the request JSON as its event payload and returns the reply payload. This example adds a SAN and clamps the lifetime to at most one hour from issuance:

```python
import datetime

def handler(event, context):
    not_before = datetime.datetime.fromisoformat(event["not_before"].replace("Z", "+00:00"))
    cap = not_before + datetime.timedelta(hours=1)
    return {
        "allow": True,
        "additional_sans": [f"{event['subject']}.internal"],
        "not_after": cap.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
```

Grant the ayane server's IAM role `lambda:InvokeFunction` on the target function, then reference it:

```json
{
  "name": "enrich-from-lambda",
  "target": { "type": "lambda", "function_name": "ayane-enrich", "region": "us-east-1" }
}
```

On `sign`, returning a `notAfter` later than the template maximum is clamped down to that maximum; returning an earlier one shortens the certificate. On `renew`/`rekey`, `notAfter` is clamped to the previous certificate's lifetime.

## See also

- [Configuration](configuration.md)
- [Audit events](events.md)
- [Provisioners and tokens](provisioners.md)
- [docs index](README.md)
