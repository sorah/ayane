# Certificate templates

A certificate template declares the *shape* of an issued certificate — its key usages, extended key usages, basic constraints, and validity policy. Templates are structured data, not free-form text: the per-request identity (subject and SANs) and the computed key identifiers are supplied by the CA when the template is rendered into concrete X.509 extensions.

Templates are defined under the top-level `templates` map in [configuration](configuration.md) and referenced by name from a [provisioner](provisioners.md) or from `default_template`.

```json
{
  "templates": {
    "server": {
      "key_usage": ["digital_signature", "key_encipherment"],
      "extended_key_usage": ["server_auth"],
      "default_validity": "24h",
      "min_validity": "5m",
      "max_validity": "168h",
      "backdate": "1m"
    }
  },
  "default_template": "server"
}
```

## Template fields

Every field is optional; omitting the whole template object (or selecting the built-in default) yields a TLS server leaf valid for 24 hours.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `key_usage` | array of names | `["digital_signature"]` | `keyUsage` extension bits (marked critical). |
| `extended_key_usage` | array of names | `["server_auth"]` | `extendedKeyUsage` purposes (marked non-critical). |
| `is_ca` | bool | `false` | `basicConstraints` CA flag. |
| `path_len` | integer (`u8`) | unset | `basicConstraints` `pathLenConstraint`; only emitted when `is_ca` is `true`. |
| `set_common_name` | bool | `true` | Set the subject `commonName` from the token subject. |
| `default_validity` | duration | `"24h"` | Lifetime used when the request does not pin `not_after`. |
| `min_validity` | duration | `"60s"` | Minimum acceptable lifetime; shorter requests are rejected. |
| `max_validity` | duration | `"24h"` | Maximum acceptable lifetime; longer requests are clamped down. |
| `backdate` | duration | `"60s"` | Amount subtracted from `notBefore` to tolerate clock skew. |

Unknown fields are rejected: the template object uses `deny_unknown_fields`, so a typo in a key name fails configuration parsing at startup.

### `key_usage` names

Each name maps to one `keyUsage` bit. The values are snake_case in JSON. The extension is only emitted when at least one bit is set; an empty `key_usage` array omits the `keyUsage` extension entirely.

| Name | `keyUsage` bit |
| --- | --- |
| `digital_signature` | `digitalSignature` |
| `content_commitment` | `nonRepudiation` (bit 1) |
| `key_encipherment` | `keyEncipherment` |
| `data_encipherment` | `dataEncipherment` |
| `key_agreement` | `keyAgreement` |
| `key_cert_sign` | `keyCertSign` |
| `crl_sign` | `cRLSign` |
| `encipher_only` | `encipherOnly` |
| `decipher_only` | `decipherOnly` |

`content_commitment` also accepts the alias `non_repudiation`; both spellings deserialize to the same bit.

### `extended_key_usage` names

Each name maps to a well-known EKU OID (RFC 5280). When `extended_key_usage` is empty, no `extendedKeyUsage` extension is emitted.

| Name | Purpose / OID |
| --- | --- |
| `server_auth` | TLS server authentication (`id-kp-serverAuth`) |
| `client_auth` | TLS client authentication (`id-kp-clientAuth`) |
| `code_signing` | Code signing (`id-kp-codeSigning`) |
| `email_protection` | S/MIME email protection (`id-kp-emailProtection`) |
| `time_stamping` | Trusted timestamping (`id-kp-timeStamping`) |
| `ocsp_signing` | OCSP response signing (`id-kp-OCSPSigning`) |

### Basic constraints (`is_ca`, `path_len`)

`is_ca` sets the `basicConstraints` CA flag. The `basicConstraints` extension is always emitted and always critical. `path_len` populates `pathLenConstraint`, but is only meaningful — and only included — when `is_ca` is `true`; for leaf templates (`is_ca: false`) any `path_len` value is ignored.

### `set_common_name`

When `true` (the default), the CA copies the token subject (the JWT `sub` claim) into the certificate subject `commonName`. Set it to `false` to issue SAN-only certificates with an empty subject DN. When the subject DN is empty, the `subjectAltName` extension is marked critical, as required for a valid certificate.

## Duration string format

All duration fields (`default_validity`, `min_validity`, `max_validity`, `backdate`) accept a single integer followed by a one-character unit suffix.

```
<integer><unit>
```

| Unit | Meaning | Example |
| --- | --- | --- |
| `s` | seconds | `"30s"` |
| `m` | minutes | `"5m"` |
| `h` | hours | `"24h"`, `"168h"` |
| `d` | days | `"90d"` |
| `w` | weeks | `"2w"` |

A value without a unit (`"10"`), an unknown unit (`"10y"`), or a non-numeric value is rejected at startup. There is no compound form: write `"36h"`, not `"1d12h"`.

## Template selection

When a request is authorized, the CA picks exactly one template using this precedence:

1. The `template` named on the [provisioner](provisioners.md) that issued the token, if set.
2. Otherwise the top-level `default_template`, if set.
3. Otherwise the built-in fallback template (equivalent to an all-defaults `CertificateTemplate`: a `server_auth` leaf with `digital_signature`, 24-hour validity).

A name referenced in step 1 or 2 must exist in the `templates` map. If it does not, issuance fails with a configuration error (`unknown template "<name>"`). Because requests flow through `default_template` whenever a provisioner does not pin a template, you should ensure any name you set there is defined in `templates`.

## Validity clamping

The validity window is computed from the request and the template's `backdate`, `default_validity`, `min_validity`, and `max_validity`:

- **`notBefore`** is the requested `not_before` (or *now* if absent), minus `backdate`.
- **Requested lifetime** is `requested_not_after - notBefore` when the request pins `not_after`; otherwise it is `default_validity + backdate`.
- If the requested lifetime is **below `min_validity`**, the request is rejected with `400 Bad Request` (`requested validity <n>s is below the minimum <min>s`). A `not_after` that precedes `not_before` is likewise a `400` (`notAfter precedes notBefore`).
- The lifetime is then **capped at `max_validity + backdate`**; anything longer is silently clamped down to that ceiling.
- **`notAfter`** is `notBefore + clamped_lifetime`.

The `backdate` is added to both the default and the maximum, so a template with `default_validity: "24h"`, `max_validity: "24h"`, and `backdate: "60s"` produces a certificate that is genuinely valid for 24 hours of *future* time after accounting for the 60-second backdate.

[Webhooks](webhooks.md) may adjust the lifetime: a webhook response can return a `notAfter` that shortens or, on `sign`, extends the window. The template's clamp is applied first, and the webhook's `notAfter` is then re-clamped to `max_validity + backdate`, so a webhook can move `notAfter` anywhere up to that ceiling but never beyond it.

## Examples

### TLS server certificate

A server leaf good for up to a week, defaulting to one day. `key_encipherment` is included for RSA key-exchange cipher suites; ECDSA-only deployments can drop it.

```json
{
  "templates": {
    "server": {
      "key_usage": ["digital_signature", "key_encipherment"],
      "extended_key_usage": ["server_auth"],
      "default_validity": "24h",
      "min_validity": "5m",
      "max_validity": "168h",
      "backdate": "1m"
    }
  }
}
```

### TLS client certificate

A client-auth leaf with a fixed 24-hour lifetime (default and max are equal, so the lifetime cannot be extended past a day).

```json
{
  "templates": {
    "client": {
      "key_usage": ["digital_signature"],
      "extended_key_usage": ["client_auth"],
      "default_validity": "24h",
      "max_validity": "24h"
    }
  }
}
```

### SAN-only certificate

To issue a certificate with no subject `commonName` — relying solely on SANs — disable `set_common_name`. The `subjectAltName` extension becomes critical automatically.

```json
{
  "templates": {
    "san-only": {
      "set_common_name": false,
      "extended_key_usage": ["server_auth", "client_auth"]
    }
  }
}
```

## See also

- [Configuration](configuration.md) — the full JSON schema, including the `templates` map and `default_template`.
- [Provisioners](provisioners.md) — how a provisioner's `template` field selects a template per issuer.
- [Webhooks](webhooks.md) — webhooks that add SANs or adjust `notAfter`.
- [docs index](README.md)
