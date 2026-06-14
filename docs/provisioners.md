# Provisioners and issuance tokens

A *provisioner* is a named trust anchor that authorizes certificate issuance. To request a new certificate from `POST /v1/sign`, a client presents a one-time issuance token (OTT): a JWT signed by a provisioner's private key, which the CA verifies against that provisioner's configured public JWK. This page covers how to configure a JWK provisioner, the exact OTT claim set, the policies enforced at signing, and how to mint a token with the `ayane` CLI.

## JWK provisioners

Ayane ships a single provisioner type, `jwk`. Each provisioner holds a name and a public JWK; the operator distributes the matching private key to whoever is allowed to mint tokens. At validation time the CA selects the provisioner whose name equals the token's `iss` claim, then verifies the signature with that provisioner's key. The accepted JWS algorithm is *pinned* to the key type, which closes the JWT algorithm-confusion class of attacks (see [Algorithm pinning](#algorithm-pinning)).

If a provisioner's `type` is anything other than `jwk`, startup fails with a configuration error.

### Configuration

Provisioners are configured under the top-level `provisioners` array in the config JSON (see [configuration](configuration.md)).

| Field | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `name` | string | yes | — | Provisioner name. Must match the token `iss` claim. |
| `type` | string | no | `"jwk"` | Provisioner type. Only `"jwk"` is supported. |
| `key` | JWK object | yes | — | The public JWK used to verify token signatures. |
| `audiences` | array of string | no | `[]` | Explicit audience allowlist. When empty, `aud` is bound to the request endpoint URL (see [Audience binding](#audience-binding)). |
| `template` | string | no | unset | Name of a [certificate template](templates.md) applied to certificates issued under this provisioner. A dangling name fails issuance. |

The `key` field is a standard JWK. The key type determines the pinned algorithm:

| JWK `kty` / `crv` | Pinned JWS algorithm |
| --- | --- |
| `EC` / `P-256` | `ES256` |
| `EC` / `P-384` | `ES384` |
| `RSA` (default) | `RS256` |
| `RSA` with `alg` hint `RS384` / `RS512` / `PS256` / `PS384` / `PS512` | `RS384` / `RS512` / `PS256` / `PS384` / `PS512` |
| `OKP` / `Ed25519` | `EdDSA` |

A JWK whose key type cannot be mapped to one of these algorithms (for example an unsupported EC curve) fails startup with a configuration error.

#### Example provisioner

```json
{
  "provisioners": [
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
  ]
}
```

The matching private key (PEM) is held by the token minter, never by the CA. See [`examples/ayane.example.json`](../examples/ayane.example.json) for a complete config.

### Listing provisioners

`GET /v1/provisioners` returns each provisioner's `name`, `type` (always `jwk`), and `audiences`. The public key is never exposed.

```bash
ayane provisioners --url https://ca.example.com
```

```json
{
  "provisioners": [
    {
      "name": "ci-issuer",
      "type": "jwk",
      "audiences": ["https://ca.example.com/v1/sign"]
    }
  ]
}
```

## The one-time issuance token (OTT)

The OTT is a JWT signed by the provisioner key. It carries the standard registered claims plus the ayane-specific `sans` and `cnf` claims that constrain the certificate to be issued.

### Claims

| Claim | Type | Description |
| --- | --- | --- |
| `iss` | string | Issuer: the provisioner name. Selects which provisioner key verifies the token. |
| `aud` | string | Audience: the CA endpoint this token is valid for. See [Audience binding](#audience-binding). |
| `sub` | string | Subject: the certificate common name / primary identity. |
| `sans` | array of string | Permitted Subject Alternative Names. When empty, only `sub` is permitted. See [SAN policy](#san-subset-policy). |
| `iat` | number | Issued-at (epoch seconds). |
| `nbf` | number | Not-before (epoch seconds). Validated. |
| `exp` | number | Expiry (epoch seconds). Validated. |
| `jti` | string | Unique token id, used for one-time (anti-replay) enforcement. See [One-time enforcement](#one-time-replay-protection). |
| `cnf` | object | Optional confirmation binding the token to a specific CSR. See [CSR binding](#optional-csr-binding-cnf). |

The JWT layer requires `exp`, `nbf`, `aud`, `iss`, and `sub` to be present (`set_required_spec_claims`), validates `nbf` and `aud`, and applies a 60-second clock-skew leeway.

A minimal OTT payload:

```json
{
  "iss": "ci-issuer",
  "aud": "https://ca.example.com/v1/sign",
  "sub": "host.example.com",
  "sans": ["host.example.com", "host.internal"],
  "iat": 1750000000,
  "nbf": 1749999995,
  "exp": 1750000300,
  "jti": "9f2c0a4e8b1d4f6a..."
}
```

### Audience binding

By default the token is bound to the request endpoint. If the provisioner's `audiences` list is empty, the CA requires `aud` to exactly equal the full URL of the endpoint that received the request (for example `https://ca.example.com/v1/sign`). This prevents a token minted for one endpoint from being replayed against another.

If the provisioner sets a non-empty `audiences` list, that list becomes a fixed allowlist instead: `aud` must match one of the configured values, and the operator is then responsible for endpoint scoping. The example above pins `audiences` to the sign endpoint explicitly.

The endpoint URL the CA compares against is derived from `server.external_url` when set; otherwise it is reconstructed from the request `Host` / `X-Forwarded-*` headers. Set `external_url` in production so the audience is deterministic — see [configuration](configuration.md) and [deployment](deployment.md).

### SAN subset policy

The OTT authorizes a *set of permitted SANs*; the CSR may request a subset of them, never more.

- The permitted set is `sans` if non-empty, otherwise the single value `sub`.
- Every SAN actually requested in the CSR must be a member of the permitted set, or issuance is rejected with `403 Forbidden` (`SAN <name> is not permitted by the token`).
- If the CSR requests no SANs, the certificate is issued with the full permitted set.

In other words, a token with `sub: "host.example.com"` and no `sans` permits exactly one identity; to permit additional names the minter must enumerate them in `sans`. Webhooks may add further SANs after this check via enrichment — see [webhooks](webhooks.md).

### Optional CSR binding (cnf)

The token may pin itself to a single CSR via an RFC 7800-style confirmation claim. When present, `cnf` carries `x5t#S256`, the base64url (no padding) SHA-256 digest of the DER-encoded CSR:

```json
{
  "cnf": { "x5t#S256": "Lr...base64url-sha256-of-CSR-DER..." }
}
```

At signing, if `cnf.x5t#S256` is present it must equal the SHA-256 thumbprint of the presented CSR's DER, otherwise the request is rejected with `403 Forbidden` (`token is bound to a different CSR`). This stops a captured token from being replayed against a different CSR / key. The binding is optional: a token without `cnf` may be used with any conforming CSR (still subject to the SAN policy and one-time enforcement). The `ayane token` CLI does not currently set `cnf`; populate it from your own minting tooling when you want CSR binding.

### Algorithm pinning

The CA does not trust the token header's `alg` field. For each provisioner it derives the single permitted algorithm from the JWK key type (see the table in [Configuration](#configuration)) and validates the token only with that algorithm. An attacker cannot, for example, downgrade an EC verification key to HMAC by forging the header. The `iss` claim is read unverified solely to select the provisioner; the signature is then verified with that provisioner's pinned key and algorithm.

### One-time (replay) protection

Each token's `jti` may be used only once. After all other checks pass — and only just before issuance commits — the CA atomically claims the `jti` in storage under the namespace `ott#<jti>`. A second presentation of the same token fails with `401 Unauthorized` (`token or proof has already been used`). Claiming late means a transient template or webhook failure never burns a still-valid token.

The denylist record's expiry is floored to outlive the validator's acceptance window (`exp` plus the replay leeway), so a token cannot be replayed within its own validity even across the skew window. DPoP proofs (used by renew/rekey/self-revoke) live in a separate `dpop#<jti>` namespace, so the two anti-replay spaces never collide. With the DynamoDB backend these records carry a `ttl` attribute for automatic expiry — see [storage](storage.md).

## Minting a token

Use `ayane token` to sign an OTT with a provisioner's private key. The token is printed to stdout.

| Flag | Required | Default | Description |
| --- | --- | --- | --- |
| `--key <path>` | yes | — | Provisioner private key PEM. |
| `--issuer <name>` | yes | — | Provisioner name (token `iss`). |
| `--url <url>` | one of url/audience | — | CA base URL; the audience is derived as `<url>/v1/<operation>`. |
| `--audience <aud>` | one of url/audience | — | Explicit token audience (overrides `--url` / `--operation` derivation). |
| `--operation <op>` | no | `sign` | Operation the token authorizes: `sign` or `revoke`. For `revoke`, set `--subject` to the certificate serial number. |
| `--subject <s>` | yes | — | Certificate subject / common name (or, for `revoke`, the serial number). |
| `--san <s>` | no (repeatable) | — | Permitted SANs. |
| `--validity <dur>` | no | `5m` | Token lifetime, e.g. `5m`, `1h`. Units: `s`, `m`, `h`, `d`. |

The CLI fills `iat` to now, `nbf` to now minus 5 seconds, `exp` to now plus the validity, and `jti` to a fresh random 128-bit hex value. The JWS algorithm is taken from the private key.

### Mint a sign token

```bash
ayane token \
  --key ci-issuer.key.pem \
  --issuer ci-issuer \
  --url https://ca.example.com \
  --subject host.example.com \
  --san host.example.com \
  --san host.internal \
  --validity 5m
```

This derives `aud` as `https://ca.example.com/v1/sign` (because `--operation` defaults to `sign`). Feed the printed token straight into `ayane certificate`:

```bash
TOKEN=$(ayane token --key ci-issuer.key.pem --issuer ci-issuer \
  --url https://ca.example.com --subject host.example.com --san host.example.com)

ayane certificate \
  --url https://ca.example.com \
  --token "$TOKEN" \
  --subject host.example.com \
  --san host.example.com \
  --key-out host.key.pem \
  --out host.crt.pem
```

If the provisioner pins `audiences` to a value that differs from `<url>/v1/sign`, pass `--audience` to match it exactly:

```bash
ayane token --key ci-issuer.key.pem --issuer ci-issuer \
  --audience https://ca.example.com/v1/sign \
  --subject host.example.com --san host.example.com
```

### Mint a revoke token

A provisioner-authorized revocation uses a token whose `--operation` is `revoke` and whose `--subject` is the certificate serial number. The derived audience targets the revoke endpoint, and the CA additionally checks that the token's `sub` (as a serial) matches the serial being revoked.

```bash
ayane token --key ci-issuer.key.pem --issuer ci-issuer \
  --url https://ca.example.com \
  --operation revoke \
  --subject 7263... \
  --validity 5m
```

See [revocation](renewal-revocation.md) for the full revoke flow, and [certificates](cli.md) for issuance, renewal, and rekey.

## See also

- [configuration](configuration.md)
- [certificates](cli.md)
- [templates](templates.md)
- [docs index](README.md)
