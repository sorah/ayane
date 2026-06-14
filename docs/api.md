# HTTP API reference

The ayane certificate authority exposes a small JSON/HTTP API under the `/v1`
prefix. The same router is served standalone (axum over tokio) and behind AWS
Lambda Function URLs; TLS is always terminated externally. Every endpoint
returns either a typed JSON body on success or an RFC 7807
`application/problem+json` body on failure.

All PEM-bearing fields carry standard PEM text (with `-----BEGIN ...-----`
armor), timestamps are RFC 3339 strings, and serial numbers are decimal strings
on output (an optional `0x` hex form is accepted on input for revocation).

## Endpoint summary

| Method | Path | Auth | Success status |
| --- | --- | --- | --- |
| `GET` | `/v1/health` | none | `200 OK` |
| `GET` | `/v1/roots` | none | `200 OK` |
| `GET` | `/v1/provisioners` | none | `200 OK` |
| `POST` | `/v1/sign` | OTT token (in body) | `201 Created` |
| `POST` | `/v1/renew` | `DPoP` header | `201 Created` |
| `POST` | `/v1/rekey` | `DPoP` header | `201 Created` |
| `POST` | `/v1/revoke` | OTT token, or `DPoP` header + certificate | `200 OK` |

The base URL is the public address of your CA. In the examples below it is
`https://ca.example`. See [configuration](configuration.md) for how the server
derives the canonical base URL (`server.external_url`), which determines the
audience and DPoP `htu` values described under [authentication](#authentication).

## Authentication

ayane has no sessions, cookies, or API keys. Each mutating request authenticates
itself with one of two short-lived, single-use credentials.

### One-time issuance token (OTT)

A signing request is authorized by a JWT (the OTT) issued by a configured
provisioner. The token is passed in the request body as the `token` field. Its
claims are:

| Claim | Required | Meaning |
| --- | --- | --- |
| `iss` | yes | Provisioner name; selects the verifying key. |
| `aud` | yes | The CA endpoint URL the token is valid for. By default this must equal the request URL (e.g. `https://ca.example/v1/sign`); if the provisioner sets an explicit `audiences` list, `aud` must be one of those values instead. |
| `sub` | yes | Subject / common name (or, for a revocation token, the serial number). |
| `sans` | no | Array of permitted Subject Alternative Names. When empty or absent, only `sub` is permitted. |
| `iat` | yes | Issued-at (epoch seconds). |
| `nbf` | yes | Not-before (epoch seconds). |
| `exp` | yes | Expiry (epoch seconds). |
| `jti` | yes | Unique token id, enforced as one-time (anti-replay). |
| `cnf` | no | RFC 7800 confirmation. When present, `cnf["x5t#S256"]` is the base64url (no padding) SHA-256 digest of the DER-encoded CSR, binding the token to one specific CSR. |

The JWT signing algorithm is pinned to the provisioner's JWK key type
(`ES256`, `ES384`, `RS256`, `RS384`, `RS512`, or `EdDSA`), so the server is not
vulnerable to algorithm-confusion attacks. The validated registered claims
(`exp`, `nbf`, `aud`, `iss`, `sub`) are required, and a 60-second leeway is
applied to time-based claims. See [tokens and authentication](provisioners.md) for the
full token model and [provisioners](provisioners.md) for key configuration.

### DPoP proof

Renewal, rekeying, and self-service revocation prove possession of an existing
certificate's private key with an RFC 9449 DPoP proof. The proof is a compact
JWS passed in the **`DPoP`** request header (note the exact casing). Its JOSE
header has `typ` set to `dpop+jwt` and `alg` matching the certificate's key. The
server verifies the proof's signature **directly against the public key of the
presented certificate** — a valid proof is itself evidence the caller holds the
key. The proof claims are:

| Claim | Meaning |
| --- | --- |
| `htm` | HTTP method, compared case-insensitively against `POST`. |
| `htu` | Full request target URI; must equal the request URL (e.g. `https://ca.example/v1/renew`). |
| `iat` | Issued-at (epoch seconds). The proof must be no older than 300 seconds, with a 60-second future-skew tolerance. |
| `jti` | Unique proof id, enforced as one-time (anti-replay). |
| `nonce` | Optional server-provided nonce. |

For renewal, rekeying, and DPoP self-revocation the certificate must also have
been issued by this CA (signature check), and must not be revoked or expired.

### Anti-replay

Both the OTT `jti` and the DPoP `jti` are claimed exactly once via storage, in
separate namespaces (`ott#<jti>` and `dpop#<jti>`). The `jti` is claimed only
after all other checks pass; a replayed credential is rejected with `401` (OTT)
or surfaces as a uniqueness conflict. See [storage](storage.md) for the
denylist item layout and TTL handling.

## GET /v1/health

Liveness probe. No authentication.

### Request

```bash
curl https://ca.example/v1/health
```

### Response — `200 OK`

```json
{
  "status": "ok"
}
```

## GET /v1/roots

Returns the CA's trusted root certificate(s) in PEM, for clients building a trust
store. No authentication.

### Request

```bash
curl https://ca.example/v1/roots
```

### Response — `200 OK`

```json
{
  "certificates": [
    "-----BEGIN CERTIFICATE-----\nMIIB...root...\n-----END CERTIFICATE-----\n"
  ]
}
```

| Field | Type | Description |
| --- | --- | --- |
| `certificates` | array of string | PEM-encoded trusted root certificate(s). |

## GET /v1/provisioners

Returns public, non-secret metadata about configured provisioners. No
authentication and no key material is disclosed.

### Request

```bash
curl https://ca.example/v1/provisioners
```

### Response — `200 OK`

```json
{
  "provisioners": [
    {
      "name": "ops-jwk",
      "type": "jwk",
      "audiences": ["https://ca.example/v1/sign"]
    }
  ]
}
```

| Field | Type | Description |
| --- | --- | --- |
| `provisioners[].name` | string | Provisioner name; matches the `iss` claim of tokens it issues. |
| `provisioners[].type` | string | Provisioner kind, e.g. `"jwk"`. |
| `provisioners[].audiences` | array of string | Accepted token audiences. Omitted from the JSON when empty (default endpoint-binding applies). |

## POST /v1/sign

Issues a brand new certificate. Authorized by an OTT in the request body. The
CSR's public key becomes the certificate's public key, and the requested SANs
must be permitted by the token.

### Request body

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `csr` | string | yes | PEM-encoded PKCS#10 certificate signing request. |
| `token` | string | yes | One-time issuance token (a signed JWT). |
| `not_before` | string | no | Requested notBefore (RFC 3339). Clamped to provisioner/template policy. |
| `not_after` | string | no | Requested notAfter (RFC 3339). Clamped to provisioner/template policy. |

### Request

```bash
curl -X POST https://ca.example/v1/sign \
  -H 'Content-Type: application/json' \
  -d '{
    "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----\n",
    "token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJvcHMtandrIiwiYXVkIjoiaHR0cHM6Ly9jYS5leGFtcGxlL3YxL3NpZ24iLCJzdWIiOiJob3N0LmV4YW1wbGUiLCJzYW5zIjpbImhvc3QuZXhhbXBsZSJdLCJqdGkiOiIuLi4ifQ.signature"
  }'
```

### Response — `201 Created`

```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\nMIID...leaf...\n-----END CERTIFICATE-----\n",
  "chain": [
    "-----BEGIN CERTIFICATE-----\nMIID...intermediate...\n-----END CERTIFICATE-----\n"
  ],
  "serial_number": "29384719283471928374",
  "not_after": "2026-06-15T12:00:00Z"
}
```

| Field | Type | Description |
| --- | --- | --- |
| `certificate` | string | PEM-encoded issued leaf certificate. |
| `chain` | array of string | PEM-encoded issuer chain: immediate issuer first, up to (but not including) the root unless the CA is configured to bundle it. |
| `serial_number` | string | Decimal serial number of the issued certificate. |
| `not_after` | string | notAfter of the issued certificate (RFC 3339). |

## POST /v1/renew

Renews an existing certificate, keeping its public key. Authorized by a `DPoP`
header proving possession of the certificate's private key.

### Headers

| Header | Required | Description |
| --- | --- | --- |
| `DPoP` | yes | RFC 9449 DPoP proof JWS. The proof's key must match the presented certificate's public key. See [DPoP proof](#dpop-proof). |

### Request body

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `certificate` | string | yes | PEM-encoded leaf certificate to be renewed (a fullchain is also accepted; the leaf is used). |

### Request

```bash
curl -X POST https://ca.example/v1/renew \
  -H 'Content-Type: application/json' \
  -H 'DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Li4ufX0.eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9jYS5leGFtcGxlL3YxL3JlbmV3IiwiaWF0IjoxNzE4MzYwMDAwLCJqdGkiOiIuLi4ifQ.signature' \
  -d '{
    "certificate": "-----BEGIN CERTIFICATE-----\nMIID...current-leaf...\n-----END CERTIFICATE-----\n"
  }'
```

### Response — `201 Created`

Returns the same `CertificateResponse` body as [`POST /v1/sign`](#post-v1sign).

## POST /v1/rekey

Renews an existing certificate with a **new** key pair. As with renewal, the
`DPoP` proof must prove possession of the *existing* certificate's private key;
the new public key is taken from the supplied CSR.

### Headers

| Header | Required | Description |
| --- | --- | --- |
| `DPoP` | yes | RFC 9449 DPoP proof JWS, bound to the existing certificate's key. See [DPoP proof](#dpop-proof). |

### Request body

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `certificate` | string | yes | PEM-encoded leaf certificate to be rekeyed. |
| `csr` | string | yes | PEM-encoded PKCS#10 CSR carrying the new public key. |

### Request

```bash
curl -X POST https://ca.example/v1/rekey \
  -H 'Content-Type: application/json' \
  -H 'DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2In0.eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9jYS5leGFtcGxlL3YxL3Jla2V5IiwiaWF0IjoxNzE4MzYwMDAwLCJqdGkiOiIuLi4ifQ.signature' \
  -d '{
    "certificate": "-----BEGIN CERTIFICATE-----\nMIID...current-leaf...\n-----END CERTIFICATE-----\n",
    "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIIB...new-key...\n-----END CERTIFICATE REQUEST-----\n"
  }'
```

### Response — `201 Created`

Returns the same `CertificateResponse` body as [`POST /v1/sign`](#post-v1sign).

## POST /v1/revoke

Revokes a certificate by serial number. Two authorization paths are accepted:

1. **Revocation token** — a provisioner-issued OTT in the `token` field whose
   `sub` claim equals the serial number being revoked. Use `--operation revoke`
   when minting the token.
2. **DPoP self-revocation** — a `DPoP` header together with the
   `certificate` field, for the key holder to revoke their own certificate. The
   certificate's serial must equal `serial_number`.

If neither a token nor a (`DPoP` + `certificate`) pair is supplied, the request
is rejected with `401 Unauthorized`. Revocation is idempotent: revoking an
already-revoked serial succeeds.

### Headers

| Header | Required | Description |
| --- | --- | --- |
| `DPoP` | conditional | Required for the DPoP self-revocation path; omit when using a revocation token. |

### Request body

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `serial_number` | string | yes | Serial number as a decimal string or `0x`-prefixed hex. |
| `reason` | string | no | Human-readable reason. |
| `reason_code` | int | no | RFC 5280 CRLReason code (0-10). Defaults to `0` when omitted. |
| `token` | string | no | Revocation token authorizing the request (token path). |
| `certificate` | string | no | PEM leaf certificate, for DPoP self-revocation (DPoP path). |

### Request (token path)

```bash
curl -X POST https://ca.example/v1/revoke \
  -H 'Content-Type: application/json' \
  -d '{
    "serial_number": "29384719283471928374",
    "reason": "key compromise",
    "reason_code": 1,
    "token": "eyJhbGciOiJFUzI1NiJ9...signature"
  }'
```

### Request (DPoP self-revocation path)

```bash
curl -X POST https://ca.example/v1/revoke \
  -H 'Content-Type: application/json' \
  -H 'DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2In0...signature' \
  -d '{
    "serial_number": "0x19d2f3a8b7c6d5e4",
    "certificate": "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"
  }'
```

### Response — `200 OK`

```json
{
  "status": "revoked"
}
```

| Field | Type | Description |
| --- | --- | --- |
| `status` | string | Always `"revoked"`. |

## Errors

All non-2xx responses use the RFC 7807 `application/problem+json` media type and
the following body shape:

```json
{
  "type": "about:blank",
  "title": "Unauthorized",
  "status": 401,
  "detail": "token validation failed: ExpiredSignature"
}
```

| Field | Type | Description |
| --- | --- | --- |
| `type` | string | URI reference identifying the problem type; defaults to `about:blank`. |
| `title` | string | Short, human-readable summary of the problem type. |
| `status` | int | HTTP status code, duplicated into the body for convenience. |
| `detail` | string | Human-readable explanation for this occurrence. Omitted for `500` responses, where the detail is logged server-side rather than returned. |
| `instance` | string | URI reference identifying the specific occurrence. Omitted when not set. |

A malformed JSON request body produces `400 Bad Request` with detail
`invalid JSON body: ...`.

### Status-code mapping

The internal error type maps to HTTP status and `title` as follows:

| Error variant | Status | `title` | `detail` returned |
| --- | --- | --- | --- |
| `BadRequest` | `400 Bad Request` | `Bad Request` | yes |
| `Unauthorized` | `401 Unauthorized` | `Unauthorized` | yes |
| `Forbidden` | `403 Forbidden` | `Forbidden` | yes |
| `NotFound` | `404 Not Found` | `Not Found` | yes |
| `Conflict` | `409 Conflict` | `Conflict` | yes |
| `Config` | `500 Internal Server Error` | `Internal Server Error` | no (suppressed) |
| `Internal` | `500 Internal Server Error` | `Internal Server Error` | no (suppressed) |

Common causes by status:

- `400` — invalid JSON body, bad CSR, unparseable serial number.
- `401` — bad/expired/replayed token signature, missing or invalid DPoP proof,
  unknown provisioner, missing credential on revoke.
- `403` — authenticated but not permitted: SAN not allowed by the token, `cnf`
  CSR mismatch, certificate revoked, serial mismatch, webhook deny.
- `404` — referenced object does not exist.
- `409` — a uniqueness constraint was violated (token or proof replay).
- `500` — configuration or unexpected internal failure (detail not exposed).

## See also

- [Tokens and authentication](provisioners.md)
- [Provisioners](provisioners.md)
- [Configuration](configuration.md)
- [docs index](README.md)
