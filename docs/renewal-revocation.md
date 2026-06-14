# Renewal, rekey, and revocation

After a certificate has been issued, the holder of its private key can renew it, rekey it onto a fresh key pair, or revoke it — all without a new issuance token. These operations authenticate with an [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) DPoP proof signed by the certificate's own key, proving possession of that key directly to the CA. Revocation additionally accepts a provisioner-issued token, the same one-time token (OTT) mechanism used for [signing](provisioners.md).

This page covers the DPoP proof, the gates ayane enforces on the presented certificate, and the `POST /v1/renew`, `POST /v1/rekey`, and `POST /v1/revoke` endpoints, with matching `ayane` CLI examples.

## The DPoP proof

A DPoP proof is a compact JWS (JWT) presented in the `DPoP` HTTP request header. Where a sign request carries an OTT minted by a provisioner, renew/rekey/self-revoke instead present a proof signed by the existing certificate's private key. The CA verifies the proof's signature **directly against the public key in the presented certificate** — not against a key embedded in the proof header — so a verifying signature is itself evidence that the caller holds the certificate's key (`ayane/src/dpop.rs`).

### Header

| Field | Required value | Notes |
| --- | --- | --- |
| `typ` | `dpop+jwt` | Rejected with 401 if absent or different (`ayane_protocol::dpop::DPOP_TYP`). |
| `alg` | Must match the certificate key type | `ES256`/`ES384` for EC P-256/P-384, `RS256` for RSA. A mismatch is rejected with 401. |
| `jwk` | The certificate's public key | The CLI sets this (`header.jwk`), but the server does not trust it; verification uses the certificate's key. |

### Claims

| Claim | Type | Meaning |
| --- | --- | --- |
| `htm` | string | HTTP method the proof is bound to. Compared case-insensitively against the request method; ayane always expects `POST`. |
| `htu` | string | The full request target URI. Must equal the endpoint URL the CA computed for the request (e.g. `https://ca.example/v1/renew`). |
| `iat` | integer | Issued-at, epoch seconds. Freshness is enforced (see below). |
| `jti` | string | Unique proof id, enforced one-time (anti-replay). |
| `nonce` | string (optional) | Optional server-provided nonce; serialized only when present. |

### Verification and freshness

`crate::dpop::verify` performs, in order (`ayane/src/dpop.rs`):

1. Decode the JOSE header and require `typ == "dpop+jwt"`.
2. Derive the decoding key and pinned algorithm from the certificate's `SubjectPublicKeyInfo`, and require the proof's `alg` to match that algorithm — this is algorithm-confusion-safe.
3. Verify the JWS signature against the certificate's public key.
4. Require `htm` to match the request method (`POST`, case-insensitive) and `htu` to match the request URI exactly.
5. Enforce freshness on `iat`: the proof must not be issued more than 60 seconds in the future (clock skew), and must not be older than `max_age`, which ayane sets to **300 seconds** (`dpop_max_age`).

On success the verifier returns the proof's `jti` and `issued_at`, which the service uses for anti-replay.

### Additional gates on the certificate

Before a proof is even evaluated, `try_renew_or_rekey` and the DPoP branch of `try_revoke` gate the presented certificate (`ayane/src/service.rs`):

| Gate | Failure | Status |
| --- | --- | --- |
| Issued by this CA — the certificate's signature must validate under the CA's public key (`ca.verify_issued`). | `certificate was not issued by this CA` | 403 |
| Not revoked — the certificate's serial must not already be on the revocation store (renew/rekey only). | `certificate is revoked` | 403 |
| Not expired — `now` must be before the certificate's `notAfter` (renew/rekey only). | `certificate has expired and cannot be renewed` | 403 |

Only after these gates and the DPoP signature/binding/freshness checks all pass does the service claim the proof's `jti` and commit the operation. See [security model](security.md) for the rationale behind verifying against the certificate key.

### Anti-replay

A proof's `jti` is claimed exactly once, namespaced `dpop#<jti>` in storage to keep it separate from the OTT namespace (`ott#<jti>`). The claim happens only after every check passes, so a transient failure never burns a still-valid proof. The denylist record's expiry is floored to outlive the validator's acceptance window (`issued_at + dpop_max_age + 60s` leeway). Replaying a proof yields 401 `token or proof has already been used`. See [storage](storage.md) for the DynamoDB token-denylist item layout and TTL.

## Renewal — `POST /v1/renew`

Renewal reissues a certificate **on the same key**, preserving its subject and all of its extensions. The request body carries only the certificate; possession of the key is proven by the `DPoP` header.

### Request

| Header / field | Type | Required | Description |
| --- | --- | --- | --- |
| `DPoP` header | DPoP proof JWT | yes | Signed by the certificate's key, with `htu` equal to the `/v1/renew` URL. |
| `certificate` | string (PEM) | yes | The PEM-encoded leaf certificate to renew (leaf or fullchain). |

### Behavior

The reissued certificate (`CertificateAuthority::reissue`, `ayane/src/ca.rs`):

- Keeps the original **subject** (DN) verbatim.
- Keeps every original extension — key usage, extended key usage, basic constraints, and SubjectAltName — **except** the Subject Key Identifier and Authority Key Identifier, which are recomputed from the key and the current CA.
- Gets a fresh random serial number.
- Is reissued for the **same effective lifetime** as the original: `not_before = now`, `not_after = now + (original notAfter − original notBefore)`. The validity *duration* is preserved, sliding forward from the moment of renewal.

Because reissue copies the extensions rather than re-deriving them from the current [template](configuration.md), a renewed certificate keeps the policy it was originally issued under, even if the CA's templates have since changed.

### Response

`201 Created` with a `CertificateResponse` (`ayane-protocol/src/api.rs`):

```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...renewed leaf...\n-----END CERTIFICATE-----\n",
  "chain": ["-----BEGIN CERTIFICATE-----\n...issuer...\n-----END CERTIFICATE-----\n"],
  "serial_number": "13750352819...",
  "not_after": "2026-06-15T12:00:00Z"
}
```

### CLI

```bash
ayane renew \
  --url https://ca.example \
  --cert /etc/ssl/leaf.pem \
  --key  /etc/ssl/leaf.key \
  --out  /etc/ssl/leaf.pem
```

The CLI reads the certificate and key, mints a DPoP proof bound to `POST https://ca.example/v1/renew`, and writes the renewed fullchain (leaf followed by the issuer chain) to `--out`. The same `--root <ca.pem>` and `--insecure` connection flags available on every command apply (see [cli](cli.md)).

## Rekey — `POST /v1/rekey`

Rekey is renewal onto a **new key pair**. The DPoP proof still proves possession of the *existing* certificate's key, while the new public key is taken from a fresh CSR.

### Request

| Header / field | Type | Required | Description |
| --- | --- | --- | --- |
| `DPoP` header | DPoP proof JWT | yes | Signed by the **existing** certificate's key, `htu` equal to the `/v1/rekey` URL. |
| `certificate` | string (PEM) | yes | The PEM-encoded leaf certificate being rekeyed. |
| `csr` | string (PEM) | yes | A PKCS#10 CSR carrying the **new** public key. Its signature is verified, proving possession of the new key. |

### Behavior

Identical to renewal — same subject, same extensions, same preserved lifetime — except the subject public key comes from the CSR instead of the old certificate. The CSR's signature is checked (`new_csr.verify_signature()`), so the request proves possession of both the old key (via DPoP) and the new key (via the CSR self-signature). The reissued certificate's Subject Key Identifier is recomputed from the new key.

### Response

`201 Created` with a `CertificateResponse`, identical in shape to renewal.

### CLI

```bash
ayane rekey \
  --url     https://ca.example \
  --cert    /etc/ssl/leaf.pem \
  --key     /etc/ssl/leaf.key \
  --kty     ec256 \
  --key-out /etc/ssl/leaf.new.key \
  --out     /etc/ssl/leaf.new.pem
```

| Flag | Default | Description |
| --- | --- | --- |
| `--cert` | — | Existing certificate PEM. |
| `--key` | — | Existing private key PEM (proves possession via DPoP). |
| `--kty` | `ec256` | New key type: `ec256`, `ec384`, `rsa2048`, `rsa3072`, or `rsa4096`. |
| `--key-out` | — | Where to write the newly generated private key. |
| `--out` | — | Where to write the rekeyed fullchain. |

The CLI generates the new key locally, builds a CSR from it, signs a DPoP proof with the *old* key, and writes both the new key (`--key-out`) and the new fullchain (`--out`).

## Revocation — `POST /v1/revoke`

Revocation marks a certificate's serial number as revoked in the storage backend. It is authorized in one of two ways:

- **Token-authorized:** a revocation token (OTT) issued by a provisioner whose `sub` claim equals the serial being revoked.
- **DPoP self-revocation:** a DPoP proof signed by the certificate's key, presented together with the certificate.

### Request

| Field / header | Type | Required | Description |
| --- | --- | --- | --- |
| `serial_number` | string | yes | Serial to revoke, as a decimal string or `0x`-prefixed hex. |
| `reason` | string | no | Human-readable reason; recorded and surfaced in the audit event detail. |
| `reason_code` | integer | no | RFC 5280 CRLReason code (0-10). Defaults to `0` when omitted. |
| `token` | string | conditional | A revocation OTT (use this path *or* DPoP). |
| `certificate` | string (PEM) | conditional | The leaf certificate, required for the DPoP path. |
| `DPoP` header | DPoP proof JWT | conditional | Required (with `certificate`) for self-revocation. |

You must supply **either** `token`, **or** both a `DPoP` header and `certificate`. Supplying neither yields 401 `revocation requires a token, or a DPoP proof with the certificate`.

### Serial number formats

The serial is normalized to a canonical decimal string before storage (`normalize_serial`, `ayane/src/service.rs`):

| Input | Normalized |
| --- | --- |
| `255` | `255` |
| `0x0a` / `0X0A` | `10` |
| `0X100` | `256` |
| `007` | `7` (leading zeros stripped) |

Non-digit, empty, or invalid-hex serials are rejected with 400.

### Authorization paths

**Token path.** The token is validated like any OTT (signature, `iss`/`aud`/`nbf`/`exp`, one-time `jti`). The token's `sub` claim — normalized as a serial — must equal the requested serial, otherwise 403 `token does not authorize this serial number`. The token's `jti` is then claimed. The provisioner name is recorded on the revocation record and audit event.

**DPoP self-revocation path.** The presented `certificate` must have been issued by this CA (`verify_issued`, else 403), and its serial must equal the requested serial (else 403 `DPoP certificate serial does not match the requested serial`). The DPoP proof is verified against the certificate's key and bound to the `/v1/revoke` URL, and its `jti` is claimed. No provisioner is recorded for self-revocation.

### Idempotency

The revocation is written with a conditional `attribute_not_exists(pk)` put, so re-revoking an already-revoked serial does not overwrite the original record and still returns success. See [storage](storage.md) for the `revocation#<serial>` item layout.

### Response

`200 OK`:

```json
{ "status": "revoked" }
```

### CLI

Token-authorized revocation:

```bash
# Mint a revocation token (subject is the serial number)
ayane token \
  --key /etc/ayane/provisioner.key \
  --issuer my-provisioner \
  --url https://ca.example \
  --operation revoke \
  --subject 13750352819... > revoke.jwt

ayane revoke \
  --url https://ca.example \
  --serial 13750352819... \
  --reason "key compromise" \
  --reason-code 1 \
  --token "$(cat revoke.jwt)"
```

DPoP self-revocation (no token; the key holder revokes their own certificate):

```bash
ayane revoke \
  --url    https://ca.example \
  --serial 0x0a3f... \
  --cert   /etc/ssl/leaf.pem \
  --key    /etc/ssl/leaf.key
```

| Flag | Description |
| --- | --- |
| `--serial` | Serial number, decimal or `0x`-hex. |
| `--reason` | Optional human-readable reason. |
| `--reason-code` | Optional RFC 5280 reason code. |
| `--token` | Revocation token for the provisioner-authorized path. |
| `--cert` + `--key` | Certificate and key for the DPoP self-revocation path (must be given together). |

`--cert` and `--key` must be provided together; supplying neither `--token` nor `--cert`/`--key` is rejected by the CLI before any request is sent.

## Errors

All failures return an RFC 7807 `application/problem+json` body. The most common statuses for these operations:

| Status | Examples |
| --- | --- |
| 400 Bad Request | Malformed PEM/CSR, invalid serial, invalid timestamp. |
| 401 Unauthorized | Missing/invalid DPoP proof, wrong `typ`/`alg`, stale or future proof, replayed `jti`, invalid token. |
| 403 Forbidden | Certificate not issued by this CA, certificate revoked or expired, serial mismatch between token/cert and request. |

See [api-reference](api.md) for the full error mapping and problem document shape.

## See also

- [signing](provisioners.md) — issuing a brand-new certificate with a one-time token.
- [security](security.md) — the DPoP and anti-replay threat model.
- [storage](storage.md) — revocation records and the token denylist.
- [docs index](README.md)
</content>
</invoke>
