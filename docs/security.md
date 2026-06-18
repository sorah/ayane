# Security model

ayane is a network-exposed X.509 certificate authority: whoever can obtain a signature from it can impersonate the identities it certifies. This page describes the trust boundaries ayane enforces, the cryptographic bindings that protect each API operation, and the operational settings you must get right in production.

## Trust boundaries

ayane is split into a few layers, each with a different trust posture.

| Boundary | Trusted to | Notes |
| --- | --- | --- |
| CA signing key | Mint certificates the whole PKI trusts | Protect with AWS KMS (`{"type":"aws_kms"}` in [`ca.key`](configuration.md)); the key never leaves the HSM-backed service |
| Provisioner keys | Authorize `sign`/`revoke` requests | A provisioner's *private* key is held by the caller; ayane stores only the *public* JWK |
| Caller's certificate key | Authorize `renew`/`rekey`/self-`revoke` via DPoP | Proven by signature, never trusted from the request body |
| Webhook endpoints | Approve or enrich issuance | Outbound; authenticated to ayane via HMAC and/or bearer token |
| TLS terminator (reverse proxy / Lambda Function URL) | Terminate transport security | ayane never terminates TLS itself; see [deployment](deployment.md) |

TLS is always terminated *in front of* ayane. The server core in `ayane/src/http.rs` speaks plain HTTP and derives request URLs from headers, so the integrity of the audience/`htu` bindings below depends on a correctly configured terminator and on [`server.external_url`](#set-external_url-in-production).

## Authentication and authorization per endpoint

The read endpoints (`GET /v1/health`, `GET /v1/roots`, `GET /v1/provisioners`) are unauthenticated and return only public information. The four mutating endpoints each require a distinct credential.

| Endpoint | Credential | What it proves |
| --- | --- | --- |
| `POST /v1/sign` | OTT JWT (`token`) | The caller holds a provisioner key authorizing this subject/SANs |
| `POST /v1/renew` | `DPoP` proof over the presented cert | The caller holds the existing certificate's private key |
| `POST /v1/rekey` | `DPoP` proof + CSR with new key | Possession of the old key *and* the new key |
| `POST /v1/revoke` | OTT JWT *or* `DPoP` + certificate | Provisioner authority *or* possession of the cert key |

See [the API reference](api.md) for the full request/response shapes.

## OTT issuance tokens

A `sign` request carries a one-time token (OTT): a JWT signed by a provisioner's private key. Validation lives in `ayane/src/authorizer/jwt.rs`. The claim set (`ayane-protocol/src/token.rs`) is:

| Claim | Meaning | Enforcement |
| --- | --- | --- |
| `iss` | Provisioner name | Must match a configured provisioner; selects the verification key |
| `aud` | CA endpoint URL | Bound to the request URL (see below) |
| `sub` | Certificate common name / primary identity | Becomes the CN |
| `sans` | Permitted Subject Alternative Names | Subset check against the CSR; empty means only `sub` |
| `iat` / `nbf` / `exp` | Issued-at / not-before / expiry (epoch seconds) | `nbf` and `exp` validated with a 60-second leeway |
| `jti` | Unique token id | One-time; claimed on the denylist after all checks pass |
| `cnf` | Optional `{"x5t#S256": base64url(SHA-256(CSR DER))}` | Binds the token to one specific CSR |

### Algorithm pinning (alg-confusion safe)

The accepted JWT algorithm is *pinned* to the algorithm implied by the provisioner's JWK, computed once at boot by `algorithm_from_jwk`:

| JWK key type | Pinned algorithm |
| --- | --- |
| EC P-256 | `ES256` |
| EC P-384 | `ES384` |
| RSA (default / `RS384` / `RS512` / `PS256` / `PS384` / `PS512` hint) | `RS256` (or the explicit hint) |
| OKP Ed25519 | `EdDSA` |

`jsonwebtoken::Validation::new(entry.algorithm)` is constructed with that single algorithm, so the verifier will only accept a token whose header `alg` matches. An attacker cannot present a token with `alg: HS256` and trick the server into verifying an EC public key as an HMAC secret — the classic JWT algorithm-confusion attack is structurally impossible here.

The `iss` claim is read *without* verifying the signature (`unverified_issuer`) solely to select which provisioner key should perform verification. No trust is placed in the unverified `iss`: an unknown issuer is rejected, and the subsequent signed verification still has to pass with that provisioner's pinned key and `set_issuer` check.

### Endpoint-bound audiences

By default the `aud` claim must equal the *request endpoint URL*. In `validate`:

```rust
if entry.audiences.is_empty() {
    validation.set_audience(&[audience]);   // request URL, e.g. https://ca.example/v1/sign
} else {
    // explicit allowlist from the provisioner config
}
```

This stops a token minted for one endpoint from being replayed against another (a token for `/v1/sign` cannot be presented to `/v1/revoke`, and vice versa). The `audience` value is the full request URL computed by `request_url` in `http.rs`. Setting a non-empty [`audiences`](configuration.md) list on a provisioner opts into a fixed allowlist instead; the operator then becomes responsible for endpoint scoping. Prefer the default unless you have a specific reason.

### CSR binding via `cnf`

If the token carries a `cnf` confirmation with `x5t#S256`, `try_sign` (in `service.rs`) compares it against `csr.fingerprint_b64url()` — the base64url SHA-256 of the CSR DER — and returns `403 Forbidden` (`"token is bound to a different CSR"`) on mismatch. This binds a captured token to exactly one key pair, so it cannot be redirected to a CSR the attacker controls.

## SAN subset authorization

The token authorizes a *set* of names; the CSR may request any subset of them, never more. In `try_sign`:

```rust
let allowed = allowed_sans(claims);          // claims.sans, or [sub] if sans is empty
let mut requested = csr.requested_sans()?;
if requested.is_empty() {
    requested = allowed.clone();
}
for san in &requested {
    if !allowed.contains(san) {
        return Err(Forbidden("SAN {san} is not permitted by the token"));
    }
}
```

A CSR requesting a name the token does not list is rejected with `403 Forbidden`. An empty `sans` claim collapses the permitted set to just `sub`. The CN itself is taken from `sub` (`claims.sub`), not from the CSR subject, so the caller cannot escalate the identity through the CSR.

## DPoP proof-of-possession

`renew`, `rekey`, and certificate-holder self-`revoke` do not use a provisioner token. Instead the caller proves it still holds the certificate's private key with an RFC 9449 DPoP proof in the `DPoP` header. Verification is `crate::dpop::verify` (`ayane/src/dpop.rs`).

The proof is a JWS with these properties:

| Field | Requirement |
| --- | --- |
| header `typ` | Must equal `dpop+jwt` (`DPOP_TYP`) |
| header `alg` | Must match the algorithm derived from the *certificate's* public key |
| `htm` | HTTP method; compared case-insensitively against `POST` |
| `htu` | Full request URL; must equal the computed request URL exactly |
| `iat` | Issued-at; must be no older than `max_age` (300s) and no more than 60s in the future |
| `jti` | Unique proof id; one-time via the denylist |

The crucial design point is *what key verifies the proof*. ayane does **not** trust a public key embedded in the proof header (a `jwk`/`jkt` would be attacker-chosen). It builds the decoding key directly from the presented certificate's `SubjectPublicKeyInfo` (`decoding_key_from_spki`) and verifies the proof against that. A valid signature is therefore itself evidence that the caller holds the certificate's private key. The `htm`/`htu` bindings additionally tie the proof to one specific request, and the `iat` freshness window plus one-time `jti` prevent a captured proof from being replayed.

### Gating: not-revoked, not-expired, issued-by-us

Before a DPoP-authenticated reissue or self-revocation is accepted, `try_renew_or_rekey` (and the DPoP branch of `try_revoke`) enforce additional checks against the presented certificate:

1. **Issued by this CA** — `self.ca.verify_issued(&cert)?` checks the certificate's signature against the CA key. A certificate ayane did not sign cannot be renewed.
2. **Not revoked** — `self.storage.get_revocation(&serial)` must return `None`; otherwise `403 Forbidden` (`"certificate is revoked"`).
3. **Not expired** — if `now >= cert_na`, renewal is refused with `403 Forbidden` (`"certificate has expired and cannot be renewed"`). An expired certificate must be re-obtained through `sign` with a fresh OTT.

### Policy preservation on reissue

Renewal and rekey deliberately do **not** re-run SAN policy or templates. Identity and extensions are carried over from the original certificate:

- The subject and SANs are read from the existing certificate (`cert_sans`, `subject_common_name`) and reissued verbatim via `self.ca.reissue(&cert, public_key, now, not_after)`, preserving key usage, EKU, basic constraints, and SANs.
- The new validity window is `now + original_duration`, where `original_duration` is the original `not_after - not_before`.
- For `rekey`, the new public key comes from a CSR whose signature is verified (`new_csr.verify_signature()`), proving possession of the *new* key as well as the old.

Because the holder already proved possession of an unrevoked, unexpired certificate this CA issued, no provisioner authorization is needed — and because the policy is copied rather than re-evaluated, a holder cannot widen its own certificate's scope through renewal.

## Anti-replay (one-time `jti`)

Both OTTs and DPoP proofs are single-use. The `jti` is recorded on a storage-backed denylist by `claim_jti` in `service.rs`:

```rust
let key = format!("{kind}#{jti}");   // "ott#<jti>" or "dpop#<jti>"
```

Two properties matter:

- **Namespaced.** OTT and DPoP `jti` values live in separate keyspaces (`ott#…` vs `dpop#…`), so they can never collide or be cross-replayed.
- **Claimed after all checks pass.** In `try_sign`, the `jti` is claimed only *after* signature verification, CSR binding, SAN authorization, template resolution, and webhooks all succeed — right before issuance commits. A transient webhook or template failure therefore never burns a token that is still otherwise valid. For DPoP operations the proof `jti` is claimed only after the signature, freshness, revocation, and expiry checks pass.

The claim is a conditional write (`attribute_not_exists(pk)` in the [DynamoDB backend](storage.md)); a duplicate `jti` raises `Conflict`, which `claim_jti` maps to `401 Unauthorized` (`"token or proof has already been used"`). The denylist TTL is floored to outlive the validator's acceptance window (`REPLAY_LEEWAY` = 60s on top of `exp` / `iat + max_age`), so a credential can never be re-presented after its record has expired. Enable DynamoDB TTL on the `ttl` attribute so stale records are reaped automatically.

## Webhook trust and integrity

Webhooks (`ayane/src/webhook/mod.rs`, orchestrated by `run` and consumed in `service.rs`) let an external service approve and/or customize issuance from a single typed response — there is no separate authorizing/enriching distinction. They are an *outbound* trust extension and must be authenticated.

- **HMAC body signing.** When a `secret` (base64 HMAC-SHA256 key) is configured on an HTTP target, ayane sends a hex HMAC-SHA256 over the exact request body bytes in the `X-Ayane-Signature` header. The receiver must verify this to ensure the request genuinely came from ayane.
- **Bearer token.** An optional `bearer_token` is sent as `Authorization: Bearer …`.
- **Fail closed.** A non-2xx response is an error, which denies issuance (`403 Forbidden` unless `allow` is not exactly `false`), so a webhook outage cannot silently let requests through.
- **Validity is re-clamped after the webhook.** A webhook may override `notBefore`/`notAfter`, but the result is re-clamped before issuance: on `sign`, `notAfter` is bounded by the resolved template's `max_validity` (`CertificateTemplate::max_not_after`); on `renew`/`rekey`, `notAfter` may not exceed the previous certificate's lifetime (the baseline window). A webhook can therefore shorten a certificate's lifetime freely, but can never extend issuance beyond the policy ceiling.

A webhook can otherwise veto any request and customize the subject, SANs, key usages, and arbitrary extensions (including basic constraints), so treat the webhook endpoint as part of your trusted control plane. See [webhooks](webhooks.md) for the full request/response contract.

## Set `external_url` in production

When [`server.external_url`](configuration.md) is unset, `request_url` in `http.rs` derives the request URL from client-influenced headers:

```rust
let scheme = header(headers, "x-forwarded-proto").unwrap_or("https");
let host = header(headers, "x-forwarded-host")
    .or_else(|| header(headers, "host"))
    .unwrap_or("localhost");
```

That URL is exactly what the token `aud` and the DPoP `htu` are checked against. If an attacker can control `Host` / `X-Forwarded-Host` / `X-Forwarded-Proto`, they can shift the audience/`htu` target and weaken the endpoint binding. **Always set `external_url` to the public base URL in production** so these bindings are computed from a trusted constant. The server logs a warning at startup when `external_url` is unset. Behind a reverse proxy, also ensure the proxy strips inbound `X-Forwarded-*` headers and sets them itself.

## Error responses and detail suppression

Errors are returned as RFC 7807 `application/problem+json` (`ayane/src/error.rs`, `ayane/src/http.rs`):

| Error variant | Status | Detail returned? |
| --- | --- | --- |
| `BadRequest` | 400 | Yes |
| `Unauthorized` | 401 | Yes |
| `Forbidden` | 403 | Yes |
| `NotFound` | 404 | Yes |
| `Conflict` | 409 | Yes |
| `Config` / `Internal` | 500 | **No** (suppressed; title is `Internal Server Error`) |

For `Internal` and `Config` errors, `to_problem` returns no `detail`, and the full error is logged server-side via `tracing::error!` instead of being sent to the client. This prevents leaking implementation specifics, file paths, or KMS/storage internals through 500 responses, while still giving operators the detail in logs.

## CA key protection

The CA signing key is the single most sensitive secret in the system. ayane supports holding it in AWS KMS via the [`ca.key`](configuration.md) `KeyConfig`:

```json
{
  "ca": {
    "key": {
      "type": "aws_kms",
      "key_id": "arn:aws:kms:us-east-1:123456789012:key/abcd-...",
      "algorithm": "ECDSA_SHA256"
    }
  }
}
```

With a KMS key, the private key material never leaves the KMS service: ayane sends digests to `Sign` and never holds the raw key. Scope the IAM policy on the key to the minimum (`kms:Sign`, and `kms:GetPublicKey` for startup), grant it only to the ayane execution role, and enable CloudTrail on the key so every signing operation is auditable. The file-based key option (`{"type":"file"}`) is convenient for development but places the key in process memory and on disk; use KMS for any deployment whose certificates are trusted beyond a test environment.

Combine KMS protection with the [audit events](events.md) stream (`certificate.issued` / `certificate.revoked` / etc.) so every issuance is independently recorded outside the server process.

## See also

- [API reference](api.md)
- [Configuration reference](configuration.md)
- [Webhooks](webhooks.md)
- [docs index](README.md)
