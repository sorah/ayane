# Signed `roots` API (RFC 9421 HTTP message signature)

## Summary

The `GET /v1/roots` endpoint returns the CA's trusted root bundle. When ayane is
served behind a third-party CA (e.g. an AWS Lambda Function URL, where TLS is
terminated by an Amazon-issued certificate), TLS alone does not prove the
response came from *our* PKI: anyone who can obtain a valid server certificate
for the host — or who controls the fronting infrastructure — could substitute a
malicious root bundle and trick a client into trusting a foreign CA.

This spec adds an **RFC 9421 HTTP Message Signature** to the `roots` response,
produced with the CA's own issuing key. The signer's certificate chain is
**referenced** by a `Signature-Key` header (the `x509` scheme from
[draft-hardt-httpbis-signature-key], using its `x5u`/`x5t` parameters) and served
out of band at a new `GET /v1/roots/signer-chain` endpoint as PEM — keeping the
chain (potentially several KB of base64 DER) out of the response headers, where
proxies and gateways impose tight size limits. `ayane-cli` **requires and
verifies** that signature against a pinned, known root bundle (`--root`) before
trusting any root in the response. Signing is relatively expensive (the key may
be AWS KMS), so signatures are computed with a configurable lifetime and
**cached in `Storage`** via a new general-purpose key/value cache, shared across
server instances.

## Motivation

ayane is explicitly designed to run behind AWS Lambda Function URLs, where "TLS
is terminated by the Function URL" and the serving certificate is issued by
Amazon's CA, not ours (see `ayane/src/server.rs`, `docs/deployment.md`). Every
other endpoint is a *mutating* operation authenticated by a short-lived
credential (OTT or DPoP), and their responses are certificates the client can
independently validate against a pinned root. `roots` is the exception: it is
the **trust-distribution** endpoint, and its response *is* the trust anchor set.
If a client bootstraps or refreshes its trust store from an unauthenticated
`roots` response, a third party in the TLS path can inject arbitrary roots.

The concrete consumer is the `machineidentity` renewal hook, which the
`renew --loop` spec already noted will switch its root-fetch step from
`step ca roots` to `ayane roots` (`specs/renew-loop.md`). That hook writes the
fetched roots into the host trust store, so an unauthenticated `roots` response
is a direct path to trusting a foreign CA fleet-wide.

We want a response-level signature, anchored in the CA key (which the client
already pins), that is:

- **independent of the TLS layer** — so a third-party serving certificate cannot
  forge it;
- **bound to the exact response body** — so the root bundle cannot be altered in
  flight;
- **time-bounded** — so a captured signed response cannot be replayed
  indefinitely;
- **cheap to serve at scale** — signing is cached, not recomputed per request,
  because the CA key may live in KMS.

## Explanation

### Wire format

`GET /v1/roots` keeps its existing JSON body
(`{"certificates": ["-----BEGIN CERTIFICATE-----\n..."]}`,
`ayane_protocol::RootsResponse`) and gains four response headers implementing an
RFC 9421 signature over the response:

```
HTTP/1.1 200 OK
Content-Type: application/json
Content-Digest: sha-384=:fNH2k...base64 SHA-384 of the body...:
Signature-Key: sig=x509;x5u="/v1/roots/signer-chain";x5t="bWcoon4QTVn8Q6xiY0ekMD6L8bNLMkuDV2KtvsFc1nM"
Signature-Input: sig=("@status" "content-type" "content-digest" "signature-key");created=1718360000;expires=1718363600;alg="ecdsa-p256-sha256"
Signature: sig=:MEUCIQ…rawECDSA(r‖s)…:

{"certificates":["-----BEGIN CERTIFICATE-----\n…root…\n-----END CERTIFICATE-----\n"]}
```

- **`Content-Digest`** (RFC 9530 format) carries `sha-384=:BASE64(SHA384(body)):`,
  binding the exact response bytes into the signature. `sha-384` is an
  ayane-private digest choice (RFC 9530 registers only `sha-256`/`sha-512`), safe
  because the only verifier is `ayane-cli`, and matches the SHA-384 signing tier.
- **`Signature-Key`** ([draft-hardt-httpbis-signature-key], `x509` scheme)
  **references** the signer certificate chain rather than inlining it:
  - **`x5u`** — URL of the signer chain (PEM), served at
    `GET /v1/roots/signer-chain` (below). Signed as a **same-origin reference**:
    `server.external_url` + `/v1/roots/signer-chain` when configured, else the
    relative `/v1/roots/signer-chain`. The client resolves it against its own
    `--url` and **never fetches a foreign origin** (see Client behavior) — so a
    tampered `x5u` cannot turn the client into an SSRF gadget.
  - **`x5t`** — `BASE64URL(SHA256(DER(leaf_cert)))`, the thumbprint of the signer
    (leaf) certificate `chain[0]` — the CA issuing certificate whose key produced
    the signature. Because `signature-key` is a covered component (below), `x5t`
    is **signed**, so it authenticates the out-of-band chain: the client binds the
    fetched `signer-chain[0]` to this thumbprint before trusting it.

  We use `x5u`+`x5t` exactly as the draft defines them (we drop the earlier
  `x5c`-inline idea to keep headers small).
- **`Signature-Input`** names the **fixed** ordered set of covered components and
  the signature parameters. The covered set is always
  `("@status" "content-type" "content-digest" "signature-key")`. Including
  `"signature-key"` as a covered component is mandated by the draft ("If
  `signature-key` is not covered, an attacker can modify the header without
  invalidating the signature") — it binds both `x5u` and `x5t` into the
  signature. Per the draft, `keyid` is **omitted** when `sigkey` is used.
  Parameters: `created` (issuance, epoch seconds), `expires` (epoch seconds), and
  `alg` (the RFC 9421 algorithm token, derived from the CA key).
- **`Signature`** carries `sig=:BASE64(signature):`. ECDSA signatures use the
  RFC 9421 fixed-width `r‖s` (IEEE P1363) encoding — **not** the X.509 DER
  `ECDSA-Sig-Value` the CA emits for certificates; RSA PKCS#1 v1.5 bytes are
  unchanged.

The signature label is `sig` throughout.

#### `GET /v1/roots/signer-chain`

Returns the signer certificate chain as a concatenated PEM bundle
(`Content-Type: application/pem-certificate-chain`, RFC 8555's media type),
leaf-first: `chain[0]` is the CA issuing certificate (the signer), followed by
any intermediates — exactly the CA's configured `ca.chain` (falling back to the
issuing certificate when `chain` is empty). No authentication and **no
signature**: its integrity is enforced cryptographically by the client — the leaf
is pinned by the signed `x5t`, each link is signature-verified, and the chain is
anchored to the pinned `--root` bundle (so a tampered chain fails to verify or to
anchor). It is static per deployment and served directly (no cache, no signing).

#### Signature base

The string signed/verified is the RFC 9421 signature base (note `@status` is the
numeric status; the component values are the exact header values sent):

```
"@status": 200
"content-type": application/json
"content-digest": sha-384=:fNH2k...base64 SHA-384 of the body...:
"signature-key": sig=x509;x5u="/v1/roots/signer-chain";x5t="bWcoon4QTVn8Q6xiY0ekMD6L8bNLMkuDV2KtvsFc1nM"
"@signature-params": ("@status" "content-type" "content-digest" "signature-key");created=1718360000;expires=1718363600;alg="ecdsa-p256-sha256"
```

The body is serialized to bytes **once**; the same bytes are digested, returned,
and (on the client) re-digested — never re-serialized for verification.

#### Algorithm tokens

Derived from the CA signing key (`crypto::SignatureAlgorithm`):

| `SignatureAlgorithm` | `alg` token | `Signature` encoding |
| --- | --- | --- |
| `EcdsaSha256` | `ecdsa-p256-sha256` | P1363 `r‖s`, 64 bytes |
| `EcdsaSha384` | `ecdsa-p384-sha384` | P1363 `r‖s`, 96 bytes |
| `RsaPkcs1Sha256` | `rsa-v1_5-sha256` | PKCS#1 v1.5 |
| `RsaPkcs1Sha384` | `rsa-v1_5-sha384` (ayane extension¹) | PKCS#1 v1.5 |
| `RsaPkcs1Sha512` | `rsa-v1_5-sha512` (ayane extension¹) | PKCS#1 v1.5 |

¹ RFC 9421 only registers `rsa-v1_5-sha256` for PKCS#1 v1.5; the SHA-384/512
tokens are ayane-private but follow the same naming. Both ends are ours, so this
is safe. (`rsa-pss-*` is not used because the CA never signs with PSS.)

### Client behavior (`ayane-cli`)

`ayane roots` now **requires** `--root` and **always verifies** the signature
(the "Always require signature" decision):

```bash
# Verifies the response signature against the pinned bundle, then prints roots.
ayane roots --url https://ca.example --root /etc/ayane/known-roots.pem

# Error: signature verification needs a pinned trust anchor.
ayane roots --url https://ca.example
# error: --root is required: the roots response signature is verified against it
```

`--root` is already loaded as the reqwest TLS trust anchor (`cmd/mod.rs`); it now
*also* serves as the **known trusted root bundle** the signature is checked
against. Verification, in order, and **fail-closed** (on any failure the command
prints nothing and exits non-zero):

1. Read the raw response **bytes** (before JSON parsing) and all four headers;
   any missing header → reject.
2. Recompute `SHA384(body)` and compare to `Content-Digest`; mismatch → reject.
3. Parse `Signature-Input` parameters; require `expires > created`,
   `expires - created <= 7d` (a defensive cap on the replay window against a
   misconfigured server), `now < expires`, and `created <= now + 60s`
   (clock-skew leeway, matching the OTT/DPoP 60s convention); otherwise reject.
4. Parse the `Signature-Key` `x5u` and `x5t`. Resolve `x5u` to a fetch URL
   **constrained to the client's own `--url` origin**: a relative reference is
   resolved against `--url`; an absolute `x5u` whose origin differs from `--url`
   → reject (no foreign fetch). Fetch the signer chain (PEM) from that URL and
   parse it into `C[0..n]` (leaf-first); empty → reject.
5. **Bind the leaf to the signed thumbprint:** require
   `BASE64URL(SHA256(DER(C[0]))) == x5t`; mismatch → reject. This is what makes
   the out-of-band chain trustworthy — `x5t` is covered by the signature.
6. Reconstruct the signature base (shared builder, byte-identical to the server)
   and verify `Signature` against `C[0]`'s public key using `alg`; bad signature
   → reject.
7. **Anchor the signer in the pinned bundle** `K` (the certificates parsed from
   `--root`) by **path building**, not a fixed linear walk — the served chain is
   an unordered *bag* of candidate issuers that may include cross-signed twins
   (same subject and key, signed by different roots) so that a single bag serves
   clients pinned to either an old or a new root during a root rotation. From the
   signer `C[0]`, search for a path where:
   - every cert on the path is **temporally valid** (`notBefore <= now <= notAfter`);
   - each **issuer** used from the bag asserts `basicConstraints` cA=TRUE and
     actually signed its child (matched by issuer/subject DN **and** signature,
     never by array position);
   - a **cross-signed twin** of any cert on the path (same subject+key, possibly a
     different issuer) may be substituted — so the signer can anchor via a twin
     issued by a different root than its own `issuer` field names; and
   - the path terminates at a cert that is **byte-equal to** a cert in `K`, or is
     **issued by** (signature verifies under) a cert in `K`. Pinned roots in `K`
     are trusted a priori, so their own validity/CA bits are not re-checked.

   A loop guard (on `(subject, key, issuer)` edges) and a depth bound keep the
   search terminating. No path found → reject.
8. On success, print `certificates` exactly as today.

Verification therefore makes **two** requests to the CA origin (the `roots`
response and the referenced signer chain), both over the possibly-untrusted TLS
layer; neither is trusted on transport — the leaf is pinned by the signed `x5t`,
and the chain is validated and anchored cryptographically.

`--insecure` retains its meaning for the TLS layer only; it does **not** bypass
signature verification (the whole point is defense when the TLS layer is
untrusted). The signed bundle returned and verified is the bundle conveyed in the
response body — trust is *anchored* in the pinned `K`, but the client may learn
new/rotated roots that chain up to `K`.

### Server configuration

A new optional block under `ca` controls the signature lifetime:

```json
{
  "ca": {
    "certificate": { "file": "ca.crt" },
    "key": { "type": "aws_kms", "key_id": "alias/ayane", "algorithm": "ECDSA_SHA256" },
    "chain": [ { "file": "intermediate.crt" } ],
    "roots": [ { "file": "root.crt" } ],
    "roots_signature": { "ttl": "24h" }
  }
}
```

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `ca.roots_signature.ttl` | duration | `24h` | Lifetime of each signed roots artifact: `expires = created + ttl`. The server re-signs before expiry (see Implementation Plan); clients reject once `now >= expires`. |

No new server flags. The signer chain is the already-configured `ca.chain`
(falling back to the issuing certificate when `chain` is empty), so a single-tier
root CA needs no extra configuration. The CA's `roots` config is what the
endpoint returns and signs.

### Storage cache (new general-purpose KV)

`Storage` gains a general key/value cache with per-entry expiry, used here to
memoize the signed artifact but available for any future cached value:

```rust
// On the object-safe `Storage` trait (bytes-in/bytes-out; see Implementation Plan):
async fn get_cache(&self, key: &str) -> Result<Option<Vec<u8>>>;
async fn set_cache(&self, key: &str, value: Vec<u8>, expires_at: SystemTime) -> Result<()>;

// Typed free-function helpers in `storage/mod.rs` (the `T: serde` surface the
// task asked for, kept off the trait so `dyn Storage` stays object-safe):
pub async fn cache_get<T: DeserializeOwned>(s: &dyn Storage, key: &str) -> Result<Option<T>>;
pub async fn cache_set<T: Serialize>(s: &dyn Storage, key: &str, value: &T, expires_at: SystemTime) -> Result<()>;
```

`get_cache` returns `None` for a missing **or expired** entry (expiry is enforced
on read, not only by background reaping). `set_cache` overwrites any existing
entry for the key.

## Drawbacks

- **More moving parts on a previously trivial endpoint.** `roots` goes from a
  one-line JSON handler to a sign-and-cache path with a storage dependency.
- **A bespoke (if small) RFC 9421 + draft implementation.** We hand-roll a
  single-message signer/verifier instead of taking a dependency. It is
  deliberately *not* a general RFC 9421 engine (see Alternatives), so it must be
  kept in lockstep between server and client — mitigated by sharing the
  signature-base builder in `ayane-protocol`.
- **An extra round-trip.** Verifying `roots` now also fetches
  `/v1/roots/signer-chain`. Acceptable for an infrequent trust-distribution call;
  it keeps response headers small (the motivation for `x5u` over inline `x5c`).
- **`ayane roots` now requires `--root`.** The convenient unauthenticated
  bootstrap (`ayane roots` with no pin) is removed by the "always require
  signature" decision. First-trust must be established out of band (ship the
  pinned root with the host image / config management) — which is already how
  `machineidentity` seeds `roots.pem`.
- **A new `Storage` method to implement per backend** (SQLite + DynamoDB), plus
  the typed-helper indirection forced by trait object-safety.

## Considered Alternatives

- **Use the `httpsig` crate.** Rejected per the task framing: its model is tied
  to `hyper` request/response types and it has no caching/expiry hook suited to
  our memoized, KMS-backed signing. We keep it as a *reference* for the signature
  base and parameter serialization (`@~/git/github.com/junkurihara/httpsig-rs`).
- **Sign with a dedicated, separate key** instead of the CA issuing key.
  Rejected for now ("we directly use a configured CA's private key"): it would
  add key management and a second trust anchor for the client to pin, for no gain
  while the CA key is already the thing clients trust.
- **`keyid` → match a cert already in the client's bundle** (no chain reference
  at all). Simpler, but only works when the signer *is* a pinned root; it breaks
  for an intermediate issuing CA, which ayane supports. The chosen
  reference-and-anchor (`x5u`+`x5t`) approach handles both single- and multi-tier
  CAs.
- **Inline the chain in the header (`x5c`).** The initial design; rejected
  because base64-DER certificate chains (RSA, or multi-tier) can exceed proxy /
  gateway header-size limits. `x5u`+`x5t` keeps headers small and is exactly what
  the published draft defines, at the cost of one extra request.
- **Put the signer chain in the JSON body** rather than referencing it. Rejected:
  it would change the existing `RootsResponse` shape, and the draft's design puts
  keying material in `Signature-Key`. A dedicated endpoint keeps the body intact
  and the chain independently cacheable/fetchable.
- **Sign per request (no cache).** Rejected: with a KMS key every `roots` GET
  would incur a KMS `Sign` call; caching amortizes it across requests and
  instances, which is the explicit requirement.
- **Detached JWS / a custom signature JSON field.** Rejected in favor of the
  standards-track RFC 9421 + RFC 9530 + draft-hardt stack, which is the
  problem's named target and composes with HTTP semantics.

## Prior Art

- **RFC 9421** — HTTP Message Signatures (signature base, `Signature` /
  `Signature-Input`, `@signature-params`, algorithm tokens).
- **RFC 9530** — Digest Fields (`Content-Digest` format; ayane uses a
  `sha-384=:…:` value).
- **draft-hardt-httpbis-signature-key** — `Signature-Key` field and its `x509`
  scheme (`x5u`/`x5t`), used as defined.
- **RFC 8555 (ACME)** — `application/pem-certificate-chain` media type, reused for
  `/v1/roots/signer-chain`.
- **`junkurihara/httpsig-rs`** — reference Rust implementation consulted for base
  and parameter serialization.
- **ayane's own DPoP** (`ayane/src/dpop.rs`, `ayane-protocol/src/dpop.rs`) — the
  in-repo precedent for a focused, hand-rolled JOSE/HTTP-crypto verifier, pinning
  algorithms and verifying directly against presented key material.

## Security and Privacy Considerations

- **Threat addressed:** a third party controlling the TLS-terminating layer
  (foreign serving cert, compromised proxy/Function URL) substituting or mutating
  the root bundle. The CA-key signature defeats this: the attacker cannot produce
  a valid signature without the CA private key.
- **Trust anchor is the pinned `--root` bundle, never the response.** The signer
  chain fetched from `x5u` is only believed insofar as (a) its leaf matches the
  signed `x5t`, and (b) it chains to `K`. A response that references a
  self-consistent but foreign chain fails anchoring at step 7.
- **Out-of-band chain is bound by the signature.** `x5u` and `x5t` are inside the
  covered `signature-key` header, so they cannot be altered without invalidating
  the signature; the fetched chain's leaf is then pinned to `x5t`. Fetching the
  chain over untrusted TLS is therefore safe — a substituted leaf fails the `x5t`
  check, and substituted intermediates fail link-verification or anchoring.
- **No SSRF from `x5u`.** The client only ever fetches the signer chain from its
  own `--url` origin; a relative `x5u` is resolved against `--url`, and an
  absolute `x5u` with a different origin is rejected. The CA host is not an
  attacker-chosen URL.
- **Body binding** via `Content-Digest` (a covered component) prevents
  tampering with the returned roots independent of the chain.
- **Replay bounding** via `created`/`expires`. The client enforces
  `expires > created`, `expires - created <= 7d` (defensive cap against a
  misconfigured server), `now < expires`, and a 60 s future-skew cap on
  `created`. `ttl` trades signing cost against replay window; default `24h`.
- **Algorithm pinning.** `alg` is taken from the CA key on the server and, on the
  client, the verifier dispatches on the `alg` token but the *key type* is fixed
  by the signer certificate's SPKI — there is no negotiation and no `alg=none`
  path. Unknown/unsupported `alg` → reject.
- **Path validation, scoped.** Client anchoring is a real path build: issuer
  matched by DN **and** signature (not array order, so cross-signed bags
  validate), `notBefore`/`notAfter` enforced on every served cert, and
  `basicConstraints` cA=TRUE required on intermediates. The remaining RFC 5280
  checks — name constraints, EKU, policy, and revocation of the *signer* chain —
  are **out of scope**: these are the operator's own pinned CA certificates.
  Pinned roots in `K` are trusted a priori (their own validity is not re-checked),
  matching how a trust store works.
- **No secret material exposed.** `/v1/roots/signer-chain` serves only public
  certificates, already returned wholesale by other endpoints' `chain`.
- **Caching does not weaken anything.** Cached artifacts are public; the cache
  key is salted by the body hash so a roots/config change cannot serve a
  signature whose digest no longer matches the body (it would simply miss the
  cache and re-sign). A stale cached signature past `expires` is rejected by the
  client and refreshed by the server.
- **Fail-closed everywhere.** Any missing header, digest mismatch, expiry, bad
  signature, or failed anchoring aborts the client with a non-zero exit and no
  output. A server-side signing/storage failure surfaces as `500` rather than an
  unsigned `200`.

## Mission Scope

### Out of scope

- Signing any endpoint other than `GET /v1/roots`. The new
  `GET /v1/roots/signer-chain` is served unsigned (integrity is enforced by the
  signed `x5t` + chain linkage + anchoring).
- A general-purpose RFC 9421 engine (arbitrary covered components, request
  signing, multiple signatures, content negotiation). The implementation is
  specialized to this one response message.
- Remaining RFC 5280 path-validation checks of the signer chain (name
  constraints, EKU, policy, signer revocation). The client *does* enforce
  temporal validity, `basicConstraints` cA, and signature/issuer linkage with
  cross-signed-twin support (see Security and Privacy Considerations).
- Inline `x5c` chain delivery (rejected for header size); only `x5u`+`x5t`
  reference delivery is implemented.
- `rsa-pss-*` algorithms (the CA never signs with PSS).
- Changes to the `machineidentity` cookbook (separate `sorah-infra` work; this
  unblocks it).
- Server-side signature *verification* (the server only signs).

### Expected Outcomes

- `GET /v1/roots` returns a valid RFC 9421 signature over its body, signed by the
  CA key, referencing the signer chain via `Signature-Key; x5u`+`x5t`, cached for
  `ttl`. `GET /v1/roots/signer-chain` serves that chain as PEM.
- `ayane roots` requires `--root`, fetches the signer chain, verifies the
  signature against it fail-closed, and otherwise behaves as before.
- `Storage` exposes a general expiring KV cache on both SQLite and DynamoDB.
- Docs and the example config reflect all of the above.

## Implementation Plan

### 1. `ayane-protocol` — shared, crypto-free signature wire format

New module `ayane-protocol/src/httpsig.rs` (re-exported from `lib.rs`), used by
**both** server and client so the signature base is byte-identical on each side.
Add a `base64` dependency to `ayane-protocol` (already a workspace dep); no
`sha2` here (digests are computed by each side and passed in as bytes).

Public surface:

```rust
pub const SIGNATURE_HEADER: &str = "Signature";
pub const SIGNATURE_INPUT_HEADER: &str = "Signature-Input";
pub const SIGNATURE_KEY_HEADER: &str = "Signature-Key";
pub const CONTENT_DIGEST_HEADER: &str = "Content-Digest";
pub const ROOTS_SIGNATURE_LABEL: &str = "sig";
pub const SIGNER_CHAIN_PATH: &str = "/v1/roots/signer-chain";
pub const PEM_CHAIN_MEDIA_TYPE: &str = "application/pem-certificate-chain";

/// `sha-384=:<base64(digest)>:` from a 48-byte SHA-384 digest.
pub fn content_digest_header(sha384: &[u8; 48]) -> String;
/// Parse the base64 digest out of a `sha-384=:…:` value (errors on any other alg).
pub fn parse_content_digest(value: &str) -> Result<[u8; 48], HttpSigError>;

/// `sig=x509;x5u="<url>";x5t="<b64url thumbprint>"`.
pub fn signature_key_x509(x5u: &str, x5t: &str) -> String;
/// Parse the `x5u` and `x5t` out of an `x509`-scheme Signature-Key value.
pub fn parse_signature_key_x509(value: &str) -> Result<(String /*x5u*/, String /*x5t*/), HttpSigError>;
/// `BASE64URL_NOPAD(digest)` — the `x5t` thumbprint, from a precomputed
/// SHA-256 of the leaf DER (digest computed by the caller, keeping `sha2` out of
/// the protocol crate, same as `content_digest_header`).
pub fn x5t_from_digest(leaf_sha256: &[u8; 32]) -> String;

pub struct RootsSigParams { pub created: u64, pub expires: u64, pub alg: String }

/// The `("@status" …);created=…;expires=…;alg="…"` string used verbatim as the
/// `Signature-Input` member value AND the `@signature-params` line value.
pub fn roots_sig_params_value(p: &RootsSigParams) -> String;
/// Parse that string back into params (covered set is validated to be exactly
/// the fixed roots set, in order).
pub fn parse_roots_sig_params(value: &str) -> Result<RootsSigParams, HttpSigError>;

/// The full signature base to sign/verify.
pub fn roots_signature_base(
    status: u16,
    content_type: &str,
    content_digest: &str,   // the `sha-384=:…:` header value
    signature_key: &str,    // the `sig=x509;x5c=(…)` header value
    p: &RootsSigParams,
) -> String;

/// `sig=:<b64(signature)>:`
pub fn signature_header(signature: &[u8]) -> String;
/// Parse the raw signature bytes out of a `sig=:…:` value.
pub fn parse_signature_header(value: &str) -> Result<Vec<u8>, HttpSigError>;
```

The covered-component set is hardcoded to
`("@status" "content-type" "content-digest" "signature-key")`; the parser
rejects anything else (no general component engine). The `Content-Digest` byte
sequence uses standard (padded) base64 inside `:…:` per RFC 8941/9530; `x5t` uses
base64url-no-pad per the draft. `HttpSigError` is a small local enum. Unit tests
pin the exact base/param strings against hand-computed vectors.

### 2. `Storage` — expiring KV cache

`ayane/src/storage/mod.rs`:

- Add to the `Storage` trait (bytes-based to keep `dyn Storage` object-safe — a
  generic `get_cache<T>` would make the trait non-object-safe, which breaks every
  `Arc<dyn Storage>` use site):
  ```rust
  async fn get_cache(&self, key: &str) -> Result<Option<Vec<u8>>>;
  async fn set_cache(&self, key: &str, value: Vec<u8>, expires_at: SystemTime) -> Result<()>;
  ```
- Add typed free helpers `cache_get<T: DeserializeOwned>` / `cache_set<T: Serialize>`
  (JSON via `serde_json`) wrapping the byte methods — this is the `T: serde`
  surface the task described.

`ayane/src/storage/sqlite.rs`:

- New table in `from_connection`:
  ```sql
  CREATE TABLE IF NOT EXISTS cache (
      key        TEXT PRIMARY KEY,
      value      BLOB NOT NULL,
      expires_at INTEGER NOT NULL   -- unix seconds
  );
  ```
- `get_cache`: `SELECT value FROM cache WHERE key=?1 AND expires_at > ?now`;
  opportunistically `DELETE FROM cache WHERE expires_at <= ?now`. `None` if absent
  or expired.
- `set_cache`: `INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (…)`.

`ayane/src/storage/dynamodb.rs`:

- New item shape: `pk = "cache:<key>"`, `sk = "cache"`, `value` (Binary `B`),
  `ttl` (Number, `expires_at + TTL_BUFFER` so lazy TTL deletion never reaps a
  still-valid entry — same pattern as the token denylist).
- `get_cache`: `GetItem`; if absent → `None`; **enforce expiry on read** by
  comparing the stored real expiry to now (store the real `expires_at` as a
  separate `exp` Number attribute alongside the TTL-buffered `ttl`, since `ttl`
  is intentionally padded). `None` when `exp <= now`.
- `set_cache`: `PutItem` **without** a conditional expression (overwrite allowed),
  setting `value`, `exp`, and `ttl`.
- Constant `CACHE_TYPE = "cache"`.

Tests mirror the existing per-backend tests (roundtrip, miss, expiry-on-read,
overwrite). `docs/storage.md`: document the cache concern, the `cache` SQLite
table, the DynamoDB `cache:<key>` item with `exp`/`ttl`, and the contract rows.

### 3. `ayane` server — sign and cache the roots response

**`crypto.rs`** (`SignatureAlgorithm`):
- `pub fn rfc9421_alg(self) -> &'static str` per the algorithm-token table.
- `pub fn rfc9421_signature_from_der(self, der: &[u8]) -> Result<Vec<u8>>`:
  ECDSA → parse the X.509 DER `ECDSA-Sig-Value` (`p256`/`p384`
  `Signature::from_der`) and return fixed-width `to_bytes()`; RSA → passthrough.

**`ca.rs`** (`CertificateAuthority`):
- `pub fn signing_algorithm(&self) -> crypto::SignatureAlgorithm` (delegates to
  `self.key.algorithm()`).
- `pub fn signer_chain_pem(&self) -> &[String]` — the leaf-first signer chain
  served at `/v1/roots/signer-chain`; this is exactly `chain_pem` (the issuing
  certificate is already `chain_pem[0]` per `builder.rs`).
- `pub fn signer_leaf_sha256(&self) -> [u8; 32]` — SHA-256 of the leaf
  (`chain_pem[0]`) DER, for `x5t`. Compute once at `new()` and store (the leaf
  DER is already parsed there).
- `pub async fn sign_http_message(&self, base: &[u8]) -> Result<Vec<u8>>`: sign
  with the key provider, then `rfc9421_signature_from_der`.

**`config.rs`**:
- `CaConfig` gains `#[serde(default)] pub roots_signature: RootsSignatureConfig`.
- `RootsSignatureConfig { #[serde(default = default_roots_sig_ttl)] ttl: ConfigDuration }`,
  default `24h`. `#[serde(deny_unknown_fields)]`. Plumb the value through
  `builder.rs` into the `Service`.

**`service.rs`** (`Service` gains `roots_signature_ttl` and `external_url`
fields; `ServiceParts` gains them — `external_url` from `config.server`):
- New `pub fn signer_chain_pem(&self) -> String` returning the concatenated PEM
  bundle for the `/v1/roots/signer-chain` handler (joins `ca.signer_chain_pem()`).
- New `pub async fn signed_roots(&self) -> Result<SignedRoots>` where
  ```rust
  pub struct SignedRoots {
      pub body: Vec<u8>,            // exact JSON bytes
      pub content_type: &'static str, // "application/json"
      pub content_digest: String,
      pub signature_input: String, // "sig=(…);created=…;…"
      pub signature: String,       // "sig=:…:"
      pub signature_key: String,   // "sig=x509;x5u=…;x5t=…"
  }
  ```
  Flow:
  1. `body = serde_json::to_vec(&self.roots())`.
  2. `digest = SHA384(body)`; `content_digest = httpsig::content_digest_header(&digest)`.
  3. `cache_key = format!("roots-sig:v1:{}", hex(digest))` — salted by the body so
     any roots/chain/config change misses the cache and re-signs.
  4. `cache_get::<CachedRootsSig>` → if present and
     `now + refresh_margin < expires`, reuse. `refresh_margin = min(ttl/4, 300s)`
     so clients never receive an about-to-expire signature.
  5. Otherwise sign:
     `x5u = format!("{}{}", external_url.unwrap_or(""), SIGNER_CHAIN_PATH)` — an
       absolute same-origin URL when `external_url` is set, else the relative
       `/v1/roots/signer-chain`. (Stable per deployment ⇒ cache stays
       host-independent.)
     `x5t = httpsig::x5t_from_digest(&SHA256(ca.signer_leaf_der))` (via
       `ca.signer_leaf_sha256()`);
     `signature_key = httpsig::signature_key_x509(&x5u, &x5t)`;
     `created = now`, `expires = now + ttl`;
     `params = { created, expires, alg: ca.signing_algorithm().rfc9421_alg() }`;
     `base = httpsig::roots_signature_base(200, content_type, &content_digest, &signature_key, &params)`;
     `sig = ca.sign_http_message(base.as_bytes())`;
     `signature = httpsig::signature_header(&sig)`;
     `signature_input = format!("{label}={}", httpsig::roots_sig_params_value(&params))`.
     `cache_set` the `CachedRootsSig { created, expires, signature_key, signature, signature_input }`
     with `expires_at = expires` (full lifetime kept; read-side margin governs
     refresh).
  6. Assemble and return `SignedRoots` (body/content_digest recomputed each call;
     deterministic).
  Concurrent cache-miss signers across instances are acceptable (last write
  wins); noted, not synchronized.

**`http.rs`**:
- `roots` handler becomes `async` and returns a manually-assembled
  `axum::response::Response` (not `axum::Json`, to control the exact bytes that
  were digested): set `Content-Type`, `Content-Digest`, `Signature-Key`,
  `Signature-Input`, `Signature` headers and the body bytes. A signing/storage
  error maps through `ApiError` to `500`.
- New route `GET /v1/roots/signer-chain` → `signer_chain` handler returning the
  PEM bundle (`Content-Type: application/pem-certificate-chain`), unsigned.

Tests: a `service`-level test issues a signed roots response from a `testca` and
verifies it end-to-end with the *client* verification routine (shared logic), and
asserts cache reuse (second call returns identical `created`). A `crypto` test
covers DER→P1363 roundtrip.

`docs/api.md`: document the four headers, the covered set, the `x509`/`x5c`
scheme, algorithm tokens, and that the body is unchanged. `docs/configuration.md`:
document `ca.roots_signature.ttl`. `examples/ayane.example.json`: add
`roots_signature`.

### 4. `ayane-cli` — require `--root` and verify

**`cmd/roots.rs`**: rewrite `run`:
- Reject when `--root` is absent: `--root is required` (clap-level or explicit
  check).
- Fetch `roots` with the existing client, reading the response **bytes** and
  headers (not `get_json`). Add a small `cmd::get_with_headers(client, url)`
  helper or inline `client.get(url).send()` then `.bytes()` + `.headers()`.
- Resolve `x5u` against `--url` (same-origin enforced) and fetch the signer-chain
  PEM with the same client.
- Run the verification routine; on success parse `RootsResponse` from the
  verified bytes and print `certificates` (unchanged output).

**New `ayane-cli/src/httpsig.rs`**: the verifier.
- `verify_roots_response(body, headers, base_url, fetch_signer_chain, known_roots_pem, now)`
  implementing the 8-step client algorithm, using `ayane_protocol::httpsig` for
  the base/params/x5u/x5t/digest parsing and assembly. `fetch_signer_chain` is a
  closure/async fn the command supplies (so the verifier stays I/O-agnostic and
  unit-testable); it resolves `x5u` same-origin against `base_url` and GETs the
  PEM.
- `x5t` binding: `BASE64URL_NOPAD(SHA256(DER(C[0]))) == x5t` else reject.
- Raw-signature verification by `alg` token:
  `ecdsa-p256-sha256` → `p256::ecdsa` (`Signature::from_slice` of 64 bytes),
  `ecdsa-p384-sha384` → `p384::ecdsa` (96 bytes),
  `rsa-v1_5-sha{256,384,512}` → `rsa::pkcs1v15` with the matching digest;
  verifying key from the signer cert's `SubjectPublicKeyInfo`.
- A `verify_x509_signature(child, parent_spki)` mirroring the server's
  `crypto::verify_signature` (ECDSA DER + RSA PKCS#1, dispatched on the child's
  `signatureAlgorithm` OID) for chain-link and anchor checks. Anchor set `K`
  parsed from the `--root` PEM bundle via `x509-cert`.
- A recursive path builder `anchor_signer` (with a precomputed `Node` per cert:
  subject/issuer/SPKI/full DER, validity window, `is_ca`). It searches from the
  signer through the served bag for a path to `K`, substituting cross-signed twins
  (same subject+key), enforcing per-cert temporal validity and intermediate
  `cA=TRUE`, guarding against loops on `(subject, key, issuer)` edges, and bounded
  by `MAX_PATH_DEPTH`. Replaces the earlier linear `windows(2)` walk.

No new `ayane-cli` deps (it already has `x509-cert`, `der`, `spki`, `p256`,
`p384`, `rsa`, `sha2`, `signature`, `base64`, `pem`).

Tests: a unit test builds a signed response with an ephemeral CA (single-tier and
two-tier) and asserts accept; plus reject cases (digest mismatch, expired,
tampered body, wrong/absent anchor, broken chain link, bad signature).

`docs/cli.md`: `roots` now requires `--root` and verifies. `docs/security.md`:
the roots-signature threat model and verification.

### Commit grouping

Each commit is self-contained and compiles (schema + impl together):

1. **storage cache** — trait methods + typed helpers + SQLite + DynamoDB +
   `docs/storage.md` + tests.
2. **protocol + server roots signing** — `ayane-protocol::httpsig`; `crypto`/`ca`
   helpers; `config`/`builder` `roots_signature`; `service::signed_roots`;
   `http` handler; `docs/api.md`, `docs/configuration.md`, example config; tests.
3. **cli roots verification** — `ayane-cli::httpsig`; `cmd/roots.rs` require/verify;
   `docs/cli.md`, `docs/security.md`; tests.

(2 depends on 1; 3 depends on 2. Could also split the protocol module into its
own leading commit if preferred during review.)

### Deliverables

- [ ] `ayane-protocol/src/httpsig.rs` + `lib.rs` re-export; `ayane-protocol/Cargo.toml` `base64`. (`SIGNER_CHAIN_PATH`, `x5u`/`x5t` builders+parsers, base/params builders.)
- [ ] `ayane/src/storage/mod.rs` — `get_cache`/`set_cache` trait methods + `cache_get`/`cache_set` helpers.
- [ ] `ayane/src/storage/sqlite.rs` — `cache` table + impls + tests.
- [ ] `ayane/src/storage/dynamodb.rs` — `cache:<key>` item (`exp`/`ttl`) + impls + tests.
- [ ] `ayane/src/crypto.rs` — `rfc9421_alg`, `rfc9421_signature_from_der` + test.
- [ ] `ayane/src/ca.rs` — `signing_algorithm`, `signer_chain_pem`, `signer_leaf_sha256`, `sign_http_message`.
- [ ] `ayane/src/config.rs` + `ayane/src/builder.rs` — `ca.roots_signature.ttl`; plumb `server.external_url` into `Service`.
- [ ] `ayane/src/service.rs` — `SignedRoots`, `signed_roots`, `signer_chain_pem`, cache integration.
- [ ] `ayane/src/http.rs` — async signing `roots` handler emitting the headers; `GET /v1/roots/signer-chain` route + handler.
- [ ] `ayane-cli/src/httpsig.rs` — verifier (x5t binding + signature + chain anchoring).
- [ ] `ayane-cli/src/cmd/roots.rs` + `main.rs`/`cmd/mod.rs` — require `--root`, fetch headers + signer chain, verify.
- [ ] Docs: `api.md` (both endpoints), `configuration.md`, `storage.md`, `cli.md`, `security.md`; `examples/ayane.example.json`.
- [ ] Tests across all of the above; `cargo clippy` clean; an end-to-end smoke test (sign on server, verify with CLI).

## Current Status

Implemented. All three commits' worth of code is written and green: `cargo test
--workspace` (108 tests) and `cargo clippy --workspace --all-targets` are clean,
and `tmp/roots-sig-smoke.sh` exercises the full path against a real server
(verify against the correct pin; `--root` required; wrong pin fails closed;
signer-chain served). Not yet committed (on `main`, awaiting branch decision).

Decisions locked:

- **Trust model:** reference the signer certificate chain from `Signature-Key`
  via the draft's `x509` scheme `x5u` (URL) + `x5t` (signed leaf thumbprint),
  serving the chain at `GET /v1/roots/signer-chain` as PEM. The client binds the
  fetched leaf to `x5t`, verifies the signature with it, and anchors the chain to
  the pinned `--root` bundle (supports single- and multi-tier CAs). Chosen over
  inline `x5c` to keep response headers within proxy/gateway size limits.
- **Enforcement:** `ayane roots` **always** verifies and **requires** `--root`;
  no unauthenticated bootstrap. Fail-closed. The signer chain is fetched only
  from the client's own `--url` origin (no SSRF via `x5u`).
- **Signing key:** the configured CA issuing key (no separate signing key for now).
- **Standards:** RFC 9421 (signature) + RFC 9530 (`Content-Digest`) +
  draft-hardt-httpbis-signature-key (`Signature-Key` `x509` scheme, `x5u`+`x5t`);
  minimal single-message implementation of our own, shared base builder in
  `ayane-protocol`.
- **Covered components (fixed):**
  `("@status" "content-type" "content-digest" "signature-key")`.
- **ECDSA signature encoding:** RFC 9421 P1363 `r‖s` (converted from the CA's
  X.509 DER signature).
- **Caching:** memoized in `Storage` (new expiring KV), keyed by body hash;
  default `ttl = 24h`; server refreshes before expiry (`refresh_margin =
  min(ttl/4, 5m)`); client skew leeway `60s`.
- **Out of scope:** full RFC 5280 path validation of the signer chain; signing
  any other endpoint; a general RFC 9421 engine; `x5u`; `rsa-pss`.

### Checklist

- [x] Commit 1: storage cache (trait + SQLite + DynamoDB + helpers + docs + tests)
- [x] Commit 2: protocol `httpsig` + server signing (crypto/ca/config/service/http) + docs + example + tests
- [x] Commit 3: CLI verification (`httpsig` + `roots.rs`) + docs + tests
- [x] `cargo clippy` clean; end-to-end smoke test passes

### Updates

- 2026-06-22: Spec written.
- 2026-06-22: Switched signer-chain delivery from inline `Signature-Key; x5c` to
  reference `x5u`+`x5t` with a new unsigned `GET /v1/roots/signer-chain` PEM
  endpoint, to avoid response-header size limits. Client gains a same-origin
  signer-chain fetch and an `x5t` leaf-binding step (now an 8-step routine).
- 2026-06-22: De-duplicated signature verification into a new
  `ayane-protocol::crypto` (`verify_x509_signature` for DER ECDSA / RSA PKCS#1 by
  OID, and `verify_rfc9421_signature` for raw P1363 / RSA by `alg` token, sharing
  one internal RSA helper and a `SignatureError`). The server's
  `crypto::verify_signature` and the CLI's cert-link / RFC 9421 checks now both
  delegate to it; the duplicated dispatch and RSA helpers were removed (and the
  CLI's now-unused `digest` dependency dropped). `ayane-protocol` gains the
  RustCrypto verification deps. (Considered `rustls-webpki` but it validates an
  end-entity TLS leaf — it rejects a CA-as-leaf and requires an EKU, and would not
  express signer-level cross-signing — so it is the wrong tool here.)
- 2026-06-22: Hardened client anchoring after a security review. Replaced the
  linear `windows(2)` chain walk — which wrongly rejected any served bag
  containing a cross-signed/cross-root cert — with a real path build (issuer by
  DN + signature, cross-signed-twin substitution, loop guard, depth bound). Added
  signer-chain temporal-validity and `basicConstraints` cA enforcement, and a
  client-side cap (`expires - created <= 7d`, plus `expires > created`) on the
  signature lifetime. Pinned roots remain trusted a priori.
- 2026-06-22: Default `ca.roots_signature.ttl` set to `24h` (was `1h`).
- 2026-06-22: `Content-Digest` over the roots body uses **SHA-384** (was
  SHA-256), matching the SHA-384 signing tier. `sha-384` is an ayane-private
  Content-Digest algorithm (RFC 9530 registers only `sha-256`/`sha-512`); safe as
  the only verifier is `ayane-cli`. The `x5t` leaf thumbprint stays SHA-256 per
  the draft.
- 2026-06-22: Implemented all three commits. `ayane-protocol::httpsig` shared
  builder; storage cache (SQLite `cache` table, DynamoDB `cache:<key>` with
  `exp`/`ttl`); server `signed_roots` (cached) + `roots` / `roots/signer-chain`
  handlers; CLI `httpsig` verifier + `roots.rs` requiring `--root`. One forced
  deviation: the cache trait is byte-based (`get_cache`/`set_cache`) with typed
  `cache_get`/`cache_set` helpers, because a generic `get_cache<T>` would break
  `dyn Storage` object-safety. Full workspace tests + clippy clean; smoke test
  green.
