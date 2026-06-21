# Storage

ayane keeps three kinds of state outside the issuing key: an **issued-certificate inventory** (a durable record of every certificate the CA produces), **revocation records** (to decide whether a certificate may still be renewed or is revoked), and a **one-time-token denylist** (to reject replays of issuance tokens and DPoP proofs). All three are served by a single pluggable [`Storage`](#the-storage-contract) backend.

Two backends ship today:

| Backend | `type` | Durable | Use |
|---|---|---|---|
| SQLite | `sqlite` (default, `:memory:`) | File path only | Development, tests, single-node deployments |
| DynamoDB | `dynamodb` | Yes | Production, multi-instance and Lambda deployments |

## Configuration

Storage is configured under the top-level `storage` key (see the [configuration reference](configuration.md)). When omitted it defaults to an in-process SQLite database (`:memory:`).

```json
{
  "storage": { "type": "sqlite", "path": ":memory:" }
}
```

A filesystem `path` makes the SQLite database durable for a single node:

```json
{
  "storage": { "type": "sqlite", "path": "/var/lib/ayane/state.db" }
}
```

```json
{
  "storage": {
    "type": "dynamodb",
    "table_name": "ayane-state",
    "region": "us-east-1"
  }
}
```

`path` defaults to `:memory:`. The legacy `type: "memory"` is accepted as an alias for an in-process SQLite database. `region` is optional; when omitted the AWS SDK's default region resolution applies (environment, profile, or instance metadata).

## What is persisted

### Issued-certificate inventory

Every certificate the CA issues — whether through `sign`, `renew`, or `rekey` — is recorded keyed by its decimal serial number:

| Field | Description |
|---|---|
| `serial_number` | Decimal serial number of the issued certificate |
| `subject` | Subject common name (empty for a SAN-only certificate) |
| `sans` | Subject Alternative Names |
| `not_before` | RFC 3339 notBefore |
| `not_after` | RFC 3339 notAfter |
| `issued_at` | RFC 3339 issuance timestamp |
| `provisioner` | Provisioner that authorized the issuance, if any (absent for renew/rekey, which authenticate via DPoP) |
| `operation` | `sign`, `renew`, or `rekey` |
| `pem` | Full PEM of the issued leaf certificate |

Recording is **fail-closed**: the inventory entry is committed before the certificate is returned to the client, so the registry never misses an issuance. If the write fails, the request fails (the serial is consumed but the certificate is not handed out). Serial numbers are random 128-bit values, so each issuance is a fresh row; a reused serial signals a collision and is rejected rather than overwriting the existing record.

### Revocation records

When a certificate is revoked, ayane stores a record keyed by the certificate's decimal serial number:

| Field | Description |
|---|---|
| `serial_number` | Decimal serial number of the revoked certificate |
| `reason_code` | RFC 5280 CRLReason code (integer) |
| `reason` | Optional human-readable reason |
| `revoked_at` | RFC 3339 timestamp |
| `provisioner` | Provisioner that authorized the revocation, if any |

Revocation is **idempotent**: revoking an already-revoked serial succeeds and keeps the original record. Renewal and rekey consult this store and refuse to reissue a revoked certificate. See [renewal and revocation](renewal-revocation.md).

### One-time-token denylist

Every issuance token (OTT) and DPoP proof carries a unique `jti`. Before a credential is allowed to take effect, ayane atomically *claims* its `jti`; a second use of the same `jti` is rejected as a replay. The claim is recorded with an expiry that outlives the window in which the credential could still validate, after which it may be reaped.

The `jti` namespaces are kept separate per credential kind (`ott` vs `dpop`) so the two anti-replay spaces can never collide.

## The Storage contract

A backend implements these asynchronous operations:

| Operation | Semantics |
|---|---|
| `record_certificate(record)` | Add an issued certificate to the inventory. A pre-existing serial is an error (collision), never an overwrite. |
| `get_certificate(serial)` | Return the inventory record for a serial number, or none. |
| `list_certificates()` | Return every issued-certificate record (order unspecified). |
| `revoke(record)` | Record a revocation. Idempotent — keeps the original record on a repeat. |
| `get_revocation(serial)` | Return the revocation record for a serial number, or none. |
| `list_revocations()` | Return every revocation record, e.g. to assemble a CRL. |
| `claim_token(jti, expires_at)` | Atomically claim a one-time id. Returns a conflict (surfaced as `401 Unauthorized`, "already been used") if it was already claimed. |
| `get_cache(key)` | Return a cached byte value, or none when absent **or expired** (expiry enforced on read). |
| `set_cache(key, value, expires_at)` | Write a cached byte value with an absolute expiry, overwriting any existing entry. |

The atomicity of `claim_token` is what makes anti-replay safe under concurrency: two simultaneous requests carrying the same token race on the claim, and exactly one wins.

The two `*_cache` methods are a **general-purpose key/value cache with per-entry expiry**, used today to memoize the signed `/v1/roots` artifact (see [the HTTP API](api.md)) but available for any cached value. The trait is byte-oriented to stay object-safe; the typed helpers `cache_get::<T>` / `cache_set::<T>` (in `storage::mod`) wrap it with JSON serialization.

## DynamoDB backend

The DynamoDB backend uses a **single table** with a composite primary key — a String partition key `pk` and a String sort key `sk` (a type marker). Three item shapes share the table, distinguished by the `pk` prefix and `sk` value. Listing (issued certificates, or revocations for a CRL) is served by an **inverted global secondary index** named `inverted` whose partition key is `sk` and sort key is `pk`.

### Table schema

Create the table with `pk`/`sk` as the key schema and the `inverted` GSI (`PAY_PER_REQUEST` billing is a good default):

```bash
aws dynamodb create-table \
  --table-name ayane-state \
  --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE \
  --global-secondary-indexes \
    'IndexName=inverted,KeySchema=[{AttributeName=sk,KeyType=HASH},{AttributeName=pk,KeyType=RANGE}],Projection={ProjectionType=ALL}' \
  --billing-mode PAY_PER_REQUEST
```

### Issued-certificate items

```
pk            = "certificate:<serial>"
sk            = "certificate"
serial_number = <decimal serial>        (String)
subject       = <common name>           (String)
sans          = [<name>, ...]           (List of String)
not_before    = <rfc3339>               (String)
not_after     = <rfc3339>               (String)
issued_at     = <rfc3339>               (String)
provisioner   = <name>                  (String, if provided)
operation     = "sign" | "renew" | "rekey"   (String)
pem           = <leaf certificate PEM>  (String)
```

Issued-certificate items carry **no `ttl`** — the inventory is retained indefinitely. They are written with an `attribute_not_exists(pk)` condition so a serial collision is surfaced rather than silently overwriting.

### Revocation items

```
pk            = "revocation:<serial>"
sk            = "revocation"
serial_number = <decimal serial>        (String)
reason_code   = <crl reason code>       (Number)
reason        = <text>                  (String, if provided)
revoked_at    = <rfc3339>               (String)
provisioner   = <name>                  (String, if provided)
```

Revocations are written with an `attribute_not_exists(pk)` condition so that re-revoking a serial is a no-op rather than an overwrite.

### Token denylist items

```
pk  = "token:<jti>"
sk  = "token"
ttl = <expiry epoch seconds>            (Number)
```

`claim_token` writes with an `attribute_not_exists(pk)` condition; a conditional-check failure means the id was already claimed and is reported as a replay.

### Cache items

```
pk    = "cache:<key>"
sk    = "cache"
value = <cached bytes>                  (Binary)
exp   = <real expiry epoch seconds>     (Number)
ttl   = <exp + buffer epoch seconds>    (Number)
```

`set_cache` writes unconditionally (last-writer-wins). `get_cache` honours the real expiry `exp` on read — `ttl` is padded beyond `exp` so DynamoDB's lazy TTL deletion never reaps an entry the application still considers valid, the same pattern as the token denylist. Enable DynamoDB TTL on `ttl` (already covered by the [update-time-to-live](#enabling-automatic-expiry) step above) to reap expired cache rows automatically.

### Enabling automatic expiry

The denylist rows carry a `ttl` attribute holding the expiry as Unix epoch seconds. Enable DynamoDB Time To Live on that attribute so expired claims are reaped automatically and the table does not grow without bound:

```bash
aws dynamodb update-time-to-live \
  --table-name ayane-state \
  --time-to-live-specification "Enabled=true,AttributeName=ttl"
```

Issued-certificate and revocation records have no `ttl` and are retained indefinitely; if you want them to expire, add your own lifecycle process keyed on their timestamps plus the certificate's original validity.

### IAM

The server's role needs `dynamodb:PutItem` and `dynamodb:GetItem` on the table, plus `dynamodb:Query` on the table and its `inverted` index for listing:

```json
{
  "Effect": "Allow",
  "Action": ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:Query"],
  "Resource": [
    "arn:aws:dynamodb:us-east-1:123456789012:table/ayane-state",
    "arn:aws:dynamodb:us-east-1:123456789012:table/ayane-state/index/inverted"
  ]
}
```

See the [deployment guide](deployment.md) for the full IAM policy and AWS wiring.

## SQLite backend

The `sqlite` backend stores all of the above in one SQLite database (the inventory, revocations, the token denylist, and the `cache` table). With the default `:memory:` path it is an in-process database — simple and fast but **not durable** and **not shared** across instances: restarting the server forgets all state, and two instances do not see each other's. A filesystem `path` makes it durable for a single node, but it is still local to that node. Use `:memory:` for development and tests; use a filesystem path only for single-node deployments. For any multi-instance or Lambda deployment, use DynamoDB.

## Operational notes

- For any multi-instance or Lambda deployment, use DynamoDB so that the inventory, anti-replay, and revocation are consistent across all instances.
- Token-denylist growth is bounded by enabling DynamoDB TTL on `ttl`; the issued-certificate inventory grows with every issuance and is never reaped automatically.
- A storage outage fails closed for issuance: the token claim and the inventory write must both complete before a certificate is returned, so issuance never proceeds without recording it.

## See also

- [Configuration reference](configuration.md) — the `storage` block
- [Renewal, rekey, and revocation](renewal-revocation.md) — how revocation records gate reissuance
- [Deployment](deployment.md) — DynamoDB table and IAM setup
- [docs index](README.md)
