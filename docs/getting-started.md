# Getting started

This quickstart takes you from a fresh checkout to issuing, renewing, and revoking a certificate against a locally running `ayane` CA. It uses a self-signed development root with a local PEM signing key and an in-memory store, so it needs no AWS account. For production deployments (AWS KMS keys, DynamoDB storage, Lambda Function URLs) see [deployment](deployment.md) and [configuration](configuration.md).

## Prerequisites

- A Rust toolchain (stable) with `cargo`.
- `openssl` (key/certificate generation and verification).
- `ruby` (used once to derive a JWK from a provisioner public key; any JWK tool works).

## Build the workspace

The workspace builds two binaries: `ayane-server` (the CA server, from the `ayane` crate) and `ayane` (the client CLI, from the `ayane-cli` crate).

```bash
cargo build --release
```

The binaries land in `target/release/`:

| Binary | Crate | Role |
| --- | --- | --- |
| `ayane-server` | `ayane` | The CA server (standalone axum or AWS Lambda) |
| `ayane` | `ayane-cli` | The client: mint tokens, request/renew/rekey/revoke certificates |

Put them on your `PATH` or invoke them by full path. The examples below assume a working directory you can write to:

```bash
mkdir -p ~/ayane-quickstart && cd ~/ayane-quickstart
```

## Create a CA key and certificate

The `file` signing-key provider loads a PEM private key. For EC keys it must be in **PKCS#8** form (`-----BEGIN PRIVATE KEY-----`), not the legacy SEC1 form (`-----BEGIN EC PRIVATE KEY-----`). Generate a P-256 key and convert it:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out ca.key.sec1.pem
openssl pkcs8 -topk8 -nocrypt -in ca.key.sec1.pem -out ca.key.pem
rm ca.key.sec1.pem
```

Confirm the header is `BEGIN PRIVATE KEY` (PKCS#8):

```bash
head -1 ca.key.pem
# -----BEGIN PRIVATE KEY-----
```

Create a self-signed development root certificate from that key. In a real deployment you would issue from an intermediate; for the quickstart the issuing certificate and the root are the same certificate.

```bash
openssl req -x509 -new -key ca.key.pem -sha256 -days 3650 \
  -subj "/CN=Ayane Dev Root CA" -out ca.crt
```

When `ca.roots` is omitted in the config, the issuing `ca.certificate` itself is served from `GET /v1/roots`, so a single self-signed certificate is all you need here.

## Create a provisioner key and JWK

A provisioner authorizes issuance by signing one-time tokens (OTTs). Its **private** key stays with whoever mints tokens (your CLI); the server only holds the matching **public** key, embedded as a JWK in the config. Generate a separate P-256 key (PKCS#8 again, so the CLI's `token` command can load it):

```bash
openssl ecparam -name prime256v1 -genkey -noout -out prov.key.sec1.pem
openssl pkcs8 -topk8 -nocrypt -in prov.key.sec1.pem -out prov.key.pem
rm prov.key.sec1.pem
```

Derive the public JWK (`x`/`y` are URL-safe base64 of the uncompressed EC point coordinates):

```bash
ruby -ropenssl -rbase64 -rjson -e '
  pkey = OpenSSL::PKey.read(File.read("prov.key.pem"))
  body = [pkey.public_key.to_bn(:uncompressed).to_s(16)].pack("H*")[1..]
  b64  = ->(s){ Base64.urlsafe_encode64(s).delete("=") }
  puts JSON.pretty_generate(
    kty: "EC", crv: "P-256", alg: "ES256",
    x: b64.call(body[0, 32]), y: b64.call(body[32, 32]))
'
```

This prints something like:

```json
{
  "kty": "EC",
  "crv": "P-256",
  "alg": "ES256",
  "x": "gHeDlkLlLsYjcl3MVxIEQOxsXEnq09U65AH4p3vu9yU",
  "y": "YFDzfxOlsrgGXBqHGv49IJS0gkfaZeWyIx3RyBmNqXg"
}
```

The `alg` pins the JWT signature algorithm the server accepts for this provisioner, which makes token validation immune to algorithm-confusion attacks. See [provisioners](provisioners.md) for the full JWK and algorithm details.

## Write a minimal config

Create `config.json`. Paste the JWK you derived above into `provisioners[].key`. A full annotated reference for every field lives in [configuration](configuration.md); this is the minimum needed to issue a server certificate.

```json
{
  "ca": {
    "certificate": { "file": "ca.crt" },
    "key": { "type": "file", "file": "ca.key.pem" }
  },
  "provisioners": [
    {
      "name": "quickstart",
      "type": "jwk",
      "key": {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "x": "PASTE_YOUR_X",
        "y": "PASTE_YOUR_Y"
      }
    }
  ],
  "default_template": "server",
  "templates": {
    "server": {
      "key_usage": ["digital_signature", "key_encipherment"],
      "extended_key_usage": ["server_auth"],
      "default_validity": "24h",
      "max_validity": "168h"
    }
  },
  "storage": { "type": "sqlite", "path": ":memory:" },
  "server": {
    "listen": "127.0.0.1:9443",
    "external_url": "http://127.0.0.1:9443",
    "tls": { "enabled": false }
  }
}
```

Notes on the defaults this relies on:

| Field | Behavior when set as above |
| --- | --- |
| `storage` `{"type":"sqlite","path":":memory:"}` | The issued-certificate inventory, revocation records, and the anti-replay token denylist live in an in-process SQLite database — non-durable, fine for a demo. Use a file `path` or `dynamodb` for anything real ([storage](storage.md)). |
| `server.listen` | Address the standalone server binds. Defaults to `0.0.0.0:9443` when omitted. |
| `server.external_url` | Public base URL. Token `aud` and DPoP `htu` are validated against it. If you omit it the server logs a warning and derives them from request `Host`/`X-Forwarded-*` headers — always set it for any deployment behind an untrusted proxy. |
| `server.tls` `{"enabled":false}` | Serve plaintext HTTP for this demo. By default the standalone server self-issues a serving certificate from its own CA and serves HTTPS; we disable that here so the `http://127.0.0.1:9443` client commands below work without configuring the CLI to trust the dev root. |
| `default_template` | Template applied when a provisioner does not name one. A reference to an undefined template name fails startup. |

For this local demo we run plain HTTP on `127.0.0.1` (`server.tls.enabled = false`), so there is no TLS to verify. In a real standalone deployment ayane serves HTTPS by default with a self-issued, auto-renewing certificate from its own CA — see [deployment](deployment.md#self-issued-serving-tls). A working example with the AWS providers wired up is at [`examples/ayane.example.json`](../examples/ayane.example.json).

## Run the server

The server reads its config from the first argument, then `AYANE_CONFIG_BASE64URL` (inline base64url-encoded JSON), then the `AYANE_CONFIG` path, then defaults to `ayane.json` — see [deployment](deployment.md) for details:

```bash
./target/release/ayane-server config.json
```

You should see `ayane server listening` on `info` level. Adjust verbosity with `RUST_LOG` (for example `RUST_LOG=debug`). Leave it running and open a second terminal for the client.

Check that it is up and that your provisioner loaded:

```bash
ayane health --url http://127.0.0.1:9443
# {"status":"ok"}

ayane provisioners --url http://127.0.0.1:9443
# {"provisioners":[{"name":"quickstart","type":"jwk","audiences":[...]}]}

ayane roots --url http://127.0.0.1:9443
# -----BEGIN CERTIFICATE----- ... (your Ayane Dev Root CA)
```

## Issue a certificate

Issuance is two steps: mint a one-time token with the provisioner private key, then exchange it for a certificate. The CLI generates a fresh leaf key locally and builds the CSR for you.

### Mint an issuance token

```bash
ayane token \
  --key prov.key.pem \
  --issuer quickstart \
  --url http://127.0.0.1:9443 \
  --subject app.internal.example \
  --san app.internal.example \
  --validity 5m > token.jwt
```

| Flag | Meaning |
| --- | --- |
| `--key` | Provisioner private key PEM (signs the token). |
| `--issuer` | Provisioner name; becomes the token `iss` and must match a configured provisioner. |
| `--url` | CA base URL; the audience is derived as `<url>/v1/<operation>` when `--audience` is absent. |
| `--audience` | Explicit token `aud`, overriding the `--url`/`--operation` derivation. |
| `--operation` | `sign` (default) or `revoke`. For `revoke`, set `--subject` to the serial number. |
| `--subject` | Certificate common name (for `sign`). |
| `--san` | Permitted SAN; repeatable. An empty list restricts the certificate to just `--subject`. |
| `--validity` | Token lifetime, e.g. `5m`. The token is single-use (`jti`) regardless. |

The command prints the JWT to stdout (captured to `token.jwt` above).

### Exchange the token for a certificate

```bash
ayane certificate \
  --url http://127.0.0.1:9443 \
  --token-file token.jwt \
  --subject app.internal.example \
  --san app.internal.example \
  --kty ec256 \
  --key-out app.key.pem \
  --out app.crt
```

`--token-file token.jwt` reads the token from a file (omit it, or pass `-`, to read from stdin; a token is never accepted as an inline argument). On success the CLI writes the new private key to `--key-out` (PKCS#8 PEM) and the certificate to `--out`, then prints the serial and expiry to stderr:

```
issued serial 123456789012345678901234567890 (notAfter 2026-06-15T12:00:00Z)
```

The `--out` file is a **fullchain**: the leaf certificate followed by the issuer chain returned by the CA.

| Flag | Meaning |
| --- | --- |
| `--token-file` | File holding the issuance token; reads stdin when omitted or `-`. |
| `--subject` / `--san` | CN and SANs to request; must stay within what the token permits. |
| `--kty` | Leaf key type: `ec256` (default), `ec384`, `rsa2048`, `rsa3072`, `rsa4096`. |
| `--key-out` | Where to write the generated private key (PKCS#8 PEM). |
| `--out` | Where to write the leaf + chain certificate PEM. |
| `--not-before` / `--not-after` | Optional RFC 3339 validity bounds (clamped to the template). |
| `--root` | Trust this PEM root for the TLS connection to the CA. |
| `--insecure` | Skip TLS verification (testing only). |

### Verify the certificate

```bash
openssl x509 -in app.crt -noout -subject -issuer -dates -ext subjectAltName

ayane roots --url http://127.0.0.1:9443 > roots.pem
openssl verify -CAfile roots.pem app.crt
# app.crt: OK
```

## Renew the certificate

Renewal keeps the same key and proves possession with an RFC 9449 DPoP proof signed by the leaf key — no provisioner token is needed. The CLI builds the proof from `--key` automatically.

```bash
ayane renew \
  --url http://127.0.0.1:9443 \
  --cert app.crt \
  --key app.key.pem \
  --out app.renewed.crt
```

The CA verifies the DPoP proof against the presented certificate's public key, and additionally checks that the certificate was issued by this CA, is not revoked, and is not expired. On success it returns a fresh fullchain to `--out`. To roll the key as well, use `rekey` (it generates a new key, signs the proof with the **old** key, and reuses the existing subject and SANs); see [renewal-and-rekey](renewal-revocation.md).

## Revoke the certificate

Revoke by serial number. For self-revocation, present the certificate and its key so the CLI can attach a DPoP proof — no token required.

```bash
SERIAL=$(openssl x509 -in app.crt -noout -serial | cut -d= -f2)

ayane revoke \
  --url http://127.0.0.1:9443 \
  --serial 0x$SERIAL \
  --reason "decommissioned" \
  --cert app.crt \
  --key app.key.pem
# revocation status: revoked
```

The `--serial` value accepts decimal or `0x`-prefixed hex (openssl prints hex, hence the `0x` prefix above). Alternatively, an operator can revoke any serial with a provisioner-signed revocation token: mint it with `ayane token --operation revoke --subject <serial>` and pass it via `--revoke`'s `--token`. Revocation is idempotent. Details and reason codes are in [revocation](renewal-revocation.md).

```bash
ayane revoke \
  --url http://127.0.0.1:9443 \
  --serial 0x$SERIAL \
  --token "$(ayane token --key prov.key.pem --issuer quickstart \
              --url http://127.0.0.1:9443 --operation revoke --subject 0x$SERIAL)"
```

## What you built

You now have a running CA that issues, renews, and revokes certificates through the `/v1` API, authorized by a JWK provisioner and DPoP-bound key possession. To take it further:

- Swap the local PEM key for AWS KMS and the in-memory store for DynamoDB — [configuration](configuration.md), [storage](storage.md).
- Shape issued certificates with templates (validity windows, key usages, CA certificates) — [templates](templates.md).
- Gate or enrich issuance with webhooks and stream audit events — [webhooks](webhooks.md), [events](events.md).
- Deploy behind a reverse proxy or as a Lambda Function URL — [deployment](deployment.md).

## See also

- [configuration](configuration.md)
- [provisioners](provisioners.md)
- [renewal-and-rekey](renewal-revocation.md)
- [docs index](README.md)
