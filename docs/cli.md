# CLI reference (ayane)

The `ayane` command-line client acquires and manages certificates against an ayane certificate authority: it mints issuance tokens, requests new certificates, renews and rekeys existing ones (proving key possession with RFC 9449 DPoP), revokes certificates, and queries the CA. This page documents every subcommand, its flags, and a runnable example.

## Synopsis

```bash
ayane <command> [flags]
```

| Command | Purpose |
| --- | --- |
| `token` | Mint an issuance token (OTT) signed by a provisioner key. |
| `certificate` | Request a new certificate using an issuance token. |
| `renew` | Renew an existing certificate (same key), authenticated with DPoP. |
| `rekey` | Rekey an existing certificate (new key), authenticated with DPoP. |
| `revoke` | Revoke a certificate by serial number. |
| `roots` | Fetch the CA root certificate(s). |
| `health` | Check CA health. |
| `provisioners` | List configured provisioners. |

The binary also accepts `--version` and `--help` (and `<command> --help`).

### Connection flags (TLS)

The `certificate`, `renew`, `rekey`, `revoke`, `roots`, `health`, and `provisioners` commands all share a common set of connection flags. TLS is terminated by the CA's reverse proxy or AWS Lambda Function URL (see [server operations](deployment.md)), so these flags control how the client trusts that endpoint.

| Flag | Required / default | Description |
| --- | --- | --- |
| `--url <URL>` | required | CA base URL, e.g. `https://ca.example`. A trailing slash is trimmed before the `/v1/...` path is appended. |
| `--root <PATH>` | optional | Trust this PEM root certificate when connecting (added to the client's trust store, e.g. for a private CA fronting the server). |
| `--insecure` | optional flag, default off | Skip TLS verification. Testing only. |

For `token` these connection flags do not apply; `token` is fully offline and prints a JWT to stdout.

### Certificate output format

All commands that write a certificate (`certificate`, `renew`, `rekey`) write a **fullchain** PEM file to `--out`: the leaf certificate first, followed by the issuer chain returned by the CA, each block newline-terminated. Commands that generate a key (`certificate`, `rekey`) write the private key as **PKCS#8 PEM** to `--key-out`.

## token

Mints a one-time issuance token (OTT) — a JWT signed by a provisioner's private key — that authorizes a `sign` (or `revoke`) request. This command runs entirely offline; it never contacts the CA. See [authentication and tokens](provisioners.md) for how the server validates the token's claims.

| Flag | Required / default | Description |
| --- | --- | --- |
| `--key <PATH>` | required | Provisioner private key PEM (the OTT signing key). |
| `--issuer <NAME>` | required | Provisioner name, emitted as the token `iss` claim. |
| `--url <URL>` | optional | CA base URL, used to derive the audience when `--audience` is absent. |
| `--audience <AUD>` | optional | Explicit token audience. Overrides the `--url`/`--operation` derivation. |
| `--operation <OP>` | default `sign` | Operation the token authorizes: `sign` or `revoke`. For `revoke`, set `--subject` to the certificate serial number. |
| `--subject <CN>` | required | Certificate subject / common name. For `revoke`, the serial number. |
| `--san <SAN>` | optional, repeatable | Permitted SAN. Repeat for multiple values; empty means only `--subject` is permitted. |
| `--validity <DUR>` | default `5m` | Token lifetime. |

The audience is resolved as follows: if `--audience` is given it is used verbatim; otherwise if `--url` is given the audience becomes `<url>/v1/<operation>` (so `sign` → `<url>/v1/sign`, `revoke` → `<url>/v1/revoke`); if neither is given the command errors. The token `nbf` is backdated 5 seconds and `exp` is `iat + validity`.

The JWT algorithm is pinned to the provisioner key type: P-256 → `ES256`, P-384 → `ES384`, RSA → `RS256`.

`--validity` (and any duration in this client) is `<integer><unit>` where unit is one of `s`, `m`, `h`, `d`. There is no week unit in the CLI's duration parser.

```bash
# Mint a 10-minute sign token for web.example with one SAN.
ayane token \
  --key provisioner.key.pem \
  --issuer my-provisioner \
  --url https://ca.example \
  --subject web.example \
  --san web.example \
  --validity 10m > token.jwt
```

```bash
# Mint a revocation token for a serial number.
ayane token \
  --key provisioner.key.pem \
  --issuer my-provisioner \
  --url https://ca.example \
  --operation revoke \
  --subject 12345678901234567890 > revoke-token.jwt
```

## certificate

Generates a fresh key pair, builds a CSR, and requests a new certificate from `POST /v1/sign` using an issuance token. Writes the new private key and the fullchain certificate to disk.

| Flag | Required / default | Description |
| --- | --- | --- |
| `--url <URL>` | required | CA base URL (connection flag). |
| `--root <PATH>` | optional | Trust this PEM root for the TLS connection (connection flag). |
| `--insecure` | optional flag | Skip TLS verification (connection flag). |
| `--token-file <PATH>` | required | File holding the issuance token (OTT); read from stdin when omitted or `-`. The contents are trimmed. Never accepted as an inline value. |
| `--subject <CN>` | required | Subject / common name placed in the CSR. |
| `--san <SAN>` | optional, repeatable | SAN to request. Repeat for multiple values. |
| `--kty <TYPE>` | default `ec256` | Key type for the generated key: `ec256`, `ec384`, `rsa2048`, `rsa3072`, `rsa4096`. |
| `--key-out <PATH>` | required | Where to write the generated private key (PKCS#8 PEM). |
| `--out <PATH>` | required | Where to write the certificate (leaf + chain) PEM. |
| `--not-before <TS>` | optional | RFC 3339 `notBefore` requested for the certificate. |
| `--not-after <TS>` | optional | RFC 3339 `notAfter` requested for the certificate. |

On success the command prints the issued serial number and `notAfter` to stderr (`issued serial <n> (notAfter <ts>)`).

```bash
ayane certificate \
  --url https://ca.example \
  --token-file token.jwt \
  --subject web.example \
  --san web.example \
  --san www.example \
  --kty ec256 \
  --key-out web.key.pem \
  --out web.fullchain.pem
```

## renew

Renews an existing certificate **with the same key**. The command reads the current certificate and key, constructs an RFC 9449 DPoP proof signed by that key, and calls `POST /v1/renew`. No issuance token is needed: the DPoP proof is verified directly against the certificate's public key. See [authentication and tokens](provisioners.md) for the DPoP rules (the CA additionally requires the certificate to have been issued by it, to be unexpired, and not revoked).

| Flag | Required / default | Description |
| --- | --- | --- |
| `--url <URL>` | required | CA base URL (connection flag). |
| `--root <PATH>` | optional | Trust this PEM root for the TLS connection (connection flag). |
| `--insecure` | optional flag | Skip TLS verification (connection flag). |
| `--cert <PATH>` | required | Existing certificate PEM (leaf, or a fullchain — the leaf is used). |
| `--key <PATH>` | required | Existing private key PEM (signs the DPoP proof). |
| `--out <PATH>` | required (one-shot); defaults to `--cert` under `--loop` | Where to write the renewed certificate (fullchain). |

The renewed certificate is written to `--out` (atomically: a sibling temp file is renamed into place, preserving the target's existing permissions); the existing key is reused, so there is no `--key-out`. The command prints `renewed serial <n>` to stderr.

```bash
ayane renew \
  --url https://ca.example \
  --cert web.fullchain.pem \
  --key web.key.pem \
  --out web.renewed.pem
```

### Continuous renewal (`--loop`)

With `--loop`, `renew` does not exit after one renewal: it keeps the certificate fresh for the life of the process. It computes a renewal time from the certificate's validity window, sleeps until then, renews, runs an optional hook, and repeats. Run it under a process supervisor (e.g. systemd with `Restart=always`). It runs in the foreground — it is **not** a forking daemon; the supervisor owns lifecycle and logging.

| Flag | Default | Description |
| --- | --- | --- |
| `--loop` | off | Renew continuously instead of once. |
| `--renew-fraction <F>` | `0.66` | Renew once the certificate has passed fraction `F` (0–1, exclusive) of its validity window. Mutually exclusive with `--renew-before`. |
| `--renew-before <DUR>` | — | Renew when remaining validity drops below `DUR` (e.g. `8h`), instead of a fraction. |
| `--jitter <DUR>` | `5m` | Maximum random jitter subtracted from the renewal time, to spread a fleet's renewals. |
| `--max-sleep <DUR>` | `1h` | Cap on a single sleep before re-reading the certificate and recomputing the schedule. |
| `--exec <CMD>` | — | Shell command run via `sh -c` after each successful renewal. A non-zero exit is logged and does not stop the loop. |

Durations are parsed by [`humantime`](https://docs.rs/humantime) — `30s`, `5m`, `8h`, `1d`, `1w`, and compound forms like `1h30m`. Because renewal preserves the original certificate's lifetime, the cadence stays stable across renewals.

Signals: `SIGHUP` renews immediately (regardless of the schedule); `SIGTERM`/`SIGINT` stop the loop and exit `0`. Transient failures (network, `5xx`, `429`) are retried with exponential backoff and jitter; terminal failures (a revoked or already-expired certificate, bad arguments) exit non-zero so the supervisor — and, where configured, a fresh bootstrap — can take over. An **expired** certificate cannot be renewed, so the loop's job is to renew well before expiry.

```bash
ayane renew --loop \
  --url https://ca.example \
  --root /etc/ssl/roots.pem \
  --cert /var/lib/identity/identity.crt \
  --key  /var/lib/identity/key.pem \
  --exec /usr/local/bin/reload-services
# --out defaults to --cert (renew in place); --renew-fraction 0.66, --jitter 5m
```

## rekey

Rekeys an existing certificate by issuing it against a **new** key. The DPoP proof is signed with the *old* key (proving possession of the certificate being replaced), while a fresh key pair is generated and a new CSR is built for it. The subject and SANs are read from the existing certificate and reused in the new CSR. Calls `POST /v1/rekey`.

| Flag | Required / default | Description |
| --- | --- | --- |
| `--url <URL>` | required | CA base URL (connection flag). |
| `--root <PATH>` | optional | Trust this PEM root for the TLS connection (connection flag). |
| `--insecure` | optional flag | Skip TLS verification (connection flag). |
| `--cert <PATH>` | required | Existing certificate PEM (leaf or fullchain). |
| `--key <PATH>` | required | Existing private key PEM. Proves possession via DPoP. |
| `--kty <TYPE>` | default `ec256` | New key type: `ec256`, `ec384`, `rsa2048`, `rsa3072`, `rsa4096`. |
| `--key-out <PATH>` | required | Where to write the new private key (PKCS#8 PEM). |
| `--out <PATH>` | required | Where to write the rekeyed certificate (fullchain). |

The subject and SANs of the new certificate are taken from the existing leaf certificate; you cannot change them with `rekey` (use `certificate` for a different subject). The command prints `rekeyed serial <n>` to stderr.

```bash
ayane rekey \
  --url https://ca.example \
  --cert web.fullchain.pem \
  --key web.key.pem \
  --kty ec384 \
  --key-out web.new.key.pem \
  --out web.rekeyed.pem
```

## revoke

Revokes a certificate by serial number via `POST /v1/revoke`. Two authorization modes are supported:

- **Token-authorized revocation:** pass `--token` (a `revoke` OTT minted with `ayane token --operation revoke`).
- **DPoP self-revocation:** pass `--cert` and `--key` together. The command signs a DPoP proof with the key and sends the certificate so the CA can confirm the caller holds the certificate being revoked.

| Flag | Required / default | Description |
| --- | --- | --- |
| `--url <URL>` | required | CA base URL (connection flag). |
| `--root <PATH>` | optional | Trust this PEM root for the TLS connection (connection flag). |
| `--insecure` | optional flag | Skip TLS verification (connection flag). |
| `--serial <SERIAL>` | required | Serial number, decimal or `0x`-hex. |
| `--reason <TEXT>` | optional | Human-readable revocation reason. |
| `--reason-code <N>` | optional | RFC 5280 reason code (integer). |
| `--token <JWT>` | conditional | Revocation token (provisioner-authorized). |
| `--cert <PATH>` | conditional | Certificate PEM, for DPoP self-revocation. |
| `--key <PATH>` | conditional | Private key PEM, for DPoP self-revocation. |

`--cert` and `--key` must be provided together; supplying only one is an error. You must provide either `--token`, or both `--cert` and `--key`. The command prints `revocation status: <status>` to stderr (the CA returns `revoked`).

```bash
# Token-authorized revocation.
ayane revoke \
  --url https://ca.example \
  --serial 12345678901234567890 \
  --reason "key compromise" \
  --reason-code 1 \
  --token "$(cat revoke-token.jwt)"
```

```bash
# DPoP self-revocation using the certificate's own key.
ayane revoke \
  --url https://ca.example \
  --serial 0x1f2e3d4c5b6a7988 \
  --cert web.fullchain.pem \
  --key web.key.pem
```

## roots

Fetches the CA's root certificate(s) from `GET /v1/roots`, **verifies the response's CA signature against a pinned trusted root bundle**, and prints the roots as PEM to stdout.

`--root` is **required**: the `GET /v1/roots` response is signed by the CA key (RFC 9421; see [the API reference](api.md#roots-response-signature)), and that signature is verified against the certificates in `--root`. This defends against a third party in the TLS path (e.g. a Lambda Function URL's Amazon-issued serving certificate) substituting a malicious root bundle. Verification is fail-closed — on any mismatch the command prints nothing and exits non-zero.

| Flag | Required / default | Description |
| --- | --- | --- |
| `--url <URL>` | required | CA base URL. |
| `--root <PATH>` | **required** | Pinned trusted root bundle (PEM). Used both as the TLS trust anchor and as the anchor the response signature is verified against. |
| `--insecure` | optional flag | Skip **TLS** verification (testing only). Does **not** bypass the response-signature check. |

```bash
ayane roots --url https://ca.example --root /etc/ayane/known-roots.pem > ca-roots.pem
```

The command fetches the signer certificate chain referenced by the response (from `GET /v1/roots/signer-chain`, on the same origin as `--url`), binds its leaf to the signed thumbprint, verifies the signature, and confirms the signer chains up to a certificate in `--root`. The printed roots are the bundle conveyed in the verified response — so `--root` can hold a long-lived pinned anchor while the command discovers new or rotated roots that chain up to it.

Establish the initial `--root` out of band (ship it with the host image or configuration management), exactly as `machineidentity` seeds its `roots.pem`.

## health

Calls `GET /v1/health` and prints the JSON response (pretty-printed) to stdout. The server returns `{"status":"ok"}`.

| Flag | Required / default | Description |
| --- | --- | --- |
| `--url <URL>` | required | CA base URL. |
| `--root <PATH>` | optional | Trust this PEM root for the TLS connection. |
| `--insecure` | optional flag | Skip TLS verification. |

```bash
ayane health --url https://ca.example
```

```json
{
  "status": "ok"
}
```

## provisioners

Calls `GET /v1/provisioners` and prints the JSON response (pretty-printed). Lists each configured provisioner's `name`, `type`, and `audiences`. See [provisioners and authentication](provisioners.md) for how these are used to validate tokens.

| Flag | Required / default | Description |
| --- | --- | --- |
| `--url <URL>` | required | CA base URL. |
| `--root <PATH>` | optional | Trust this PEM root for the TLS connection. |
| `--insecure` | optional flag | Skip TLS verification. |

```bash
ayane provisioners --url https://ca.example
```

```json
{
  "provisioners": [
    {
      "name": "my-provisioner",
      "type": "jwk",
      "audiences": []
    }
  ]
}
```

## Errors

When the CA returns a non-2xx status, the client parses the RFC 7807 `application/problem+json` body and reports `CA returned <status>: <detail-or-title>`; if the body is not problem JSON it reports the raw body. The process exits with a failure status and prints `error: <message>` to stderr. See the [HTTP API reference](api.md) for the problem-details schema and status codes.

## See also

- [Authentication and tokens](provisioners.md)
- [HTTP API reference](api.md)
- [Server operations](deployment.md)
- [docs index](README.md)
