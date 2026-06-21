# Spec: long-running renewal loop for `ayane renew`

## Overview

`ayane renew` today is a one-shot: it presents an existing certificate, proves
possession of its key with a DPoP proof, and writes the renewed certificate
once. Long-lived hosts need the certificate kept fresh automatically for the
life of the machine — the role that `step ca renew --daemon --exec <hook>`
plays in the `machineidentity` cookbook
(`sorah-infra/.../machineidentity/templates/etc/systemd/system/machineidentity-renewal.service`).

This spec adds a **supervised renewal loop** to the `ayane` CLI: a foreground
process that watches a certificate's validity window, renews it shortly before a
configurable fraction of its lifetime elapses (with jitter), runs an optional
post-renewal hook, and repeats — intended to run under a process supervisor
(systemd `Restart=always`).

It is deliberately **not a daemon** in the fork-and-detach sense (neither is
step-ca's `--daemon`, which is a misnomer — it never forks). It runs in the
foreground and lets the supervisor own lifecycle, logging, and restart. The flag
is therefore named `--loop`, not `--daemon`.

## Scope

In scope:

- A `--loop` mode for the existing `renew` subcommand (`ayane-cli`), reusing the
  existing one-shot renew logic for each iteration.
- Renewal-threshold computation (fraction-of-lifetime, with `--renew-before`
  duration override), jitter, sleep/wake, post-renewal `--exec` hook, signal
  handling, and error classification with backoff.

Out of scope (separate follow-ups, noted under Integration):

- Changes to the `machineidentity` cookbook / systemd units (consumes this
  feature; tracked in `sorah-infra`).
- `rekey` loop mode. Only `renew` (same key) gets a loop; rekey remains one-shot.
- Any server-side change. The server already enforces every gate the loop
  relies on; this is a pure CLI feature.

## Background: what the server guarantees (already implemented)

These existing behaviors (`ayane/src/service.rs`) are load-bearing for the loop
design and require no change:

- **Expired certs cannot be renewed** — `now >= notAfter` → `403 Forbidden`
  ("certificate has expired and cannot be renewed", `service.rs:368`). The loop
  must always renew *before* expiry; a fully-expired cert is out of the loop's
  recovery scope (the bootstrap path re-issues).
- **Renewal preserves lifetime, subject, SANs, and extensions** —
  `not_after = now + (original notAfter − original notBefore)` (`service.rs:393`).
  Each renewed cert has the same validity *span*, so the fraction threshold
  produces a stable cadence, and the loop never re-passes subject/SANs.
- **Revoked certs are refused** — `403 Forbidden` ("certificate is revoked",
  `service.rs:361`).
- **Same key for renew** — the DPoP proof is signed by the existing cert's key;
  the private key file is unchanged across iterations.

## CLI surface

The loop extends the existing `renew` subcommand (`ayane-cli/src/cmd/renew.rs`).
Existing one-shot flags are reused unchanged: `--url`, `--root`, `--insecure`
(via `UrlArgs`), `--cert`, `--key`, `--out`.

New flags:

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--loop` | bool | `false` | Run continuously instead of renewing once and exiting. When set, all flags below apply; without it they are ignored (a warning is logged if any loop-only flag is set without `--loop`). |
| `--renew-fraction` | f64 in `(0.0, 1.0)` | `0.66` | Renew once the cert has passed this fraction of its validity window. Mutually exclusive with `--renew-before`. |
| `--renew-before` | duration | — | Alternative threshold: renew when remaining validity drops below this duration. Overrides `--renew-fraction` when set; supplying both is an error. |
| `--jitter` | duration | `5m` | Maximum jitter, **subtracted** from the computed renewal time (uniform random in `[0, jitter]`), so a fleet does not renew simultaneously. Subtracting only ever pulls renewal *earlier*, never past expiry. |
| `--exec` | string | — | Shell command run via `sh -c` after each **successful** renewal. Optional. |
| `--max-sleep` | duration | `1h` | Cap on a single sleep before re-evaluating, to bound drift from clock jumps / host suspend. The threshold is recomputed after each wake. |

`--out` defaults to the value of `--cert` (renew in place) so the next iteration
reads the freshly renewed certificate. In one-shot mode `--out` remains required
as today.

Duration parsing reuses the CLI's existing `parse_duration_secs`
(`ayane-cli/src/cmd/token.rs`) — units `s`/`m`/`h`/`d`. Extract it to a shared
helper (`cmd/mod.rs`) rather than duplicating.

### Example (loop)

```bash
ayane renew --loop \
  --url https://ca.example \
  --root /var/lib/machineidentity/roots.pem \
  --cert /var/lib/machineidentity/stage/identity.crt \
  --key  /var/lib/machineidentity/stage/key.pem \
  --exec /usr/bin/machineidentity-renewal
# --out defaults to --cert (in place); --renew-fraction 0.66, --jitter 5m
```

## Behavior

### Threshold computation

Given the current certificate's `notBefore` (`nb`) and `notAfter` (`na`):

```
lifetime          L = na - nb
renew_at_base     = nb + renew_fraction * L         # default fraction 0.66
                  = na - renew_before               # when --renew-before set
jitter            j = uniform_random[0, jitter_max] # default jitter_max 5m
renew_at          = renew_at_base - j
```

`renew_at` is clamped to be ≥ `nb` (never schedule before the cert is valid).

### Main loop

1. **Read** `--cert` and `--key` from disk. Parse the cert's validity window. If
   the cert is unreadable or unparseable → **fatal** (see Error handling).
2. **Compute** `renew_at` per above.
3. **Decide**:
   - If `now >= renew_at` → renew now. On the **first** iteration only, first
     sleep a *startup jitter* — uniform `[0, min(jitter_max, max_sleep)]` — so a
     fleet rebooting together does not stampede the CA. Subsequent immediate
     renewals (e.g. tight threshold) use no extra startup delay.
   - Else → sleep until `renew_at`, but no longer than `--max-sleep`; on wake,
     **go to step 1** (re-read, recompute) rather than assuming the cert is
     unchanged (it may have been replaced out of band).
4. **Renew** by invoking the existing one-shot renew path (build DPoP proof
   against `--key`, `POST /v1/renew`, receive the fullchain). Write the result
   to `--out` (default `--cert`) atomically: write to a temp file in the same
   directory, `fsync`, `rename` over the target — so a reader never observes a
   truncated cert. Preserve the existing file's mode/owner.
5. **On success**: log the new serial and notAfter. If `--exec` is set, run it
   via `sh -c <cmd>` inheriting the process environment. Exec failure (non-zero
   exit / spawn error) is **logged as a warning and does not abort the loop** —
   it is not a renewal failure. Reset the backoff counter.
6. **On renewal failure**: classify (below) and either back off and retry, or
   exit non-zero.
7. Loop back to step 1.

### Error handling and classification

| Condition | Class | Loop action |
| --- | --- | --- |
| Network error, timeout, connection refused | transient | Backoff + retry |
| HTTP `5xx`, HTTP `429` | transient | Backoff + retry |
| HTTP `4xx` other than `429` (e.g. `401` bad proof, `403` revoked/expired) | fatal | Log error, **exit non-zero** |
| Cert/key file unreadable or unparseable at startup | fatal | Log error, **exit non-zero** |
| Cert/key file unreadable on a later iteration | transient | Backoff + retry (file may be mid-replacement) |
| Invalid args (e.g. both `--renew-fraction` and `--renew-before`, fraction out of range) | fatal | Exit non-zero before the loop starts |

**Fatal → exit non-zero** deliberately delegates recovery to the supervisor and
the bootstrap path: a revoked or already-expired cert cannot be renewed, so the
loop surfaces it rather than spinning. Under the cookbook, systemd
`Restart=always`/`RestartSec` restarts the unit, and the bootstrap service's
`ConditionPathExists`/expiry check re-issues from scratch when appropriate.

**Backoff**: exponential with full jitter — `sleep = min(cap, base * 2^n)` then
randomized in `[0, sleep]`; `base = 1m`, `cap = 30m`. Increment `n` per
consecutive transient failure; reset to `0` after any successful renewal.

### Signals

| Signal | Action |
| --- | --- |
| `SIGHUP` | Interrupt the current sleep and renew immediately (matches the cookbook's `ExecReload=/bin/kill -HUP $MAINPID`). Resets to the normal schedule afterward. |
| `SIGTERM`, `SIGINT` | Stop after the current in-flight renewal/exec completes (or immediately if idle in a sleep); exit `0`. |

Implement via `tokio::signal::unix`. The sleep is a `tokio::select!` over the
timer, a SIGHUP stream, and a shutdown (SIGTERM/SIGINT) stream.

## Architecture / where logic lives

- **`ayane-cli/src/cmd/renew.rs`** — gains the loop. Refactor the current body
  into `renew_once(&client, &args) -> Result<RenewOutcome>` returning the parsed
  cert (serial, notAfter, validity window) so the loop can both write output and
  recompute the threshold without re-reading. `run()` branches on `--loop`:
  one-shot calls `renew_once` once; loop mode drives the state machine above.
- **Threshold + jitter math** — a small pure helper (`fn next_renewal(nb, na,
  policy, jitter, rng) -> Instant`/`SystemTime`) kept free of I/O so it is unit-
  testable.
- **Duration parsing** — promote `parse_duration_secs` from `cmd/token.rs` to
  `cmd/mod.rs` as a shared `parse_duration` returning `std::time::Duration`;
  update `token.rs` to use it.
- **Atomic write** — a shared `write_atomic(path, bytes, mode)` helper in
  `cmd/mod.rs` (also usable by one-shot `--out`).
- **RNG** — use the `rand` crate for jitter and backoff. Confirm it is already
  in the dependency tree (it is pulled transitively by the crypto stack); add an
  explicit `ayane-cli` dependency if not. Determinism is not required.

No changes to `ayane-protocol` or the server crate.

## Security considerations

- **No new key handling** — the loop reuses the existing one-shot DPoP path; the
  private key is read from `--key` and never written or transmitted. Renew keeps
  the same key.
- **`--exec` runs an arbitrary shell command** with the loop process's
  privileges and environment. This mirrors `step ca renew --exec` and the
  existing cookbook trust model (the command string is operator-controlled in
  the unit file, not attacker-influenced). Document that `--exec` is a shell
  command and must be trusted. The renewed cert content is never interpolated
  into the command.
- **Atomic, mode-preserving writes** avoid exposing a truncated cert or
  loosening file permissions on the identity material.
- **`--insecure`** retains its one-shot semantics and warning; unchanged.

## Operations / integration

The consuming change lives in `sorah-infra` (separate PR, out of scope here).
Sketch of the resulting unit, for reference:

```ini
[Service]
ExecStart=/usr/bin/ayane renew --loop \
          --url https://ca.example \
          --root /var/lib/machineidentity/roots.pem \
          --cert /var/lib/machineidentity/stage/identity.crt \
          --key  /var/lib/machineidentity/stage/key.pem \
          --exec /usr/bin/machineidentity-renewal
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=20m
```

Notes for that follow-up (not implemented here):

- The `--exec` hook (`machineidentity-renewal`) keeps doing the stage→dest copy
  and reload-notify, but its root-fetch step changes from `step ca roots` /
  `step ca federation` to `ayane roots` (multiple roots come back in one
  `/v1/roots` response — federation is not needed).
- `ConditionPathExists`/expiry-based bootstrap re-issue is unchanged and remains
  the recovery path when the loop exits fatally on an expired/revoked cert.

## Deliverables

- [ ] `ayane-cli/src/cmd/renew.rs` — refactor to `renew_once`; add `--loop` and
      loop-only flags; implement the state machine, threshold/jitter, exec hook,
      signal handling, and error classification/backoff.
- [ ] `ayane-cli/src/cmd/mod.rs` — shared `parse_duration`, `write_atomic`, and
      the `next_renewal` threshold helper (or a small sibling module).
- [ ] `ayane-cli/src/cmd/token.rs` — switch to the shared duration parser.
- [ ] `ayane-cli/Cargo.toml` — add `rand` and `tokio` `signal` feature if not
      already enabled.
- [ ] Unit tests: `next_renewal` (fraction vs `--renew-before`, jitter bounds,
      clamp to `nb`, already-past → renew-now); duration parsing; error
      classification (transient vs fatal mapping); backoff progression.
- [ ] `docs/renewal-revocation.md` and `docs/cli.md` — document `renew --loop`
      and its flags (usage-focused; design rationale stays in this spec).

## Current Status

Implemented. All checklist items done; `cargo clippy` clean, unit tests and an
end-to-end smoke test pass.

Note vs. spec: no `Cargo.toml` change was needed — `rand` is already a direct
`ayane-cli` dependency and `tokio` already enables the `signal` feature.

Decisions locked:
- Mechanism: in-process supervised loop in `ayane renew`, foreground under
  systemd — flagged `--loop` (not `--daemon`).
- Threshold: fraction-of-lifetime (default `0.66`) with `--renew-before`
  duration override; jitter subtracted (default `5m`).
- Expiry/revoked → fatal exit (delegate recovery to supervisor + bootstrap);
  network/5xx/429 → exponential backoff with jitter (base 1m, cap 30m).
- `SIGHUP` = renew now; `SIGTERM`/`SIGINT` = graceful exit.
- `--out` defaults to `--cert` (in-place, atomic write).

### Checklist
- [x] Implement loop in `renew.rs`
- [x] Shared helpers in `cmd/mod.rs` (`parse_duration`, `write_atomic`; `next_renewal` lives in `renew.rs`)
- [x] `token.rs` uses shared duration parser
- [x] ~~`Cargo.toml` deps~~ — not needed (`rand` and tokio `signal` already present)
- [x] Unit tests
- [x] Docs (`renewal-revocation.md`, `cli.md`)

### Updates

- 2026-06-18: Spec written.
- 2026-06-18: Implemented. `renew --loop` with fraction/`--renew-before`
  threshold, jitter, `--exec` hook, `SIGHUP`/`SIGTERM`/`SIGINT` handling, and
  transient-vs-terminal error classification with exponential backoff. Added
  typed `RequestError` + `post_json_typed` in `cmd/mod.rs`, shared
  `parse_duration`/`write_atomic`. 10 unit tests + an end-to-end smoke test
  (`tmp/renew-loop-smoke.sh`: idle → SIGHUP force-renew → atomic in-place
  rewrite → exec hook → graceful SIGTERM, renewed cert verifies) all pass;
  clippy clean.
