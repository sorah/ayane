# Audit events

Ayane emits a structured audit record for every authorization decision and certificate operation, fanning it out to the configured destinations. Auditing is independent of [webhooks](webhooks.md): webhooks participate in the issuance decision, whereas audit events are a one-way record of what happened (and why) that is written after the decision is made.

## The audit model

Each `POST /v1/sign`, `/v1/renew`, `/v1/rekey`, and `/v1/revoke` produces exactly one [`AuditEvent`](configuration.md). The event is built at the end of the operation:

- On success, the event carries the `success` outcome plus the provisioner, subject, serial number, and SANs of the issued or revoked certificate.
- On failure, a denial event is emitted with the `denied` or `error` outcome and a `detail` string carrying the error message.

The event is then handed to every configured [`EventSink`](#destinations). Emission is **best-effort**: a sink that fails is logged and skipped, and the certificate operation is never failed because of it (see [Best-effort emission](#best-effort-emission)).

## The AuditEvent schema

The on-the-wire JSON record is defined by `AuditEvent` in `ayane/src/event_sink/mod.rs`. Optional fields are omitted entirely when empty (`Option::None`, or an empty `sans` array), so a minimal event contains only `event_type`, `timestamp`, and `outcome`.

| Field | JSON type | Always present | Description |
| --- | --- | --- | --- |
| `event_type` | string | yes | Dotted event type, e.g. `certificate.issued`, `certificate.revoked`. See [Event types](#event-types). |
| `timestamp` | string | yes | RFC 3339 timestamp (seconds precision), stamped when the event is constructed. |
| `outcome` | string | yes | One of `success`, `denied`, `error`. See [Outcomes](#outcomes). |
| `provisioner` | string | no | The provisioner involved, when known. Omitted if absent. |
| `subject` | string | no | Certificate subject / common name, when known. Omitted if absent or empty. |
| `serial_number` | string | no | Certificate serial number in decimal. Omitted if absent. |
| `sans` | array of string | no | Subject Alternative Names. Omitted when the list is empty. |
| `detail` | string | no | Free-form detail, such as a denial reason or a revocation reason. Omitted if absent. |
| `request_id` | string | no | Correlating request id (see below). Omitted if absent. |

The `request_id` is taken from the incoming `x-request-id` header; when that header is absent the server generates a random 16-byte hex value so every operation is still correlatable. Put this value into your front proxy logs to join a request across the proxy and the audit stream.

### Field population by operation

The values placed into the optional fields depend on the operation that produced the event:

| Event | `provisioner` | `subject` | `serial_number` | `sans` | `detail` |
| --- | --- | --- | --- | --- | --- |
| `certificate.issued` (success) | issuing provisioner | token `sub` | issued serial | permitted SANs | — |
| `certificate.renewed` / `certificate.rekeyed` (success) | — | certificate CN (omitted when empty) | new serial | certificate SANs | — |
| `certificate.revoked` (success) | revoking provisioner, if any | — | revoked serial | — | revocation reason, if given |
| any operation (denial) | — | — | — | — | error message |

## Event types

`event_type` is a dotted string. The values emitted by the server today, sourced from `ayane/src/service.rs`, are:

| `event_type` | Emitted for |
| --- | --- |
| `certificate.issued` | `POST /v1/sign` — a new leaf certificate was requested. |
| `certificate.renewed` | `POST /v1/renew` — same-key reissue under a DPoP proof. |
| `certificate.rekeyed` | `POST /v1/rekey` — reissue with a new key from the CSR. |
| `certificate.revoked` | `POST /v1/revoke` — a certificate was revoked. |

Both the success record and the denial record for an operation share the same `event_type`; they are distinguished by `outcome`. For EventBridge, `event_type` is also used as the rule-matchable `detail-type` (see [EventBridge](#aws-eventbridge)).

## Outcomes

The `outcome` field has three possible values:

| `outcome` | Meaning |
| --- | --- |
| `success` | The operation completed and a certificate was issued, reissued, or revoked. |
| `denied` | The request was rejected by an authorization check (bad token, failed DPoP proof, a [webhook](webhooks.md) that returned `allow: false`, a replayed `jti`, etc.). |
| `error` | The operation failed due to a server-side or configuration fault. |

The split between `denied` and `error` is mechanical: a `Config` or `Internal` error maps to `error`, and every other error type (`BadRequest`, `Unauthorized`, `Forbidden`, `NotFound`, `Conflict`) maps to `denied`. For both, the `detail` field carries the error message string. See [errors](api.md) for how those same error types map to HTTP status codes.

## Best-effort emission

Audit emission never blocks or fails a certificate operation. After the operation's outcome is decided, the event is offered to each configured sink in turn; if a sink's `emit` returns an error, the server logs a warning and moves on:

```
WARN audit sink failed error=<...> sink_event=certificate.issued
```

The practical implications:

- A misconfigured or unreachable destination (e.g. EventBridge throttling, a read-only audit file) degrades to a logged warning, not a failed `POST /v1/sign`.
- Audit is therefore **not** a guaranteed-delivery channel. If you need durable, gap-free auditing, ship the stdout/file lines through a log pipeline you control, or alert on the `audit sink failed` warning.
- Multiple destinations are independent: if `stdout` succeeds and `event_bridge` fails, the stdout line is still written.

## Destinations

Destinations are configured under the top-level `events` array. Each entry is tagged by `type`. With no `events` configured, no audit events are emitted at all. The three destination types are defined by `EventConfig` in `ayane/src/config.rs`.

| `type` | Sink | Fields |
| --- | --- | --- |
| `stdout` | `StdoutSink` | none |
| `file` | `FileSink` | `path` (required) |
| `event_bridge` | `EventBridgeSink` | `event_bus_name?`, `source?`, `region?` |

You can list several destinations at once; the event is delivered to all of them.

```json
{
  "events": [
    { "type": "stdout" },
    { "type": "file", "path": "/var/log/ayane/audit.jsonl" },
    {
      "type": "event_bridge",
      "event_bus_name": "default",
      "source": "ayane",
      "region": "us-east-1"
    }
  ]
}
```

### stdout

```json
{ "type": "stdout" }
```

Writes one compact JSON line per event to standard output via `println!`. This is the simplest destination and pairs well with a container log collector. Sample line:

```json
{"event_type":"certificate.issued","timestamp":"2026-06-14T09:30:00Z","outcome":"success","provisioner":"ci","subject":"svc.internal.example.com","serial_number":"123456789012345678901234567890","sans":["svc.internal.example.com"],"request_id":"3f1c9e7a..."}
```

A denial on the same endpoint looks like this — note the `outcome` and the `detail` carrying the rejection reason:

```json
{"event_type":"certificate.issued","timestamp":"2026-06-14T09:31:11Z","outcome":"denied","detail":"token or proof has already been used","request_id":"a02b..."}
```

### file

```json
{ "type": "file", "path": "/var/log/ayane/audit.jsonl" }
```

Appends one compact JSON line per event to the file at `path`. The file is opened (creating it if absent) when the server starts, and each write appends a single line. Writes are serialized under a mutex so that concurrent operations do not interleave their lines, making the output a clean newline-delimited JSON (`jsonl`) stream you can `tail -f` or feed to a log shipper.

If the file cannot be opened at startup, server startup fails. If a later append fails, the failure follows the [best-effort](#best-effort-emission) rule and is only logged.

### AWS EventBridge

```json
{
  "type": "event_bridge",
  "event_bus_name": "default",
  "source": "ayane",
  "region": "us-east-1"
}
```

Publishes each audit event to an Amazon EventBridge event bus using a single `PutEvents` call per event.

| Field | Default | Maps to |
| --- | --- | --- |
| `event_bus_name` | `default` | The `EventBusName` of the target entry. |
| `source` | `ayane` | The `Source` of the entry; use this to scope EventBridge rules to Ayane. |
| `region` | inherits the process/SDK region | Region override for the EventBridge client. |

Each event is sent as one `PutEventsRequestEntry`:

- `Source` is the configured `source` (default `ayane`).
- `DetailType` is the event's `event_type` (e.g. `certificate.issued`).
- `Detail` is the JSON-serialized `AuditEvent` — the same body shown for [stdout](#stdout).
- `EventBusName` is the configured `event_bus_name`.

If `PutEvents` returns any failed entries (a non-zero `FailedEntryCount`), the sink reports an error, which is then handled per the [best-effort](#best-effort-emission) rule (logged, not fatal).

The IAM principal the server runs as needs `events:PutEvents` on the target bus. EventBridge is also available when running under [AWS Lambda](deployment.md); ensure the function's execution role grants the same permission.

#### Sample EventBridge event

After EventBridge wraps the entry, a consumer (rule target, archive, or `aws events` capture) sees the envelope below. The Ayane `AuditEvent` is the value of `detail`, and `detail-type` mirrors `event_type`:

```json
{
  "version": "0",
  "id": "5f7e8a1c-0b3d-4e2a-9c11-7a2b3c4d5e6f",
  "detail-type": "certificate.issued",
  "source": "ayane",
  "account": "123456789012",
  "time": "2026-06-14T09:30:00Z",
  "region": "us-east-1",
  "resources": [],
  "detail": {
    "event_type": "certificate.issued",
    "timestamp": "2026-06-14T09:30:00Z",
    "outcome": "success",
    "provisioner": "ci",
    "subject": "svc.internal.example.com",
    "serial_number": "123456789012345678901234567890",
    "sans": ["svc.internal.example.com"],
    "request_id": "3f1c9e7a..."
  }
}
```

A matching rule can route on `source` and `detail-type`, for example to alert on every revocation:

```json
{
  "source": ["ayane"],
  "detail-type": ["certificate.revoked"]
}
```

Or to capture only denied authorizations across all certificate operations:

```json
{
  "source": ["ayane"],
  "detail": { "outcome": ["denied"] }
}
```

## See also

- [configuration](configuration.md) — the full server configuration schema, including the `events` array.
- [webhooks](webhooks.md) — callbacks that gate and/or customize the decision an audit event records.
- [errors](api.md) — the error types that determine the `denied` vs `error` outcome.
- [docs index](README.md)
