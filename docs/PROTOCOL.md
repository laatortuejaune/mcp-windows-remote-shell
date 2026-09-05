# Relay protocol

The rendezvous uses a SQLite-backed Durable Object named `SessionMailbox` and
keeps one active session per deployment. The agent exposes ordinary HTTP on
loopback; the operator-side MCP server exposes the stdio MCP interface.

## Worker endpoints

| Endpoint | Authentication | Behavior |
|---|---|---|
| `GET /` | None | Service/protocol identification only |
| `POST /ticket` | Bearer PROVISION_KEY | Register or explicitly rotate a package credential |
| `GET /ticket` | Bearer PROVISION_KEY | Credential metadata, never the secret |
| `POST /session` | Bearer package credential | Open a session or retry the identical publication |
| `GET /session` | Bearer READ_KEY | Read the current target and its agent token |
| `DELETE /session` | Bearer session deletion token + X-Relay-Session-Id | Remove only the matching session |

Persistent credential registration:

```json
{"ticket_id":"32-lowercase-hex","ticket_hash":"64-lowercase-hex-sha256","expires_at":null,"generation":1}
```

Session publication:

```json
{
  "ticket_id": "32-lowercase-hex",
  "url": "https://EXAMPLE.trycloudflare.com",
  "token": "AGENT_TOKEN",
  "host": "OPTIONAL_REPORTED_HOST",
  "os": "windows",
  "session_id": "32-lowercase-hex",
  "delete_token": "64-lowercase-hex"
}
```

The example hostname must be replaced with the actual lowercase quick-tunnel
origin. The Worker returns a session with `published_at`, `expires_at`, and a
server-assigned increasing `sequence` for persistent credentials. It never
returns the package secret or deletion token to readers.

Sessions last 12 hours. A different publication cannot replace an active session.
An identical retry returns the same dates. Deletion/expiration frees the mailbox
without revoking a persistent package credential. Previously used session IDs
remain recorded to reject replay. Old deletion tokens cannot remove newer sessions.

Credential registration generations increase on explicit rotation. Exact retries
are idempotent. An authenticated operator can convert a legacy v2 credential to
persistent form with the same ID/hash/generation and `expires_at:null`, preserving
an already active v2 session. Session sequence numbers prevent client rollback.

## Agent endpoints

`GET /health` and `POST /exec` both require `Authorization: Bearer AGENT_TOKEN`.
The agent refuses to start without a token and listens only on `127.0.0.1`.

```json
{"command":"echo hello","timeout_seconds":30}
```

```json
{"exit_code":0,"stdout":"hello\n","stderr":"","timed_out":false,"truncated":false,"duration_ms":4}
```

Request bodies are capped at 64 KiB. Each captured stream is capped at 1 MiB.
Commands use `cmd /c` on Windows and `sh -c` on Unix and do not share shell state.
The MCP transport budget must exceed command timeout by at least 15 seconds.

## Storage and compatibility

Credentials, session identity pins, and sequence state are not public source.
Operator installations use `~/.config/remote-support-relay/operator.json` by
default. A migration must copy credentials without printing or rotating them and
must update MCP configuration before removing any previous private state.

English package entry points are `start-relay.cmd`, `cleanup.cmd`, and `README.txt`.
Export a fresh package directory when upgrading older filenames; do not overlay
new files onto a running target package. Existing deployed Worker names can be
kept in ignored `wrangler.local.jsonc`; the public template is generic.
