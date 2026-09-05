# Security model

MCP Windows Remote Shell intentionally executes arbitrary shell commands on the
selected target. It is a proof of concept, not a sandbox or a hardened production
remote-management product. Use it only on machines you are authorized to operate.

## Credentials and their consequences

| Credential | Location | Consequence of compromise |
|---|---|---|
| Agent bearer token | Target process and rendezvous session | Command execution on the connected target |
| READ_KEY | Operator configuration and Worker | Reading the agent URL/token, therefore command access |
| PROVISION_KEY | Private operator state and Worker | Administration of the accepted package credential |
| Persistent package credential | Prepared target package | Publishing a future target when the mailbox is free |
| Session deletion token | Private target session state | Deleting that session, not another one |

The reusable package credential does not expire or get renewed by the MCP server.
A compromised target can keep a copy and impersonate a future target when no
session is active. This is the explicit convenience/security tradeoff. Cleanup
cannot revoke copied credentials. Rotate the package credential and redistribute
it if its copies are no longer trusted.

The Worker prevents active-session replacement and assigns increasing session
sequences. The MCP checks the configured package ID and pins each session's
identity. This authenticates a credential and a session, not the physical device
or the truthfulness of its hostname, files, or command output.

## Transport and execution

- The agent binds to loopback only and requires a bearer token on health/exec.
- Cloudflare Tunnel exposes the authenticated agent through an outbound channel.
  Cloudflare remains a trusted transport/provider; this is not additional
  end-to-end encryption independent of that provider.
- Redirects and nonconforming target URLs are rejected. Bodies, output, and
  execution time are bounded.
- Unix process groups and Windows Job Objects supervise ordinary descendants.
  An authorized arbitrary command can interact with external services or
  deliberately escape some forms of supervision. This is not containment.
- Remote files and command output remain untrusted data, including when presented
  through an automated client. Do not treat them as instructions to disclose
  local secrets.

## Cleanup and distribution

Cleanup removes known package files and identified processes only. It refuses
protected, linked, removable, network, or unverified locations and preserves
additional files. It does not erase OS logs, backups, screenshots, or copies.
The reusable package itself must be kept private and must never be a GitHub asset.

Cloudflared may be downloaded from the official GitHub latest release without
version/hash pinning. Project executables are unsigned. Both are accepted POC
limitations; do not describe them as supply-chain guarantees.

## Reporting a vulnerability

Never include live credentials, configured packages, private paths, or target data
in a public issue. If private vulnerability reporting is enabled for the repository,
use its Security tab to report privately. Otherwise, ask the repository owner for
a private reporting channel without publishing exploitation details or secrets.
No private reporting address is invented by this template.
