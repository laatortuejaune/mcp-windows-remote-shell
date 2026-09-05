MCP WINDOWS REMOTE SHELL - Windows target package
=================================================

1. Copy this entire prepared package to a dedicated writable directory on the
   target computer's fixed local drive. Keep the original package for reuse.
   Do not launch from removable storage or a network share.
2. Double-click start-relay.cmd. The operator connection is automatic.
3. Leave the launcher window open while troubleshooting.
4. Press Ctrl+C to stop the relay and start cleanup. Read the cleanup result.
   If cleanup fails, run cleanup.cmd to retry.
5. Reuse the same original package for another session. No credential renewal,
   storage-device round trip, or pairing code is required.

The package credential is persistent. Every launch creates new session tokens.
Only one session may be active at a time. Close the previous session before
starting another. A session expires after 12 hours; the package stays reusable.

Administrator rights are not requested by the launcher. Commands run with the
privileges of the account that starts it. System administration commands may
require additional rights. Organization policies may block PowerShell, CIM
queries, unsigned executables, or outbound tunnels; the relay does not bypass
those controls or automatically elevate itself.

Cleanup removes only identified relay processes and known package files.
Additional files are preserved. Unverified or removable locations are not
removed. This is not forensic erasure or revocation of copied credentials.
Anyone keeping a copy of the package credential can attempt a later connection.
Treat the prepared package as confidential. Operator read and provisioning keys
must never be included in it. Do not share or publish .relay-session.

Required files: start-relay.cmd, cleanup.cmd, start-relay.ps1,
relay-common.ps1, relay-cleaner.ps1, relay-agent-windows-amd64.exe,
and rendezvous.json (version 3, persistent package credential).
cloudflared.exe is downloaded from GitHub if absent (not version/hash pinned).

Optional port: start-relay.cmd -Port 50000
Explicit manual mode: start-relay.cmd -RevealToken
Manual mode reveals the URL and agent token. Do not share its output.
Nothing is copied automatically to the clipboard.

Helper tests: powershell -NoProfile -File .\tests.ps1
Local HTTP tests: powershell -NoProfile -File .\tests.ps1 -Http
