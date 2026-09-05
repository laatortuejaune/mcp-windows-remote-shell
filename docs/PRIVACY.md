# Privacy and publication review

The public repository must contain only reusable source, tests, and generic
documentation. It must not contain a configured target package, deployment
configuration, credentials, runtime state, user data, personal paths, hostnames,
account identifiers, or author details unintentionally inherited from private
work.

## Files that are always private

- `operator.json`, `worker-secrets.json`, and generated `mcp-config.json`.
- Every configured `rendezvous.json` target package.
- `.env*`, `.dev.vars*`, `secrets*.json`, and `wrangler.local.jsonc`.
- `.relay-session`, logs, downloaded/compiled executables, dependency directories,
  build output, caches, and prepared package exports.
- Any terminal transcript, screenshot, test output, or issue attachment containing
  a target hostname, tunnel URL, command output, username, or filesystem path.

The checked-in `rendezvous.example.json` and `operator.example.json` contain
placeholders only. They are not valid credentials.

## Review procedure

1. Run all checks in [CONTRIBUTING.md](../CONTRIBUTING.md).
2. Run `python3 scripts/audit-public-source.py` in the working repository.
3. Run `python3 scripts/export-source.py` to create a source-only snapshot.
4. Run `python3 scripts/audit-public-source.py --root release/source/mcp-windows-remote-shell`
   against the exact snapshot that will be published.
5. Manually review every file in that snapshot, its staged diff, and repository
   settings. Automated pattern matching cannot prove that prose contains no
   identifying anecdotes or business context.
6. Initialize fresh Git history inside the reviewed snapshot. Do not copy the
   private checkout's `.git` directory or reuse its commits.

The audit checks every selected file and filename, validates text encoding and
Windows line endings, detects common credential formats, absolute user paths,
email addresses, live-looking Worker/tunnel URLs, and legacy non-English names.
It deliberately reports categories and file locations without echoing matched
values.

## Git metadata

Every Git commit normally contains an author name and email. Even a pseudonymous
identity can become identifying when reused across repositories. Before the first
public commit, configure the exact public author identity you intend to expose.
GitHub's privacy settings can provide a `noreply` address, but choosing and
configuring that identity remains the publisher's decision.

Existing private history can also retain deleted credentials, paths, machine
names, deployment URLs, or contextual prose. Deleting them from the latest tree
does not remove them from old commits. The publication workflow therefore starts
from a clean source snapshot rather than attempting to sanitize history in place.

## Limits

No automated audit can promise mathematical anonymity. Source code can expose
writing style, architecture choices, timestamps in external services, dependency
choices, or later GitHub activity. The workflow removes direct identifiers and
private deployment material from the source artifact. The publisher must still
choose an account identity, license, repository visibility, and public activity
policy deliberately.

Publishing from an existing personal GitHub account can identify its owner even
when every source file is clean. A username, avatar, profile, organizations,
commit signing key, reused pseudonym, public email, issue activity, and social
links can connect the project to a person. GitHub also receives non-public account
and network metadata. Repository sanitation protects the published artifact; it
does not provide anonymity from the hosting platform or correlation across
accounts.
