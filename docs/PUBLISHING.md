# Publishing the source on GitHub

Prepare a **source repository**, never a configured target package. This guide
does not publish anything or change repository visibility automatically.

## 1. Verify the source

Run the checks in [CONTRIBUTING.md](../CONTRIBUTING.md). Review the threat model
and permissions claims. Native Windows tests and standard-user behavior must not
be presented as verified merely because cross-compilation or mocks passed.

Run `python3 scripts/audit-public-source.py --history` in the private checkout.
It is expected to flag Git author metadata and may flag old files. Do not publish
that history merely because the current working tree passes.

The project uses the permissive MIT License with a generic contributor notice.
Verify that this remains the intended licensing policy before publishing. See
GitHub's [licensing guidance](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository).

## 2. Create a clean source snapshot

From the repository root:

```sh
python3 scripts/export-source.py
```

The output is `release/source/mcp-windows-remote-shell/`. The exporter refuses to
replace an existing output and includes source/docs/tests only. It excludes:

- `.git` and all existing commit history;
- `rendezvous.json`, `operator.json`, setup-generated credential files;
- local Worker configuration, `.env`/`.dev.vars`, and secret input files;
- dependencies, compiled binaries, build output, caches, runtime state, and logs.

Review the output itself. An allowlist is not a substitute for checking source
contents for accidentally hardcoded credentials or personal data. Do not copy
files back from a prepared target package into the public snapshot.

```sh
python3 scripts/audit-public-source.py \
  --root release/source/mcp-windows-remote-shell
```

## 3. Start publication from the snapshot

Earlier development history can contain personal author metadata and deployment
context even after current files have been cleaned. The source snapshot avoids
publishing that history; the original local history is left intact.

```sh
cd release/source/mcp-windows-remote-shell
git init -b main
git config --local user.useConfigOnly true
git config --local user.name "PUBLIC_PSEUDONYM"
git config --local user.email "YOUR_GITHUB_NOREPLY_ADDRESS"
git add .
git diff --cached --check
git diff --cached
# Commit only after reviewing the staged source.
git commit -m "Initial public source release"
```

Create your own GitHub repository, attach its remote, and push when you are ready.
Do not use the original checkout's history for publication without a separate
history audit. Do not add a shared deployment URL, cloud account ID, real hostname,
private key, token, or operator-specific filesystem path to the public repository.

If personal anonymity matters, use a dedicated pseudonymous GitHub account with
a GitHub-provided `noreply` commit address. Do not reuse a personal username,
avatar, biography, website, organization membership, GPG/SSH signing identity,
or commit email. Review the account's public events and profile before pushing.
The account provider can still receive private signup, network, and access data;
this source-cleaning workflow cannot make platform use anonymous to GitHub.

## 4. Repository settings and releases

Enable private vulnerability reporting before advertising a security-reporting
channel. Keep pull-request CI free of production credentials and do not expose
secrets to untrusted fork code. Do not promise production readiness.

For a binary release, build from a reviewed revision and publish only unconfigured
binaries/scripts with checksums and the chosen license notices. Never include
`rendezvous.json`, operator credentials, or `.relay-session`. Review redistribution
terms before bundling third-party executables such as cloudflared.

A public clone deploys its own Worker and creates its own credentials using the
README. No public user should depend on a maintainer's private rendezvous service.
