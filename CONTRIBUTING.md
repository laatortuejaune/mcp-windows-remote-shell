# Contributing

Read [SECURITY.md](SECURITY.md) first. Keep changes small, use synthetic test
credentials, and describe the trigger, behavior change, and validation results.
Do not test against an unrelated live target or Worker.

Use **pnpm only** for Node/TypeScript. Dependency build scripts must not be enabled
implicitly. The Go agent stays standard-library-only unless a dependency is
explicitly justified. All user-facing text and documentation are English.

Windows `.ps1`/`.cmd` scripts must remain ASCII + CRLF. Avoid changing raw Windows
command-line handling or descendant supervision without native regression coverage.

## Local checks

```sh
cd agent
./build.sh
go test ./...
go vet ./...
GOOS=windows GOARCH=amd64 go vet ./...
gofmt -l .
cd ../mcp-server
pnpm install --frozen-lockfile
pnpm run build
pnpm run typecheck
pnpm test
cd ../rendezvous
pnpm install --frozen-lockfile
pnpm run typecheck
pnpm test
cd ..
pwsh -NoProfile -File target-windows/tests.ps1 -Http
node --test scripts/test-setup.mjs
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/audit-public-source.py
git diff --check
```

Miniflare and HTTP tests use local listeners. Sandboxed execution may need
permission to bind loopback ports or inspect test-process identities. Do not
confuse these environment restrictions with a reason to weaken production checks.

Before submitting changes, remove real deployment configuration, credentials,
operator state, logs, machine names, and personal paths. Follow
[the source publication guide](docs/PUBLISHING.md). Do not attach assistant
attribution trailers automatically to commits.
