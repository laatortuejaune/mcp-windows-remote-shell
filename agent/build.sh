#!/usr/bin/env sh
# Build the relay-agent for the local host and cross-compile for Windows.
set -eu
cd "$(dirname "$0")"
OUT=dist
mkdir -p "$OUT"
LDFLAGS="-s -w"   # strip symbols/DWARF for a smaller binary
echo "native ($(go env GOOS)/$(go env GOARCH)) ..."
go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/relay-agent" .
echo "windows/amd64 ..."
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/relay-agent-windows-amd64.exe" .
echo "done:"
ls -la "$OUT"
