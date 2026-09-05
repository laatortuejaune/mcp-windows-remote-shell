#!/bin/zsh
set -euo pipefail
relay_root="${0:A:h}"
cd "$relay_root/mcp-server"
exec node dist/prepare.js "$@"
