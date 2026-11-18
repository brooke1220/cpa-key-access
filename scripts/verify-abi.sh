#!/usr/bin/env bash
# Loads a built plugin library through the C ABI (dlopen) and drives it with test/abi/harness.c.
# Usage: scripts/verify-abi.sh <library>
set -euo pipefail

LIB="$(cd "$(dirname "${1:?usage: scripts/verify-abi.sh <library>}")" && pwd)/$(basename "$1")"
cd "$(dirname "$0")/.."

sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
SCOPE="$(printf 'cli-proxy-api:caller-scope:v1\000%s' abi-key | sha | cut -d' ' -f1)"
YAML="$(printf 'version: 1\npolicies:\n  - caller_scope: %s\n    deny_models: ["gpt-*"]\n    allow_profiles: ["claude:*"]\n' "$SCOPE")"
B64="$(printf '%s' "$YAML" | base64 | tr -d '\n')"
cc -o "$TMP/harness" test/abi/harness.c -ldl
"$TMP/harness" "$LIB" "$SCOPE" "$B64"
