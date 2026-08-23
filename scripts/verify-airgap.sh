#!/usr/bin/env bash
# Optional air-gap check: run lading verify with no network namespace (Linux).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LADING="${LADING:-$ROOT/lading}"
if [[ ! -x "$LADING" ]]; then
  (cd "$ROOT" && go build -o "$LADING" ./cmd/lading/)
fi
ARTIFACT="$ROOT/testdata/inventory/bin/symver_ssl_elf"
# Build ephemeral bundle via go test helper is heavy; require prebuilt fixture or skip.
BUNDLE="${1:-}"
VEX="${2:-}"
if [[ -z "$BUNDLE" || -z "$VEX" ]]; then
  echo "usage: $0 <evidence-bundle-dir> <vex.json>" >&2
  echo "Run go test ./internal/evidence/ -run TestVerify_Success first to build a fixture manually." >&2
  exit 2
fi
if command -v unshare >/dev/null 2>&1; then
  exec unshare -n "$LADING" verify "$ARTIFACT" "$VEX" "$BUNDLE"
else
  echo "unshare not available; running verify without network namespace isolation" >&2
  exec "$LADING" verify "$ARTIFACT" "$VEX" "$BUNDLE"
fi
