#!/usr/bin/env bash
# Profile every ARTIFACTS.yaml entry: binary counts, stripped %, static %,
# dynsym-only. Emits results/binary-profile.csv and PROFILE.md.
# Measurement only — does not change scan/decision logic.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

mkdir -p "${ROOT}/results" "${ROOT}/.lading/profile-rootfs"

echo "[profile-corpus] building helper…" >&2
go build -o "${ROOT}/.lading/profile-corpus" ./scripts/profile-corpus

echo "[profile-corpus] running across ARTIFACTS.yaml…" >&2
"${ROOT}/.lading/profile-corpus" "${ROOT}"
echo "[profile-corpus] done" >&2
