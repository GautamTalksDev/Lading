# Checkpoints

Status ledger for LADING checkpoints. Update when a Definition of Done is met
with recorded evidence — do not mark closed on CI green alone when the DoD
requires a hand step.

---

## CP-0 — Compliance evidence constraints

**Status:** closed (workspace rule + deterministic core).

---

## CP-1 — Cross-platform CI and signed releases

**Status: CP-1 closed.**

| DoD item | Status |
|----------|--------|
| CI matrix ubuntu / macOS / Windows × Go 1.23 | met (`.github/workflows/ci.yml`) |
| GoReleaser static binaries + SHA256SUMS | met (`.goreleaser.yaml`, `dist/`) |
| Cosign keyless + SLSA provenance on tag | met (`.github/workflows/release.yml`) |
| **Windows zip extracted on real Windows; `lading --help` prints usage** | **met — windows binary verified 2026-08-24** |

### Windows smoke (closes the last open CP-1 item)

| Field | Value |
|-------|--------|
| Artifact | `dist/lading_0.0.1-next_windows_amd64.zip` (zip sha256 `5768082b0d91962065e5181c73c51387974fde4d595321305b11ba2f69c99e58`) |
| Host | real Windows NT 10.0.26200.0, AMD64, computer `GAUTAMKH` (not WSL; PE run via Windows PowerShell) |
| Extract path | `C:\Users\Public\lading-cp1-verify\extracted\` |
| Binary | `lading.exe` (5 610 496 bytes; sha256 `3B77F5F00B44487D95A7FAE167C9DF8B9B28359AC226BC6D0E709F8A3383E317`) |
| Command | `.\lading.exe --help` |
| Result | printed Usage / Available Commands without error; process exit code **0** |
| Verified_at | 2026-08-24T19:35:00Z (approx.) |
| Verified_by | hand (Windows host PowerShell) |

Open item since CP-1 was written: Windows `--help` on a real machine. **Closed.**

---

## Later checkpoints

See `docs/OPERATIONS.md` for the schedule (CP-2 onward). Do not edit kill-test
thresholds when recording checkpoint status.
