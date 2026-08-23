# Contributing to LADING

Thank you for contributing. LADING emits claims that people will rely on in
regulatory filings. Contributions must preserve determinism, unit-testability,
and evidence integrity.

## Developer Certificate of Origin (DCO)

**All commits must be signed off** with the [Developer Certificate of Origin](https://developercertificate.org/).

Use `git commit -s` (or `--signoff`). Unsigned commits will be rejected.

```
Signed-off-by: Your Name <your.email@example.com>
```

By signing off, you certify that you have the right to submit the work under
the project's Apache 2.0 license (see `LICENSE`) and that the DCO text applies.

## Principles (non-negotiable)

- No LLM calls, heuristic scores, probabilities, or network requests the user
  did not explicitly request.
- Never emit `not_affected` without a re-derivable evidence bundle.
- When in doubt, the verdict is `under_investigation`.
- Do not add dependencies absent from `go.mod` without maintainer approval.
- Prefer the Go standard library (`debug/elf`, `debug/pe`, `debug/macho`).

## Workflow

1. Fork and branch from `main`.
2. Keep changes focused; include tests for decision and evidence logic.
3. Run `go test ./...`, `go vet ./...`, and `golangci-lint run`.
4. Open a pull request. Commits must include `Signed-off-by`.

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
