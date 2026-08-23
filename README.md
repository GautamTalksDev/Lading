# LADING

Deterministic compliance evidence for binary vulnerability triage.

LADING builds re-derivable evidence bundles and machine-readable VEX-style
outputs from artifact inventory and a versioned manifest. Every output is a
claim someone may rely on in a regulatory filing. See [DISCLAIMER.md](DISCLAIMER.md).

## Kill Tests

  KT-1 (coverage): If across 5 real shipped artifacts fewer than 30% of
       scanner-reported CVEs resolve to a decidable not_affected verdict
       with a re-derivable evidence bundle, this tool adds too little over
       manual triage and the project stops.
  KT-2 (soundness): If ANY single not_affected statement in a 100-statement
       hand-verified ground truth set is wrong, the decision engine is
       unsound. One false negative is a total failure, not a percentage.
  KT-3 (commercial, month 8): If no company has contacted us unprompted
       asking for evidence storage, CI integration or private manifest
       entries within 4 months of launch, there is no business here.

## What LADING Refuses To Do

LADING will **never** emit the following VEX status justifications. They are
prove-a-negative claims that cannot be established from deterministic binary
inventory and manifest evidence alone:

1. `vulnerable_code_not_in_execute_path`
2. `vulnerable_code_cannot_be_controlled_by_adversary`
3. `inline_mitigations_already_exist`

When evidence is insufficient for a decidable `not_affected` with a
re-derivable evidence bundle, the answer is `under_investigation`.

## Status

Foundations only: repository skeleton, licensing, and contribution guardrails.
No decision engine or emitters yet.

## Layout

```
cmd/lading/           CLI entrypoint (cobra)
internal/inventory/   binary symbol/string inventory
internal/manifest/    Lading Manifest loader + schema
internal/decide/      deterministic decision engine
internal/vexout/      OpenVEX / CycloneDX / CSAF emitters
internal/evidence/    evidence bundle construction + verification
internal/unpack/      sandboxed artifact unpacking (Linux only)
internal/purl/        PURL canonicalization
manifest/             versioned Lading Manifest data
testdata/             fixtures, including real small ELF binaries
```

## Build

Requires Go 1.23+.

```bash
go build ./...
go vet ./...
go test ./...
```

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Contributing

DCO sign-off is required on every commit (`git commit -s`). See
[CONTRIBUTING.md](CONTRIBUTING.md).
