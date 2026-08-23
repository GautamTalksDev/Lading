# CP-11 ground truth (KT-2)

100 hand-verified `(finding, inventory, manifest slice) → verdict` statements.

## Files

| File | Purpose |
|------|---------|
| `statements.yaml` | Committed dataset (gt-001..gt-100) |
| `verify_test.go` | Re-runs `decide.Evaluate` against every statement; fails on any mismatch |
| `../LAB_NOTEBOOK.txt` | Plain-text lab notes (corpus work) |

## Build / verify

```bash
go build -o bin/groundtruth-probe ./scripts/groundtruth-probe
python3 scripts/corpus-groundtruth-build.py   # regenerates statements.yaml from specs + engine probe
go test ./corpus/groundtruth/ -count=1
```

## Stratification (cp11-gt-1)

- **40** statements from `testdata/decide/` fixtures (gt-001..gt-040)
- **60** statements from `testdata/inventory/bin/` ELFs/PE/Mach-O (gt-041..gt-100)
- Weighted toward `NOT_AFFECTED` (64/100 in v1)
- Each inventory statement includes `verification.readelf_excerpt` where `readelf` applies

## KT-2 rule

**Zero** engine `NOT_AFFECTED` verdicts that disagree with ground truth. One false `not_affected` = FAIL. The verify test treats engine-vs-ground-truth `NOT_AFFECTED` mismatches as KT-2 violations.

## License

Published under **CC-BY 4.0** as part of the CP-11 corpus (`corpus/DATA-LICENSE.md`). Cite: *Gautam Khosla / LADING CP-11 ground truth (2026)*.
