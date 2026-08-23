# Decision engine conformance fixtures

Each subdirectory is one complete evaluation tuple for `internal/decide`
(`evidence-v1`).

```
<case-id>/
  case.yaml      # finding, manifest slice, expected verdict/rule/reason
  *.json         # inventory records
```

Run:

```bash
go test ./internal/decide/ -count=1
```

Minimum **8 fixtures per rule** (D01–D04), **≥40 total**, including near-misses
from SPEC-EVIDENCE.md §7.
