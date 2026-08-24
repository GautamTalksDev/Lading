# CP-11 / S-14 ground truth (KT-2)

## Files

| File | Purpose |
|------|---------|
| `real-100.yaml` | **KT-2 evidence** — 100 statements sampled from real corpus pipeline verdicts (`seed: 20260824`). `human_label` is hand-filled. |
| `real_kt2_test.go` | Schema/stratification + KT-2 compare vs `human_label` (false `not_affected` count) |
| `statements.yaml` | **Unit-test fixtures only** (synthetic). Not KT-2 evidence. |
| `verify_test.go` | Re-runs `decide.Evaluate` on synthetic `statements.yaml` |
| `../LAB_NOTEBOOK.txt` | Plain-text lab notes |

## Build / sample (real KT-2 set)

```bash
bash scripts/corpus-scan.sh          # writes corpus/results/*/decisions.jsonl
python3 scripts/sample-real-groundtruth.py
# hand-label every human_label in real-100.yaml (optional human_notes per row)
go test ./corpus/groundtruth/ -count=1 -v
bash scripts/rederive-results.sh   # re-renders §KT-2 from labels
```

## Stratification (`real-100.yaml`, seed 20260824)

- ≥40 firmware-class artifacts
- ≥20 pipeline `not_affected`
- ≥20 refusals across multiple reason codes
- remainder random

## KT-2 rule

**Zero** pipeline `NOT_AFFECTED` verdicts that disagree with `human_label`. One false `not_affected` = FAIL.

Until all `human_label` fields are non-empty, `TestKT2_Real100` fails with **NOT EVALUABLE**.

## Synthetic fixtures

`statements.yaml` stays for engine regression (D01–D04). Its historical "KT-2 PASS" must not be cited as corpus kill-test evidence.

## License

Published under **CC-BY 4.0** as part of the corpus (`corpus/DATA-LICENSE.md`).
