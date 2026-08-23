# Paid consulting & product build log

Track paid engagements and the **two matching requests** rule before writing
LADING Evidence product code.

---

## Consulting engagements

| # | Company | SOW date | Hours | Rate | Paid (date) | Primary ask | Evidence pack delivered |
|---|---------|----------|-------|------|-------------|-------------|-------------------------|
| 1 | | | | $ | | | [ ] |
| 2 | | | | $ | | | [ ] |
| 3 | | | | $ | | | [ ] |

**CP-14 DoD:** ≥1 row with **Paid** filled before any paid **feature** code lands in repo.

---

## Matching request tracker (step 3 gate)

LADING Evidence code only after **two paid engagements** requested the **same**
capability:

| Capability bucket | Engagement #1 (company, date) | Engagement #2 (company, date) | Build approved? |
|-------------------|--------------------------------|--------------------------------|-----------------|
| Evidence storage / retention | | | [ ] |
| CI integration (org audit log) | | | [ ] |
| Private Manifest entries | | | [ ] |
| CRA technical file export | | | [ ] |

**Build approved** = both cells in a row filled + written customer acknowledgment
on [PAID-TIER-ONE-PAGER.md](PAID-TIER-ONE-PAGER.md).

---

## Paid tier customer acknowledgment

| Company | One-pager sent | Customer agreed (date) | Monthly fee | Subscription start |
|---------|----------------|------------------------|-------------|-------------------|
| | | | $ | |

**CP-14 DoD:** at least one row with **Customer agreed** before subscription billing.

---

## Product code gate (do not implement early)

If tempted to add paid-only code before the rows above are complete, add the idea
to [IDEAS.md](../../IDEAS.md) with prefix **CP-14 gated** — do not merge.

Allowed before two matching paid asks:

- Consulting deliverables using **existing** CLI only
- Documentation, evidence packs, gap memos

Forbidden before gates:

- New repo or module named `evidence`, `saas`, `cloud`, `enterprise` that gates CP-12 features
- License checks that disable `lading verify`, scan, or public manifest for non-payers
