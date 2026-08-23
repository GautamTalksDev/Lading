# Consulting offer (CP-14 step 2)

Use **after** discovery calls with all three inbound companies. Offer this
**before** any paid product. Rate: **$200–400/hr** (pick a fixed rate per
engagement; do not discount the hourly below $200).

---

## Email / proposal text (adapt, do not oversell)

Subject: LADING evidence review — scoped consulting

Hi [Name],

Thanks for describing [verbatim reference to their audit/questionnaire/deadline].

I can run LADING across [product line / artifact set they named] and deliver:

1. **Evidence pack** — reproducible bundles per artifact (`lading verify`-compatible), with manifest provenance where coverage exists
2. **Honest gap list** — CVEs that remain `under_investigation` or `purl-insufficient`, and why (no prove-a-negative)
3. **Short memo** — what your current process covers vs. what a notified body or customer questionnaire is actually asking for

This is fixed-scope consulting, not a product subscription. You keep all outputs;
the free CLI and public Manifest stay unchanged.

**Rate:** $[200–400]/hr, estimated [N] hours, cap at [H] hours unless we agree in writing.

**Prerequisite before invoice:** engagement under [registered entity name] with
standard liability cap ([ENTITY-CHECKLIST.md](ENTITY-CHECKLIST.md)).

If useful, propose [dates] for a kickoff.

[Your name]

---

## Scope boundaries (state explicitly)

Included:

- Run existing `lading` CLI on their binaries/images (air-gapped ok)
- Document gaps against their stated regulation/questionnaire
- Hand off evidence bundles and VEX outputs the tool already produces

Excluded (until CP-14 step 3 + two matching paid asks):

- Building new paid-only product features
- Private hosted Manifest SaaS
- Long-term evidence retention infrastructure
- Custom CI product integration (beyond documenting GitHub Action they can self-host)

---

## Paid research rule

Two completed paid engagements must request the **same capability** before
writing LADING Evidence product code. Log requests in [ENGAGEMENT-LOG.md](ENGAGEMENT-LOG.md).
