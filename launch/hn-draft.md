> **HOLD — DO NOT PUBLISH.** See [DO-NOT-PUBLISH.md](DO-NOT-PUBLISH.md).

# Hacker News — DO NOT POST until steps 1–6 complete

**Target window:** Tuesday, 9:00–11:00 US Eastern  
**Rule:** Title = finding. Comment = reproduction. No star ask.

---

## Title (choose one)

1. **10,088 scanner CVEs on 41 shipped Linux artifacts — 0 with binary evidence at v1**
2. **We refused to guess on ten thousand container CVEs (corpus study, CC-BY)**
3. **Scanner CVE labels ≠ “vulnerable code not present” — 0% decided in open corpus**

Do **not** use “LADING” or “launch” in the title.

---

## URL

Link to gautamkhosla.com post 1 (not GitHub homepage).

---

## First comment (post immediately)

```
Author here. Method:

- 41 public artifacts (OCI, OpenWrt rootfs, static bins, SDK zips) — catalog in repo
- grype JSON in → sandbox unpack → ELF inventory → manifest + deterministic rules
- Kill test pre-registered: needed ≥30% decided; got 0% (all refused at PURL gate)
- Separate 100-case hand verification: 0 false "not affected"

Reproduce: github.com/gautamtalksdev/lading — scripts/corpus-download.sh, RESULTS.md

Dataset CC-BY. Not legal advice. Follow-up next week on inert VEX documents.
```

---

## Do not

- Ask for upvotes or stars
- Post twice
- Argue with “just use Trivy” threads — point to refusal semantics only
