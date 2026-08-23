# 01 — EMBA maintainers

**To:** EMBA core maintainers (GitHub discussion or security@ contact on project page)  
**Sent:** _pending_

---

Hi — I run firmware/static analysis pipelines on OpenWrt rootfs and container exports, and EMBA’s unpack → scan flow is the closest thing in the wild to how we think about “what’s actually in the blob.”

I finished a reproducible corpus study (41 shipped Linux artifacts, grype in → binary inventory → evidence rules) and got **0% decided coverage at v1** — almost entirely PURL identity, not missing CVE data. Posted write-up leads with the numbers; tool is below the fold.

Two things you might care about:

1. **Stripped/static dominance** in our inventory stats matches what EMBA users see daily — any clearance claim without symtab visibility should fail closed.
2. We open-sourced **`lading audit-vex`**, which flags inert VEX statements (Grype-class PURL mismatch). Happy to share fixtures if useful for EMBA’s VEX export checks.

Corpus + ground truth: CC-BY in the repo (`RESULTS.md`, `corpus/`). No ask beyond: if the method looks wrong for firmware tarballs, tell me where.

— Gautam
