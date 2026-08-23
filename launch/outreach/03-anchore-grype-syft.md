# 03 — Anchore Grype / Syft

**To:** Anchore OSS maintainers (grype / syft GitHub)  
**Sent:** _pending_  
**Vendor notice:** also logged in `vendor-notifications/LOG.md` for post 2

---

Hi Anchore team,

I used grype as the **only** CVE intake for a 41-artifact corpus (OCI + OpenWrt rootfs + static binaries). Findings JSON fed a downstream engine that requires `TypeNormalized` PURL match before symbol rules run.

Result: **10,088 CVE rows, 100% refused at `purl-insufficient`** against a 25-component manifest — not a grype accuracy claim, a **composition** claim.

Separately, `lading audit-vex` models an **inert VEX** failure when statement products match SBOM at `name_version_only` only (`testdata/auditvex/grype_inert/`). I’m describing this shape in a follow-up post after private notice period.

Questions I’d value your read on:

- Is there a recommended PURL canonicalization hook between syft SBOM and third-party OpenVEX authors?
- Would you accept a repro repo link in the post footnote?

Repro corpus row + grype JSON archived under CC-BY.

— Gautam
