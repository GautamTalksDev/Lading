# 04 — Aqua Trivy

**To:** Trivy maintainers  
**Sent:** _pending_  
**Vendor notice:** logged for post 2 (overbroad failure mode)

---

Hi Trivy team,

I built a deterministic VEX auditor (`lading audit-vex`) that grades whether VEX product IDs attach to CycloneDX SBOM components at useful match quality.

One modeled failure — **overbroad** — is an `exact` PURL hit on a **subcomponent** while the statement reads like product-level clearance (fixture: `testdata/auditvex/trivy_overbroad/`). I’ll write about the failure mode, not Trivy specifically, after a 14-day vendor heads-up.

You’ve thought about PURL matching more than most. If there’s existing guidance on “root product vs. dependency scope” in VEX emitters, I’ll link it instead of reinventing.

Happy to send the draft paragraph for factual check.

— Gautam
