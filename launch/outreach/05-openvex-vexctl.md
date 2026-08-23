# 05 — OpenVEX / vexctl

**To:** OpenVEX maintainers / OSSF VEX Technical Advisory Group  
**Sent:** _pending_

---

Hi,

OpenVEX is the interchange format we emit after a deterministic decision (`lading vex emit`). Before that, we **`audit-vex`** third-party documents against CycloneDX SBOMs — flagging statements that never bind (inert) or bind only to subcomponents (overbroad).

I’m **not** proposing spec changes. I want practitioners to run the auditor in CI before filing VEX.

Would the VEX TG be open to a short appendix example showing match-quality grading on a minimal OpenVEX doc + SBOM pair? Our fixtures are MIT/Apache licensed in-repo.

Paper + blog post cite OpenVEX `@context` 0.2.0 only.

— Gautam
