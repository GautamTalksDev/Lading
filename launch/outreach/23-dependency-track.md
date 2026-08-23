# 23 — Dependency-Track

**To:** Dependency-Track maintainers (GitHub discussion)  
**Sent:** _pending_

---

Hi DT team,

Dependency-Track consumes SBOM + vulnerability intel. LADING consumes **scanner findings + binary inventory + curated manifest** and outputs VEX-shaped docs or refusal.

Integration idea (issue draft in `launch/distribution/issues/dependency-track.md`): attach LADING evidence bundle hash to DT finding as `analysis` comment — refusal vs. cleared with bundle URL.

Not asking for merge — asking if the extension point still prefers webhooks vs. REST bulk upload in 4.x.

— Gautam
