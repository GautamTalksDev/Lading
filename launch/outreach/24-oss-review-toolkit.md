# 24 — OSS Review Toolkit

**To:** ORT / OSS Review Toolkit maintainers  
**Sent:** _pending_

---

Hi ORT team,

ORT’s advisor pipeline already separates **detection** from **policy**. LADING is a deterministic “can we substantiate not_affected from symbols?” step after grype/Trivy.

Proposal in `launch/distribution/issues/ort-advisor.md`: optional advisor reading LADING `scan-summary.json` + bundle path, surfacing `UNDER_INVESTIGATION` as policy violation instead of silent pass.

Would you accept a community advisor module external to core first?

— Gautam
