# 16 — NCC Group embedded practice

**To:** NCC hardware/firmware assessment lead (LinkedIn or known contact)  
**Sent:** _pending_

---

Hi [Name],

NCC’s firmware assessments already treat scanner output as untrusted until mapped to binaries. We automated the **refusal half** — when mapping fails, emit `under_investigation` + evidence bundle skeleton, never the three forbidden VEX justifications.

Corpus: 41 artifacts, 10k CVE labels, 0% decided at v1. Useful negative result for client conversations.

If ORT or Dependency-Track integration interests your team, I filed a tracking issue draft in `launch/distribution/` — happy to co-author.

— Gautam
