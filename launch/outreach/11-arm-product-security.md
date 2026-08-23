# 11 — ARM Product Security

**To:** ARM security / GNU toolchain product team contact  
**Sent:** _pending_

---

Hi,

Corpus artifact: **arm-gnu-toolchain-13.2** (public ARM download). Grype noise on host binaries; **0** evidence-decided CVEs against our 25-component manifest at v1.

Customers use your toolchain to **build** firmware; compliance teams still run scanners on the SDK tarball itself. Our post is about that category error — not ARM CVE claims.

If ARM publishes SBOM/VEX for toolchain releases, I’ll run `audit-vex` before citing anything publicly.

— Gautam
