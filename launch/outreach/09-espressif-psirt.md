# 09 — Espressif Product Security

**To:** security@espressif.com  
**Sent:** _pending_

---

Hi Espressif PSIRT,

Our CP-11 corpus includes **esp-idf-v5.2.2.zip** as an RTOS/SDK class artifact (public GitHub release). Grype reported CVEs on host-side tools in the bundle; **zero** mapped to manifest v1 entries at PURL quality sufficient for symbol rules.

I'm **not** reporting a new ESP-IDF vulnerability. I'm measuring how scanner noise presents on SDK drops customers actually download.

If you publish VEX or SBOM for ESP-IDF releases, I'd run `lading audit-vex` privately before any public citation — 14-day notice policy.

— Gautam
