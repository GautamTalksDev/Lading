# 10 — Zephyr Security Committee

**To:** Zephyr security mailing list / SC chair  
**Sent:** _pending_

---

Hi Zephyr SC,

We scanned **zephyr-sdk-0.16.5** (public SDK tarball) as part of a 41-artifact Linux corpus. Scanner CVE count was modest; decided-with-evidence count was **zero** at v1 — host tools vs. manifest coverage mismatch, not a Zephyr CVE claim.

Zephyr’s own security process is source-centric; our angle is **what compliance teams do with SDK zips customers actually install**. Open to sharing aggregate numbers only (no alarmist framing).

If Zephyr ships machine-readable VEX alongside SDK releases someday, `audit-vex` is built to catch inert statements before they reach customers.

— Gautam
