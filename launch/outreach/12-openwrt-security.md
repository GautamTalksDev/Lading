# 12 — OpenWrt Security

**To:** security@openwrt.org  
**Sent:** _pending_  
**Vendor notice:** LOG.md row 3

---

Hi OpenWrt security team,

We scanned **four OpenWrt rootfs artifacts** (23.05 x86-64 tarball, snapshot tarball, plus OCI `openwrt/rootfs` tags where tarballs 404’d). Grype reported **8–22 CVEs** per rootfs; **~300 binaries** inventoried per tar; **0%** decided with symbol evidence at v1 (PURL/manifest gate).

Post cites OpenWrt as **positive example of smaller scanner counts vs. Node images** — not as a vulnerable project.

Heads-up 14 days before publication. Factual corrections welcome.

— Gautam
