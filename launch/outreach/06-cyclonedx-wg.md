# 06 — CycloneDX working group

**To:** CycloneDX core maintainers / TC  
**Sent:** _pending_

---

Hi CycloneDX folks,

`lading audit-vex` consumes CycloneDX SBOM JSON as the ground truth for “which components exist” when auditing OpenVEX statements. We flag **inert** and **overbroad** matches based on graded PURL equivalence — no boolean “matched yes/no.”

Blog post #2 is about silent VEX failure; I cite CycloneDX component graphs explicitly (root vs. nested). Draft available for factual review on how we represent `is_root` from your BOM structure.

Would a minimal “VEX audit profile” example belong in CycloneDX guidance, or stay out-of-spec in community docs?

— Gautam
