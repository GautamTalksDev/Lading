# Related work — positioning LADING (CP-11)

This note positions the LADING kill-test corpus result against the two closest
peer papers. It is written for the workshop draft related-work section; claims
are conservative by design.

**Corpus anchor:** CP-11 — **55** scanned real artifacts (including **12**
firmware-class), **15,641** grype CVE rows, refusal-first pipeline with
stage-attributed termination (`REFUSAL-STAGES.md`, `RESULTS.md`).

---

## Churakova, Ekstedt, and Schmid — “Vexed by VEX Tools” (arXiv:2503.14388)

Churakova et al. measure **cross-tool consistency** among seven
VEX-generation tools (Trivy, Grype, DepScan, Docker Scout, OSV-Scanner, Vexy,
Snyk) on **48 Docker Hub container images** (random, “high-vuln,” and
“non-vuln” subsets). They compare reported vulnerability **sets** using
Jaccard and Tversky overlap on CVE/GHSA identifiers, run input-type controls
(direct image scan vs native SBOM vs Scout-produced SBOM), and attribute most
divergence to **differences in vulnerability-database coverage** (Pearson
correlation **0.88** between DB overlap and report overlap). They explicitly
do **not** score false `not_affected` claims, do **not** inspect shipped
binaries or symbol tables, and their cross-tool design **cannot isolate a
same-tool, different-ingestion-path split** — e.g. Syft CycloneDX vs Syft SPDX
through one consumer — which is the design of our separate interoperability
measurement (FINDING-001).

---

## Rasheed et al. — “Hidden Dependencies and Component Variants in SBOM-Based
Software Composition Analysis” (arXiv:2604.21278)

Rasheed et al. study **two mismatch patterns** in SBOM-based SCA on **four
hand-built Java/Maven fixtures** (Study I: hidden code-level dependencies and
VEX suppression scope; Study II: cloned Log4j component variants with and
without CycloneDX/SPDX lineage metadata). They score whether Grype, Trivy,
CVE-Bin-Tool, and OSV-Scanner **detect** a seeded CVE and whether VEX
suppression behaves as path scope requires. On VEX scope (Study I), **Grype and
CVE-Bin-Tool apply no suppression** (inert relative to the fixture VEX) while
**Trivy suppresses all four cases** including reachable ones (overbroad) — we
**cite Rasheed et al. for that split**; we do **not** claim to have discovered
it. They do **not** measure refusal-stage termination on a multi-class shipped
artifact corpus, do **not** run a binary-grounded clearance pipeline, and do
**not** attribute where a symbol-evidence instrument stops before reaching
symbols.

---

## Prior art on SBOM identity and naming (via Churakova §5–§6)

Churakova’s discussion cites earlier work showing the **identity/naming problem
is already known**; our contribution is **where it terminates a
binary-grounded pipeline**, not that the problem exists:

- **Cofano et al.** — in the Python ecosystem, low SBOM precision can cause
  roughly **80%** of vulnerabilities to be lost relative to ground truth when
  SBOM accuracy is poor.
- **Benedetti et al.** — with current SBOM-generator precision, only about
  **20%** of vulnerabilities may be identifiable from generated SBOMs alone.
- **Dann et al.** — on Java-oriented scanner evaluation, only about **34%** of
  findings were true positives under their test suite.

These figures motivate identity resolution as a bottleneck; they do **not**
substitute for stage-attributed measurement on firmware, containers, and static
binaries together.

---

## Our delta (one paragraph)

LADING’s CP-11 result is **stage-attributed failure measurement** of a
**refusal-first, binary-grounded** VEX clearance pipeline on **55 real shipped
artifacts** (OCI apps/bases, OpenWrt rootfs, static release binaries, RTOS SDK
archives, and **12 firmware-class** rows) and **15,641** scanner-reported CVE
rows: **91.9%** of pipeline decisions terminate at **identity resolution**, a
further **7.7%** at **manifest lookup**, and **zero** at symbol-table stages
(S3/S5), so the pre-registered symbol-evidence kill test (KT-1) is **NOT
EVALUABLE** rather than a measured pass/fail on clearance rate. Where the
pipeline does decide after the FINDING-002 guard (**5** rows, **0.032%**, all
`AFFECTED`), outputs carry re-derivable evidence bundles under rules `evidence-v1`.
KT-2 on **100** labeled real statements is **FAIL** (**20** false `not_affected`;
[FINDING-002.md](FINDING-002.md)). **`audit-vex`** (separate from the
corpus kill test) grades CycloneDX PURL match quality for public VEX fixtures;
it operationalizes checks aligned with Rasheed’s VEX-scope findings but is **not**
presented as novel discovery of Grype-inert / Trivy-overbroad behavior.

---

## What we are **not** claiming

Reviewers should not read the following into this work:

1. **First report that scanners or VEX tools disagree.** Churakova et al. and
   O’Donoghue et al. already establish low cross-tool overlap; we add
   **in-pipeline stage attribution** on a heterogeneous shipped-artifact
   corpus, not another Jaccard table on containers alone.

2. **Discovery of the Grype-inert / Trivy-overbroad VEX split.** Rasheed et
   al. (Study I) document it on Java fixtures; we cite them and optionally
   reproduce with `audit-vex`, without claiming priority.

3. **Discovery that SBOM naming loses vulnerabilities.** Cofano, Benedetti,
   and Dann (among others) already quantify SBOM/identity loss; we locate the
   **termination point** (identity → manifest, not symbols) for a pipeline that
   *would* require binary proof if it got that far.

4. **Corpus-scale proof that symbol evidence is insufficient.** With **zero**
   symbol-stage refusals, we did not run symbol rules at scale; the honest claim
   is that **identity resolution prevents the instrument from reaching that
   question** for 99.6% of findings.

5. **A positive clearance rate or KT-1 pass/fail.** **0.2557%** decided is an
   observed pipeline output, not an answer to the pre-registered ≥30% bar under
   current evaluability rules (`RESULTS.md` §6, README §11).

6. **General superiority of grype, trivy, or syft.** CP-11 scans through
   grype; FINDING-001 (Syft→Trivy SBOM interoperability) is orthogonal
   supply-chain evidence filed separately — not a claim that one vendor’s stack
   is “correct.”

7. **KT-2 soundness beyond OpenSSL D02.** KT-2 is **FAIL** (**20/20** false
   `not_affected` in `real-100.yaml`, labels **100/100**) on OpenSSL
   internal-symbol D02 clearances only. That does not establish unsoundness for
   D01, D04, or other components; D01 had no natural corpus instance (see
   `RESULTS.md` §5).

Conservative positioning: **known identity problems, new termination map on real
shipped artifacts; known VEX-scope asymmetry, cited not rediscovered; KT-2 FAIL
on a named OpenSSL D02 mechanism; binary grounding not exercised at corpus scale
because refusal happens upstream.**

---

## Suggested citations (BibTeX keys TBD)

| Work | Role in our narrative |
|------|------------------------|
| Churakova et al., arXiv:2503.14388 | Closest cross-tool VEX consistency study; contrast Jaccard design |
| Rasheed et al., arXiv:2604.21278 | VEX scope + component variants; cite Grype/Trivy asymmetry |
| Cofano et al. (via Churakova) | SBOM precision → vuln loss (Python) |
| Benedetti et al. (via Churakova) | ~20% vulns identifiable at SBOM-generator precision |
| Dann et al. (via Churakova) | ~34% TP rate on Java scanner suite |
