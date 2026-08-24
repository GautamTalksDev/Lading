# DO NOT PUBLISH

KT-1 is NOT EVALUABLE, not FAIL. The corpus run decided 0/10,088 CVEs because
grype emits distro PURLs (pkg:deb/..., pkg:apk/...) and the Manifest carries
upstream PURLs (pkg:generic/...). Per D03 that is purl-insufficient, so the
decision engine never ran on a single real CVE. This is an instrument defect,
not a finding about firmware.

Nothing in launch/ ships until CP-15 (distro-PURL identity resolution) lands
and CP-11 is re-run against the unchanged 30% threshold.

No vendor notices. No outreach. No posts. No HN.
