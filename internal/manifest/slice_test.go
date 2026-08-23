package manifest_test

import (
	"testing"

	"github.com/gautamtalksdev/lading/internal/manifest"
)

func TestLoadFromSlice_MatchesBuildForTest(t *testing.T) {
	comp := manifest.Component{
		Name:            "zlib",
		Ecosystem:       "native",
		PURLs:           []string{"pkg:generic/zlib@1.2.12"},
		IdentitySymbols: []string{"inflate"},
	}
	entry := manifest.Entry{
		CVE:              "CVE-2022-37434",
		AffectedVersions: []string{"1.2.12"},
		VulnerableSymbols: []manifest.VulnerableSymbol{{
			Name:       "inflate",
			Confidence: manifest.ConfidenceDefinitive,
			Provenance: manifest.Provenance{
				UpstreamFixCommit: "https://github.com/madler/zlib/commit/eff308af425b67093bab25f80f1ae950166bece1",
				Derivation:        manifest.DerivationPatchTouched,
				ReviewedBy:        "t",
				ReviewedAt:        "2026-08-23",
			},
		}},
		ManifestVersion: "0.1.0",
	}
	m1, err := manifest.BuildForTest("0.1.0", comp, []manifest.Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	slice, err := manifest.SliceFromManifest(m1, "zlib", "CVE-2022-37434")
	if err != nil {
		t.Fatal(err)
	}
	m2, err := manifest.LoadFromSlice(slice)
	if err != nil {
		t.Fatal(err)
	}
	if m2.Version() != m1.Version() {
		t.Fatalf("version %s vs %s", m2.Version(), m1.Version())
	}
	ents, ok := m2.LookupCVE("CVE-2022-37434")
	if !ok || len(ents) != 1 {
		t.Fatal("lookup failed")
	}
	if ents[0].VulnerableSymbols[0].Name != "inflate" {
		t.Fatal("symbol mismatch")
	}
	_ = ents[0].AllowsNotAffected()
}
