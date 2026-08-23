package decide_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gautamtalksdev/lading/internal/decide"
	"github.com/gautamtalksdev/lading/internal/inventory"
	"github.com/gautamtalksdev/lading/internal/manifest"
	"gopkg.in/yaml.v3"
)

type fixtureCase struct {
	ID                    string `yaml:"id"`
	ExpectRule            string `yaml:"expect_rule"`
	ExpectVerdict         string `yaml:"expect_verdict"`
	ExpectJustification   string `yaml:"expect_justification,omitempty"`
	ExpectReason          string `yaml:"expect_reason,omitempty"`
	Finding               struct {
		CVE           string `yaml:"cve"`
		ComponentPURL string `yaml:"component_purl"`
	} `yaml:"finding"`
	Manifest struct {
		Version   string `yaml:"version"`
		Component struct {
			Name            string   `yaml:"name"`
			Ecosystem       string   `yaml:"ecosystem"`
			PURLs           []string `yaml:"purls"`
			IdentitySymbols []string `yaml:"identity_symbols"`
			IdentityStrings []string `yaml:"identity_strings,omitempty"`
		} `yaml:"component"`
		Entry struct {
			CVE               string `yaml:"cve"`
			AffectedVersions  []string `yaml:"affected_versions"`
			VulnerableSymbols []struct {
				Name       string `yaml:"name"`
				Confidence string `yaml:"confidence"`
			} `yaml:"vulnerable_symbols"`
			ManifestVersion string `yaml:"manifest_version"`
		} `yaml:"entry"`
	} `yaml:"manifest"`
	Inventories []struct {
		File string `yaml:"file"`
	} `yaml:"inventories"`
}

func TestFixtures_Conformance(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "decide")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	countByRule := map[string]int{}
	var total int
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		casePath := filepath.Join(root, ent.Name(), "case.yaml")
		if _, err := os.Stat(casePath); err != nil {
			continue
		}
		total++
		fc := loadFixture(t, casePath)
		countByRule[fc.ExpectRule]++

		dir := filepath.Dir(casePath)
		var invs []*inventory.Inventory
		for _, ref := range fc.Inventories {
			inv := loadInventory(t, filepath.Join(dir, ref.File))
			invs = append(invs, inv)
		}

		comp := manifest.Component{
			Name:            fc.Manifest.Component.Name,
			Ecosystem:       fc.Manifest.Component.Ecosystem,
			PURLs:           fc.Manifest.Component.PURLs,
			IdentitySymbols: fc.Manifest.Component.IdentitySymbols,
			IdentityStrings: fc.Manifest.Component.IdentityStrings,
		}
		var vulnSyms []manifest.VulnerableSymbol
		for _, vs := range fc.Manifest.Entry.VulnerableSymbols {
			conf := manifest.ConfidenceProbable
			if vs.Confidence == "definitive" {
				conf = manifest.ConfidenceDefinitive
			}
			vulnSyms = append(vulnSyms, manifest.VulnerableSymbol{
				Name:       vs.Name,
				Confidence: conf,
				Provenance: manifest.Provenance{
					UpstreamFixCommit: "https://example.com/commit/fix",
					Derivation:        manifest.DerivationManual,
					ReviewedBy:        "fixture",
					ReviewedAt:        "2026-08-23",
				},
			})
		}
		entry := manifest.Entry{
			CVE:               fc.Manifest.Entry.CVE,
			AffectedVersions:  fc.Manifest.Entry.AffectedVersions,
			VulnerableSymbols: vulnSyms,
			ManifestVersion:   fc.Manifest.Entry.ManifestVersion,
		}
		m, err := manifest.BuildForTest(fc.Manifest.Version, comp, []manifest.Entry{entry})
		if err != nil {
			t.Fatalf("%s: manifest: %v", fc.ID, err)
		}

		got, err := decide.Evaluate(decide.Input{
			Inventories: invs,
			Finding: decide.Finding{
				CVE:           fc.Finding.CVE,
				ComponentPURL: fc.Finding.ComponentPURL,
			},
			Manifest: m,
		})
		if err != nil {
			t.Fatalf("%s: %v", fc.ID, err)
		}

		if string(got.Verdict) != fc.ExpectVerdict {
			t.Fatalf("%s: verdict=%s want %s (rule=%s reason=%s)",
				fc.ID, got.Verdict, fc.ExpectVerdict, got.RuleID, got.ReasonCode)
		}
		if string(got.RuleID) != fc.ExpectRule {
			t.Fatalf("%s: rule=%s want %s", fc.ID, got.RuleID, fc.ExpectRule)
		}
		if fc.ExpectJustification != "" && string(got.Justification) != fc.ExpectJustification {
			t.Fatalf("%s: justification=%s want %s", fc.ID, got.Justification, fc.ExpectJustification)
		}
		if fc.ExpectReason != "" && string(got.ReasonCode) != fc.ExpectReason {
			t.Fatalf("%s: reason=%s want %s", fc.ID, got.ReasonCode, fc.ExpectReason)
		}
		if got.ToolVersion != decide.ToolVersion {
			t.Fatalf("%s: tool_version=%s", fc.ID, got.ToolVersion)
		}
		if got.ManifestVersion == "" {
			t.Fatalf("%s: empty manifest_version", fc.ID)
		}
		if got.RuleID == "" {
			t.Fatalf("%s: empty rule_id", fc.ID)
		}
	}
	if total < 40 {
		t.Fatalf("fixture count=%d want >=40", total)
	}
	for _, rule := range []string{"D01", "D02", "D03", "D04"} {
		if countByRule[rule] < 8 {
			t.Fatalf("rule %s fixtures=%d want >=8", rule, countByRule[rule])
		}
	}
	t.Logf("conformance fixtures: %d total", total)
}

func loadFixture(t *testing.T, path string) fixtureCase {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		t.Fatal(err)
	}
	var fc fixtureCase
	if err := yaml.Unmarshal(data, &fc); err != nil {
		t.Fatal(err)
	}
	return fc
}

func loadInventory(t *testing.T, path string) *inventory.Inventory {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		t.Fatal(err)
	}
	var inv inventory.Inventory
	if err := json.Unmarshal(data, &inv); err != nil {
		t.Fatal(err)
	}
	if inv.Path == "" {
		inv.Path = filepath.Base(path)
	}
	return &inv
}
