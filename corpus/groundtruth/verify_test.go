package groundtruth_test

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

type statementsDoc struct {
	Version    string      `yaml:"version"`
	Statements []statement `yaml:"statements"`
}

type statement struct {
	ID                   string `yaml:"id"`
	SourceType           string `yaml:"source_type"`
	Source               string `yaml:"source"`
	ExpectRule           string `yaml:"expect_rule"`
	ExpectVerdict        string `yaml:"expect_verdict"`
	ExpectJustification  string `yaml:"expect_justification,omitempty"`
	ExpectReason         string `yaml:"expect_reason,omitempty"`
	Finding              struct {
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

func TestGroundTruth_100Statements(t *testing.T) {
	root := filepath.Join("..", "..")
	path := filepath.Join(root, "corpus", "groundtruth", "statements.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read statements: %v", err)
	}
	var doc statementsDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse statements: %v", err)
	}
	if len(doc.Statements) != 100 {
		t.Fatalf("statements=%d want 100", len(doc.Statements))
	}

	falseNA := 0
	countRule := map[string]int{}
	countVerdict := map[string]int{}

	for _, st := range doc.Statements {
		countRule[st.ExpectRule]++
		countVerdict[st.ExpectVerdict]++

		invs, err := loadInventories(root, st)
		if err != nil {
			t.Fatalf("%s: %v", st.ID, err)
		}
		m, err := buildManifest(st)
		if err != nil {
			t.Fatalf("%s: manifest: %v", st.ID, err)
		}
		got, err := decide.Evaluate(decide.Input{
			Inventories: invs,
			Finding: decide.Finding{
				CVE:           st.Finding.CVE,
				ComponentPURL: st.Finding.ComponentPURL,
			},
			Manifest: m,
		})
		if err != nil {
			t.Fatalf("%s: evaluate: %v", st.ID, err)
		}

		if string(got.Verdict) != st.ExpectVerdict {
			t.Errorf("%s: verdict=%s want %s rule=%s reason=%s",
				st.ID, got.Verdict, st.ExpectVerdict, got.RuleID, got.ReasonCode)
		}
		if string(got.RuleID) != st.ExpectRule {
			t.Errorf("%s: rule=%s want %s", st.ID, got.RuleID, st.ExpectRule)
		}
		if st.ExpectJustification != "" && string(got.Justification) != st.ExpectJustification {
			t.Errorf("%s: justification=%s want %s", st.ID, got.Justification, st.ExpectJustification)
		}
		if st.ExpectReason != "" && string(got.ReasonCode) != st.ExpectReason {
			t.Errorf("%s: reason=%s want %s", st.ID, got.ReasonCode, st.ExpectReason)
		}

		if st.ExpectVerdict == "NOT_AFFECTED" && got.Verdict != decide.VerdictNotAffected {
			falseNA++
		}
		if got.Verdict == decide.VerdictNotAffected && st.ExpectVerdict != "NOT_AFFECTED" {
			falseNA++
			t.Errorf("%s: FALSE NOT_AFFECTED engine=%s ground_truth=%s", st.ID, got.Verdict, st.ExpectVerdict)
		}
	}

	for _, rule := range []string{"D01", "D02", "D03", "D04"} {
		if countRule[rule] < 15 {
			t.Errorf("rule %s count=%d want >=15 stratified", rule, countRule[rule])
		}
	}
	if countVerdict["NOT_AFFECTED"] < 50 {
		t.Errorf("NOT_AFFECTED count=%d want >=50 (weighted toward NA)", countVerdict["NOT_AFFECTED"])
	}
	if falseNA > 0 {
		t.Fatalf("KT-2 violation: %d false not_affected disagreements", falseNA)
	}
}

func loadInventories(root string, st statement) ([]*inventory.Inventory, error) {
	var invs []*inventory.Inventory
	base := filepath.Join(root, st.Source)
	if st.SourceType == "decide_fixture" {
		base = filepath.Join(root, st.Source)
	}
	for _, ref := range st.Inventories {
		var p string
		if st.SourceType == "decide_fixture" {
			p = filepath.Join(base, ref.File)
			raw, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			var inv inventory.Inventory
			if err := json.Unmarshal(raw, &inv); err != nil {
				return nil, err
			}
			if inv.Path == "" {
				inv.Path = filepath.Base(p)
			}
			invs = append(invs, &inv)
			continue
		}
		p = filepath.Join(root, "testdata", "inventory", "bin", ref.File)
		inv, err := inventory.Scan(p)
		if err != nil {
			return nil, err
		}
		invs = append(invs, inv)
	}
	return invs, nil
}

func buildManifest(st statement) (*manifest.Manifest, error) {
	comp := manifest.Component{
		Name:            st.Manifest.Component.Name,
		Ecosystem:       st.Manifest.Component.Ecosystem,
		PURLs:           st.Manifest.Component.PURLs,
		IdentitySymbols: st.Manifest.Component.IdentitySymbols,
		IdentityStrings: st.Manifest.Component.IdentityStrings,
	}
	var vulnSyms []manifest.VulnerableSymbol
	for _, vs := range st.Manifest.Entry.VulnerableSymbols {
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
				ReviewedBy:        "groundtruth",
				ReviewedAt:        "2026-08-23",
			},
		})
	}
	entry := manifest.Entry{
		CVE:               st.Manifest.Entry.CVE,
		AffectedVersions:  st.Manifest.Entry.AffectedVersions,
		VulnerableSymbols: vulnSyms,
		ManifestVersion:   st.Manifest.Entry.ManifestVersion,
	}
	return manifest.BuildForTest(st.Manifest.Version, comp, []manifest.Entry{entry})
}
