package corpus_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"
)

// Allowed artifact classes after RP-6 / S-06 honesty pass + S-08 firmware stratum.
var classEnum = map[string]struct{}{
	"oci-base":             {},
	"oci-app":              {},
	"openwrt":              {},
	"firmware":             {},
	"static-binary":        {},
	"substitute-container": {},
	"rtos-sdk":             {},
	"benchmark":            {},
}

type artifactsDoc struct {
	Version   string         `yaml:"version"`
	Schema    map[string]any `yaml:"schema"`
	Artifacts []artifactEntry `yaml:"artifacts"`
}

type artifactEntry struct {
	ID          string  `yaml:"id"`
	Class       string  `yaml:"class"`
	Substitutes string  `yaml:"substitutes"`
	License     string  `yaml:"license"`
	Provenance  string  `yaml:"provenance"`
	SourceURL   string  `yaml:"source_url"`
	SHA256      *string `yaml:"sha256"`
	FetchedAt   *string `yaml:"fetched_at"`
	Status      string  `yaml:"status"`
	Notes       string  `yaml:"notes"`
	Ref         string  `yaml:"ref"`
	URL         string  `yaml:"url"`
	Path        string  `yaml:"path"`
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// corpus/artifacts_test.go -> repo root
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}

func TestArtifactsYAMLSchema(t *testing.T) {
	path := filepath.Join(repoRoot(t), "corpus", "ARTIFACTS.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read ARTIFACTS.yaml: %v", err)
	}
	var doc artifactsDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse ARTIFACTS.yaml: %v", err)
	}
	if len(doc.Artifacts) < 40 {
		t.Fatalf("expected >=40 artifacts, got %d", len(doc.Artifacts))
	}

	seen := map[string]struct{}{}
	for i, a := range doc.Artifacts {
		if a.ID == "" {
			t.Errorf("artifact[%d]: missing id", i)
			continue
		}
		if _, dup := seen[a.ID]; dup {
			t.Errorf("duplicate id %q", a.ID)
		}
		seen[a.ID] = struct{}{}

		if a.Class == "" {
			t.Errorf("%s: missing class", a.ID)
		} else if _, ok := classEnum[a.Class]; !ok {
			t.Errorf("%s: class %q not in fixed enum", a.ID, a.Class)
		}
		if a.Class == "yocto" {
			t.Errorf("%s: forbidden dishonest class %q (use firmware with real provenance)", a.ID, a.Class)
		}
		if a.Class == "firmware" {
			if a.SHA256 == nil || *a.SHA256 == "" {
				t.Errorf("%s: class firmware requires non-empty sha256", a.ID)
			}
			if a.SourceURL == "" || a.SourceURL == "SUBSTITUTE" {
				t.Errorf("%s: class firmware requires real source_url (not SUBSTITUTE)", a.ID)
			}
		}
		if a.Class == "substitute-container" && a.Substitutes == "" {
			t.Errorf("%s: substitute-container requires substitutes:", a.ID)
		}

		// Required honesty fields (keys must be present; null allowed when missing).
		if a.SourceURL == "" {
			t.Errorf("%s: missing source_url", a.ID)
		}
		if a.Status != "present" && a.Status != "missing" {
			t.Errorf("%s: status must be present|missing, got %q", a.ID, a.Status)
		}
		switch a.Status {
		case "present":
			if a.SHA256 == nil || *a.SHA256 == "" {
				t.Errorf("%s: status=present requires non-empty sha256", a.ID)
			}
			if a.FetchedAt == nil || *a.FetchedAt == "" {
				t.Errorf("%s: status=present requires fetched_at", a.ID)
			}
		case "missing":
			if a.SHA256 != nil {
				t.Errorf("%s: status=missing requires sha256: null", a.ID)
			}
		}

		// yaml.v3 omits absent keys as zero values; ensure required keys exist by re-decode map.
	}

	// Map-level check: every entry must contain sha256, source_url, fetched_at keys.
	var rawDoc struct {
		Artifacts []map[string]any `yaml:"artifacts"`
	}
	if err := yaml.Unmarshal(raw, &rawDoc); err != nil {
		t.Fatalf("reparse map: %v", err)
	}
	required := []string{"sha256", "source_url", "fetched_at", "status", "class", "id"}
	for i, m := range rawDoc.Artifacts {
		id, _ := m["id"].(string)
		for _, k := range required {
			if _, ok := m[k]; !ok {
				t.Errorf("artifact[%d] id=%q: missing required key %q", i, id, k)
			}
		}
	}

	fw := 0
	for _, a := range doc.Artifacts {
		if a.Class == "firmware" {
			fw++
		}
	}
	if fw < 10 {
		t.Errorf("S-08 bar: need >=10 class=firmware entries, got %d", fw)
	}
}
