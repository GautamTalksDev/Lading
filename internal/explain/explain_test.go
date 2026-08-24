package explain_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gautamtalksdev/lading/internal/decide"
	"github.com/gautamtalksdev/lading/internal/evidence"
	"github.com/gautamtalksdev/lading/internal/explain"
	"github.com/gautamtalksdev/lading/internal/inventory"
	"github.com/gautamtalksdev/lading/internal/manifest"
)

func TestExplain_FromBundle(t *testing.T) {
	bundle := writeExplainFixture(t)
	rep, err := explain.Explain(explain.Options{
		BundleDir: bundle,
		CVE:       "CVE-2023-0286",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.RuleID != string(decide.RuleD02) {
		t.Fatalf("rule %s", rep.RuleID)
	}
	text := explain.FormatHuman(rep)
	for _, want := range []string{
		"CVE-2023-0286",
		"Not affected",
		"D02",
		"upstream fix:",
		"GENERAL_NAME_cmp",
		"lading verify",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
	for _, forbidden := range []string{
		"vulnerable_code_not_in_execute_path",
		"vulnerable_code_cannot_be_controlled_by_adversary",
		"inline_mitigations_already_exist",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("forbidden phrase in explain output: %s", forbidden)
		}
	}
}

func TestExplain_RefusalReadable(t *testing.T) {
	bundle := writeRefusalFixture(t)
	rep, err := explain.Explain(explain.Options{
		BundleDir: bundle,
		CVE:       "CVE-2099-0001",
	})
	if err != nil {
		t.Fatal(err)
	}
	text := explain.FormatHuman(rep)
	if !strings.Contains(text, "Refused") {
		t.Fatalf("expected refusal headline:\n%s", text)
	}
	if !strings.Contains(text, "no manifest entry") {
		t.Fatalf("expected plain reason:\n%s", text)
	}
	if !strings.Contains(text, "prove-a-negative") {
		t.Fatalf("expected forbidden justification reminder:\n%s", text)
	}
}

func writeExplainFixture(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	artifact := filepath.Join(filepath.Dir(file), "..", "..", "testdata", "inventory", "bin", "symver_ssl_elf")
	inv, err := inventory.Scan(artifact)
	if err != nil {
		t.Fatal(err)
	}
	comp := manifest.Component{
		Name:            "openssl",
		Ecosystem:       "native",
		PURLs:           []string{"pkg:generic/openssl@3.0.7"},
		IdentitySymbols: []string{"OPENSSL_init_ssl", "GENERAL_NAME_cmp", "SSL_CTX_new"},
	}
	entry := manifest.Entry{
		CVE:              "CVE-2023-0286",
		AffectedVersions: []string{"3.0.7"},
		VulnerableSymbols: []manifest.VulnerableSymbol{{
			Name:                 "GENERAL_NAME_cmp",
			Confidence:           manifest.ConfidenceDefinitive,
			DynsymExportVerified: true,
			Provenance: manifest.Provenance{
				UpstreamFixCommit: "https://github.com/openssl/openssl/commit/2f7530077e0ef79d98718138716bc51ca0cad658",
				Derivation:        manifest.DerivationPatchTouched,
				ReviewedBy:        "fixture",
				ReviewedAt:        "2026-08-23",
			},
		}},
		ManifestVersion: "0.1.0",
	}
	m, err := manifest.BuildForTest("0.1.0", comp, []manifest.Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	slice, err := manifest.SliceFromManifest(m, "openssl", "CVE-2023-0286")
	if err != nil {
		t.Fatal(err)
	}
	finding := decide.Finding{CVE: "CVE-2023-0286", ComponentPURL: "pkg:generic/openssl@3.0.7"}
	result, err := decide.Evaluate(decide.Input{
		Inventories: []*inventory.Inventory{inv},
		Finding:     finding,
		Manifest:    m,
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle")
	if _, err := evidence.WriteBundleDir(bundle, []evidence.BuildInput{{
		ArtifactPath: artifact,
		StatementID:  "cve-2023-0286",
		Finding:      finding,
		Result:       result,
		Inventories:  []*inventory.Inventory{inv},
		Slice:        slice,
	}}); err != nil {
		t.Fatal(err)
	}
	return bundle
}

func writeRefusalFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle")
	stmtDir := filepath.Join(bundle, "statements", "refused")
	if err := os.MkdirAll(stmtDir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(stmtDir, "statement.json"), map[string]string{
		"cve":         "CVE-2099-0001",
		"purl":        "pkg:generic/unknown@1",
		"verdict":     "UNDER_INVESTIGATION",
		"rule_id":     "D03",
		"reason_code": "manifest_no_entry",
	})
	writeJSON(t, filepath.Join(stmtDir, "inputs.json"), map[string]any{
		"artifact_sha256": "abc",
		"binaries":        []any{},
	})
	writeJSON(t, filepath.Join(stmtDir, "observations.json"), map[string]any{
		"symbols_present": []any{},
		"symbols_absent":  []any{},
	})
	writeJSON(t, filepath.Join(stmtDir, "manifest-slice.json"), map[string]any{
		"version": "0.1.0",
		"component": map[string]string{
			"name":      "unknown",
			"ecosystem": "native",
		},
		"entries": []any{},
	})
	writeJSON(t, filepath.Join(stmtDir, "versions.json"), map[string]string{
		"manifest_version": "0.1.0",
	})
	manifestBody := "# evidence-bundle-v1 MANIFEST.sha\n"
	for _, name := range []string{"statement.json", "inputs.json", "observations.json", "manifest-slice.json", "versions.json"} {
		data, err := os.ReadFile(filepath.Join(stmtDir, name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256hex(data)
		manifestBody += sum + "  statements/refused/" + name + "\n"
	}
	if err := os.WriteFile(filepath.Join(bundle, "MANIFEST.sha"), []byte(manifestBody), 0o600); err != nil {
		t.Fatal(err)
	}
	return bundle
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func sha256hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
