package vexout_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gautamtalksdev/lading/internal/decide"
	"github.com/gautamtalksdev/lading/internal/vexout"
)

func schemaDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Join(filepath.Dir(file), "schema")
}

func fixtureInput() vexout.DocumentInput {
	return vexout.DocumentInput{
		BundleID:       "abc123def4567890abc123def4567890abc123def4567890abc123def4567890",
		ArtifactSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Timestamp:      "2026-08-23T07:00:00Z",
		Statements: []vexout.Statement{
			{
				StatementID:   "cleared",
				CVE:           "CVE-2023-0286",
				ComponentPURL: "pkg:generic/openssl@3.0.7",
				Result: decide.Result{
					Verdict:          decide.VerdictNotAffected,
					Justification:    decide.JustificationVulnerableCodeNotPresent,
					RuleID:           decide.RuleD02,
					ManifestVersion:  "0.1.0+seed",
				},
			},
			{
				StatementID:   "affected",
				CVE:           "CVE-2024-0001",
				ComponentPURL: "pkg:generic/zlib@1.2.13",
				Result: decide.Result{
					Verdict:         decide.VerdictAffected,
					RuleID:          decide.RuleD04,
					ManifestVersion: "0.1.0+seed",
				},
			},
			{
				StatementID:   "refused",
				CVE:           "CVE-2024-0002",
				ComponentPURL: "pkg:generic/libexpat@2.5.0",
				Result: decide.Result{
					Verdict:         decide.VerdictUnderInvestigation,
					RuleID:          decide.RuleD03,
					ReasonCode:      decide.ReasonManifestNoEntry,
					ManifestVersion: "0.1.0+seed",
				},
			},
		},
	}
}

func TestEmit_Deterministic(t *testing.T) {
	in := fixtureInput()
	a, err := vexout.Emit(in)
	if err != nil {
		t.Fatal(err)
	}
	b, err := vexout.Emit(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range []struct {
		name string
		x, y []byte
	}{
		{"openvex", a.OpenVEX, b.OpenVEX},
		{"cyclonedx", a.CycloneDX, b.CycloneDX},
		{"csaf", a.CSAF, b.CSAF},
		{"refusals", a.Refusals, b.Refusals},
	} {
		if !bytes.Equal(pair.x, pair.y) {
			t.Fatalf("%s: not byte-identical across repeated emit", pair.name)
		}
	}
	if a.Summary.Cleared != 1 || a.Summary.Affected != 1 || a.Summary.Refusals != 1 {
		t.Fatalf("summary: %+v", a.Summary)
	}
}

func TestEmit_ImpactDetailPresent(t *testing.T) {
	in := fixtureInput()
	out, err := vexout.Emit(in)
	if err != nil {
		t.Fatal(err)
	}
	want := "rule_id="
	for _, doc := range []struct {
		name string
		data []byte
	}{
		{"openvex", out.OpenVEX},
		{"cyclonedx", out.CycloneDX},
		{"csaf", out.CSAF},
	} {
		if !strings.Contains(string(doc.data), want) {
			t.Fatalf("%s missing impact/detail with rule_id", doc.name)
		}
		if !strings.Contains(string(doc.data), in.BundleID) {
			t.Fatalf("%s missing bundle_id", doc.name)
		}
	}
	if !strings.Contains(string(out.OpenVEX), "checksum=sha256") {
		t.Fatal("openvex missing digest-pinned purl")
	}
}

func TestEmit_DocumentDisclaimerInAllFormats(t *testing.T) {
	in := fixtureInput()
	out, err := vexout.Emit(in)
	if err != nil {
		t.Fatal(err)
	}
	want := "manufacturer remains solely responsible"
	for _, pair := range []struct {
		name string
		data []byte
	}{
		{"openvex", out.OpenVEX},
		{"cyclonedx", out.CycloneDX},
		{"csaf", out.CSAF},
		{"refusals", out.Refusals},
	} {
		if !strings.Contains(string(pair.data), want) {
			t.Fatalf("%s missing disclaimer metadata", pair.name)
		}
	}
}

func TestDigestPinnedPURL(t *testing.T) {
	got, err := vexout.DigestPinnedPURL("pkg:generic/openssl@3.0.7", "ABCD")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "checksum=sha256%3Aabcd") && !strings.Contains(got, "checksum=sha256:abcd") {
		t.Fatalf("unexpected purl %q", got)
	}
}

func TestEmit_SchemaValidation(t *testing.T) {
	if _, err := exec.LookPath("check-jsonschema"); err != nil {
		t.Skip("check-jsonschema not installed")
	}
	in := fixtureInput()
	out, err := vexout.Emit(in)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files := map[string][]byte{
		"vex.openvex.json": out.OpenVEX,
		"vex.cdx.json":     out.CycloneDX,
		"vex.csaf.json":    out.CSAF,
	}
	schemas := map[string]string{
		"vex.openvex.json": filepath.Join(schemaDir(t), "openvex_json_schema.json"),
		"vex.cdx.json":     filepath.Join(schemaDir(t), "bom-1.6.schema.json"),
		"vex.csaf.json":    filepath.Join(schemaDir(t), "csaf_json_schema.json"),
	}
	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("check-jsonschema", "--schemafile", schemas[name], path)
		outBytes, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s schema validation failed: %v\n%s", name, err, outBytes)
		}
	}
}

func TestLoadFromBundle_Deterministic(t *testing.T) {
	bundle := writeTestBundle(t)
	a, err := vexout.LoadFromBundle(bundle, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := vexout.LoadFromBundle(bundle, "")
	if err != nil {
		t.Fatal(err)
	}
	outA, err := vexout.Emit(a)
	if err != nil {
		t.Fatal(err)
	}
	outB, err := vexout.Emit(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(outA.OpenVEX, outB.OpenVEX) {
		t.Fatal("bundle load emit not deterministic")
	}
}

func writeTestBundle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "bundle")
	in := fixtureInput()
	// Write a minimal bundle matching LoadFromBundle expectations.
	if err := os.MkdirAll(filepath.Join(bundleDir, "statements", "0001"), 0o750); err != nil {
		t.Fatal(err)
	}
	stmt := in.Statements[0]
	writeJSON(t, filepath.Join(bundleDir, "statements", "0001", "statement.json"), map[string]string{
		"cve":           stmt.CVE,
		"purl":          stmt.ComponentPURL,
		"verdict":       string(stmt.Result.Verdict),
		"justification": string(stmt.Result.Justification),
		"rule_id":       string(stmt.Result.RuleID),
	})
	writeJSON(t, filepath.Join(bundleDir, "statements", "0001", "inputs.json"), map[string]any{
		"artifact_sha256": in.ArtifactSHA256,
		"binaries":        []any{},
	})
	writeJSON(t, filepath.Join(bundleDir, "statements", "0001", "versions.json"), map[string]string{
		"manifest_version": stmt.Result.ManifestVersion,
	})
	manifest := "# evidence-bundle-v1 MANIFEST.sha\n" +
		"0000000000000000000000000000000000000000000000000000000000000000  statements/0001/statement.json\n"
	for _, name := range []string{"statement.json", "inputs.json", "versions.json"} {
		data, err := os.ReadFile(filepath.Join(bundleDir, "statements", "0001", name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256Bytes(data)
		manifest += sum + "  statements/0001/" + name + "\n"
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "MANIFEST.sha"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	return bundleDir
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

func sha256Bytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
