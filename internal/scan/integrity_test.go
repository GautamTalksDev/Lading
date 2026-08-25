package scan_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gautamtalksdev/lading/internal/scan"
)

func TestVerifyArtifactIntegrity_HashMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blob.bin")
	if err := os.WriteFile(path, []byte("honest-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	want, err := scan.SHA256File(path)
	if err != nil {
		t.Fatal(err)
	}
	// Tamper one byte after cataloguing.
	if writeErr := os.WriteFile(path, []byte("tampered-bytes"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}

	err = scan.VerifyArtifactIntegrity(path, scan.IntegrityExpectation{Expected: want})
	ie := scan.IntegrityErrorOf(err)
	if ie == nil || ie.Reason != scan.ReasonArtifactHashMismatch {
		t.Fatalf("want hash-mismatch, got %v", err)
	}
	if ie.Expected != want || ie.Actual == want {
		t.Fatalf("expected/actual not recorded: %+v", ie)
	}
}

func TestVerifyArtifactIntegrity_Absent(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-artifact")
	err := scan.VerifyArtifactIntegrity(missing, scan.IntegrityExpectation{Expected: "abc"})
	ie := scan.IntegrityErrorOf(err)
	if ie == nil || ie.Reason != scan.ReasonArtifactAbsent {
		t.Fatalf("want artifact-absent, got %v", err)
	}
}

func TestVerifyArtifactIntegrity_Unhashed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blob.bin")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := scan.VerifyArtifactIntegrity(path, scan.IntegrityExpectation{NullSHA256: true})
	ie := scan.IntegrityErrorOf(err)
	if ie == nil || ie.Reason != scan.ReasonArtifactUnhashed {
		t.Fatalf("want artifact-unhashed, got %v", err)
	}

	err = scan.VerifyArtifactIntegrity(path, scan.IntegrityExpectation{Expected: ""})
	ie = scan.IntegrityErrorOf(err)
	if ie == nil || ie.Reason != scan.ReasonArtifactUnhashed {
		t.Fatalf("empty expected should be unhashed, got %v", err)
	}
}

func TestRun_RefusesTamperedBeforeUnpack(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blob.bin")
	if err := os.WriteFile(path, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	want, err := scan.SHA256File(path)
	if err != nil {
		t.Fatal(err)
	}
	if writeErr := os.WriteFile(path, []byte("v2"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}

	res, err := scan.Run(scan.Options{
		ArtifactPath: path,
		FindingsPath: filepath.Join(dir, "missing-findings.json"), // would fail later if integrity skipped
		ManifestDir:  filepath.Join("..", "..", "manifest"),
		OutDir:       dir,
		Integrity:    &scan.IntegrityExpectation{Expected: want},
	})
	if !scan.IsIntegrityError(err) {
		t.Fatalf("expected integrity error, got %v", err)
	}
	if res.Report.Success {
		t.Fatal("success must be false")
	}
	if res.Report.IntegrityRefusals[scan.ReasonArtifactHashMismatch] != 1 {
		t.Fatalf("integrity_refusals: %+v", res.Report.IntegrityRefusals)
	}
	if res.Report.RefusedTotal != 1 {
		t.Fatalf("refused total=%d", res.Report.RefusedTotal)
	}
	if res.Report.BinariesScanned != 0 {
		t.Fatal("must not scan binaries after integrity refusal")
	}
}

func TestRun_RefusesAbsent(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "gone.bin")
	res, err := scan.Run(scan.Options{
		ArtifactPath: missing,
		FindingsPath: filepath.Join(dir, "f.json"),
		OutDir:       dir,
		Integrity:    &scan.IntegrityExpectation{Expected: strings.Repeat("a", 64)},
	})
	ie := scan.IntegrityErrorOf(err)
	if ie == nil || ie.Reason != scan.ReasonArtifactAbsent {
		t.Fatalf("want absent, got %v", err)
	}
	if res.Report.IntegrityRefusals[scan.ReasonArtifactAbsent] != 1 {
		t.Fatalf("%+v", res.Report.IntegrityRefusals)
	}
}

func TestRun_RefusesUnhashed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blob.bin")
	if err := os.WriteFile(path, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := scan.Run(scan.Options{
		ArtifactPath: path,
		FindingsPath: filepath.Join(dir, "f.json"),
		OutDir:       dir,
		Integrity:    &scan.IntegrityExpectation{NullSHA256: true},
	})
	ie := scan.IntegrityErrorOf(err)
	if ie == nil || ie.Reason != scan.ReasonArtifactUnhashed {
		t.Fatalf("want unhashed, got %v", err)
	}
	if res.Report.IntegrityRefusals[scan.ReasonArtifactUnhashed] != 1 {
		t.Fatalf("%+v", res.Report.IntegrityRefusals)
	}
}
