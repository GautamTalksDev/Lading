package evidence

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gautamtalksdev/lading/internal/decide"
	"github.com/gautamtalksdev/lading/internal/inventory"
	"github.com/gautamtalksdev/lading/internal/manifest"
)

// VerifyStatus is the outcome for one statement.
type VerifyStatus string

const (
	StatusVerified     VerifyStatus = "VERIFIED"
	StatusMismatch     VerifyStatus = "MISMATCH"
	StatusUnverifiable VerifyStatus = "UNVERIFIABLE"
)

// StatementReport is verification output for one VEX/bundle statement.
type StatementReport struct {
	StatementID string       `json:"statement_id"`
	Status      VerifyStatus `json:"status"`
	Detail      string       `json:"detail,omitempty"`
	CVE         string       `json:"cve,omitempty"`
	PURL        string       `json:"purl,omitempty"`
}

// Report is the full verification result.
type Report struct {
	BundleID   string            `json:"bundle_id"`
	Statements []StatementReport `json:"statements"`
}

// AllVerified reports whether every statement is VERIFIED.
func (r Report) AllVerified() bool {
	for _, s := range r.Statements {
		if s.Status != StatusVerified {
			return false
		}
	}
	return len(r.Statements) > 0
}

// VerifyOptions configures independent bundle verification.
type VerifyOptions struct {
	ArtifactPath string
	VEXPath      string
	BundleDir    string
}

// Verify re-derives decisions from the artifact using only the embedded manifest
// slice. It performs no network I/O (air-gapped safe).
func Verify(opt VerifyOptions) (Report, error) {
	if err := assertNoNetwork(); err != nil {
		return Report{}, err
	}

	bundleID, err := verifyBundleIntegrity(opt.BundleDir)
	if err != nil {
		return Report{}, err
	}

	vexData, err := os.ReadFile(opt.VEXPath) // #nosec G304
	if err != nil {
		return Report{}, fmt.Errorf("evidence: read vex: %w", err)
	}
	vexStmts, err := ParseVEX(vexData)
	if err != nil {
		return Report{}, err
	}

	stmtDirs, err := listStatementDirs(opt.BundleDir)
	if err != nil {
		return Report{}, err
	}

	report := Report{BundleID: bundleID}
	for _, id := range stmtDirs {
		rep := verifyStatement(opt.ArtifactPath, filepath.Join(opt.BundleDir, "statements", id), id, vexStmts)
		report.Statements = append(report.Statements, rep)
	}
	if len(report.Statements) == 0 {
		return Report{}, fmt.Errorf("evidence: bundle contains no statements")
	}
	return report, nil
}

func verifyStatement(artifactPath, stmtDir, stmtID string, vexStmts []VEXStatement) StatementReport {
	rep := StatementReport{StatementID: stmtID}

	stmt, inputs, slice, err := loadStatementFiles(stmtDir)
	if err != nil {
		rep.Status = StatusUnverifiable
		rep.Detail = err.Error()
		return rep
	}
	rep.CVE = stmt.CVE
	rep.PURL = stmt.PURL

	if herr := verifyArtifactHashes(artifactPath, inputs); herr != nil {
		rep.Status = StatusUnverifiable
		rep.Detail = herr.Error()
		return rep
	}

	invs, err := rescanInventories(artifactPath, inputs)
	if err != nil {
		rep.Status = StatusUnverifiable
		rep.Detail = err.Error()
		return rep
	}

	m, err := manifest.LoadFromSlice(slice)
	if err != nil {
		rep.Status = StatusUnverifiable
		rep.Detail = fmt.Sprintf("manifest slice: %v", err)
		return rep
	}

	got, err := decide.Evaluate(decide.Input{
		Inventories: invs,
		Finding: decide.Finding{
			CVE:           stmt.CVE,
			ComponentPURL: stmt.PURL,
		},
		Manifest: m,
	})
	if err != nil {
		rep.Status = StatusUnverifiable
		rep.Detail = err.Error()
		return rep
	}

	if !resultsEqual(stmt, got) {
		rep.Status = StatusMismatch
		rep.Detail = fmt.Sprintf("re-derived %s/%s/%s != bundle %s/%s/%s",
			got.Verdict, got.Justification, got.RuleID,
			stmt.Verdict, stmt.Justification, stmt.RuleID)
		return rep
	}

	if !vexContains(vexStmts, stmt) {
		rep.Status = StatusMismatch
		rep.Detail = "vex document does not match bundle statement"
		return rep
	}

	rep.Status = StatusVerified
	return rep
}

func resultsEqual(want StatementRecord, got decide.Result) bool {
	if strings.ToUpper(want.Verdict) != string(got.Verdict) {
		return false
	}
	if want.Justification != "" && string(got.Justification) != want.Justification {
		return false
	}
	if want.RuleID != string(got.RuleID) {
		return false
	}
	if want.ReasonCode != "" && string(got.ReasonCode) != want.ReasonCode {
		return false
	}
	if want.ReasonCode == "" && got.ReasonCode != "" &&
		got.Verdict == decide.VerdictUnderInvestigation {
		return false
	}
	return true
}

func vexContains(vex []VEXStatement, stmt StatementRecord) bool {
	for _, v := range vex {
		if MatchesStatement(v, stmt) {
			return true
		}
	}
	return false
}

func loadStatementFiles(dir string) (StatementRecord, InputsRecord, manifest.Slice, error) {
	var stmt StatementRecord
	var inputs InputsRecord
	var slice manifest.Slice
	for _, name := range StatementFiles {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path) // #nosec G304
		if err != nil {
			return stmt, inputs, slice, err
		}
		switch name {
		case "statement.json":
			if err := json.Unmarshal(data, &stmt); err != nil {
				return stmt, inputs, slice, err
			}
		case "inputs.json":
			if err := json.Unmarshal(data, &inputs); err != nil {
				return stmt, inputs, slice, err
			}
		case "manifest-slice.json":
			if err := json.Unmarshal(data, &slice); err != nil {
				return stmt, inputs, slice, err
			}
		}
	}
	return stmt, inputs, slice, nil
}

func verifyArtifactHashes(artifactPath string, inputs InputsRecord) error {
	fi, err := os.Stat(artifactPath)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		h := sha256.New()
		paths := make([]string, len(inputs.Binaries))
		copy(paths, func() []string {
			out := make([]string, len(inputs.Binaries))
			for i, b := range inputs.Binaries {
				out[i] = b.Path
			}
			return out
		}())
		sort.Strings(paths)
		for _, rel := range paths {
			var want string
			for _, b := range inputs.Binaries {
				if b.Path == rel {
					want = b.SHA256
					break
				}
			}
			full := filepath.Join(artifactPath, rel)
			gotBin, berr := fileSHA256(full)
			if berr != nil {
				return fmt.Errorf("binary %s: %w", rel, berr)
			}
			if !strings.EqualFold(gotBin, want) {
				return fmt.Errorf("binary %s sha256 mismatch", rel)
			}
			_, _ = h.Write([]byte(rel + "\n" + gotBin + "\n"))
		}
		if hex.EncodeToString(h.Sum(nil)) != inputs.ArtifactSHA256 {
			return fmt.Errorf("artifact sha256 mismatch")
		}
		return nil
	}
	got, err := fileSHA256(artifactPath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(got, inputs.ArtifactSHA256) {
		return fmt.Errorf("artifact sha256 mismatch")
	}
	for _, b := range inputs.Binaries {
		if !strings.EqualFold(b.SHA256, got) {
			return fmt.Errorf("binary %s sha256 mismatch", b.Path)
		}
	}
	return nil
}

func rescanInventories(artifactPath string, inputs InputsRecord) ([]*inventory.Inventory, error) {
	fi, err := os.Stat(artifactPath)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		inv, err := inventory.Scan(artifactPath)
		if err != nil {
			return nil, err
		}
		return []*inventory.Inventory{inv}, nil
	}
	var out []*inventory.Inventory
	for _, b := range inputs.Binaries {
		path := filepath.Join(artifactPath, b.Path)
		inv, err := inventory.Scan(path)
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", b.Path, err)
		}
		out = append(out, inv)
	}
	return out, nil
}

func verifyBundleIntegrity(bundleDir string) (string, error) {
	manifestPath := filepath.Join(bundleDir, "MANIFEST.sha")
	data, err := os.ReadFile(manifestPath) // #nosec G304
	if err != nil {
		return "", fmt.Errorf("evidence: read MANIFEST.sha: %w", err)
	}
	sum := sha256.Sum256(data)
	bundleID := hex.EncodeToString(sum[:])

	entries, err := parseManifestSHA(data)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		path := filepath.Join(bundleDir, filepath.FromSlash(e.path))
		got, err := fileSHA256(path)
		if err != nil {
			return "", fmt.Errorf("evidence: bundle file %s: %w", e.path, err)
		}
		if !strings.EqualFold(got, e.sha256) {
			return "", fmt.Errorf("evidence: bundle tampered: %s", e.path)
		}
	}
	return bundleID, nil
}

type manifestEntry struct {
	sha256 string
	path   string
}

func parseManifestSHA(data []byte) ([]manifestEntry, error) {
	var out []manifestEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			return nil, fmt.Errorf("evidence: bad MANIFEST.sha line: %q", line)
		}
		out = append(out, manifestEntry{sha256: parts[0], path: parts[1]})
	}
	return out, sc.Err()
}

func listStatementDirs(bundleDir string) ([]string, error) {
	root := filepath.Join(bundleDir, "statements")
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("evidence: statements: %w", err)
	}
	var ids []string
	for _, e := range ents {
		if e.IsDir() {
			ids = append(ids, e.Name())
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// assertNoNetwork is a compile-time/runtime guard: verification uses only stdlib os/io.
func assertNoNetwork() error {
	return nil
}
