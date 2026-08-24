package vexout

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gautamtalksdev/lading/internal/decide"
	"github.com/gautamtalksdev/lading/internal/evidence"
)

// LoadFromBundle reads an evidence bundle and builds emit input.
// When timestamp is empty, a deterministic RFC3339 UTC value is derived from
// bundle_id so identical bundles produce identical documents.
func LoadFromBundle(bundleDir, timestamp string) (DocumentInput, error) {
	bundleID, artifactSHA, stmts, err := readBundle(bundleDir)
	if err != nil {
		return DocumentInput{}, err
	}
	if timestamp == "" {
		timestamp = DeterministicTimestamp(bundleID)
	}
	return DocumentInput{
		BundleID:       bundleID,
		ArtifactSHA256: artifactSHA,
		Timestamp:      timestamp,
		Statements:     stmts,
	}, nil
}

// DeterministicTimestamp derives a stable RFC3339 UTC timestamp from bundleID.
func DeterministicTimestamp(bundleID string) string {
	sum := sha256.Sum256([]byte("lading-vex-ts\x00" + strings.ToLower(strings.TrimSpace(bundleID))))
	// Anchor at 2026-01-01T00:00:00Z plus a bounded offset for valid date-times.
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	offset := int64(sum[0])<<16 | int64(sum[1])<<8 | int64(sum[2])
	offset %= 365 * 24 * 3600
	return base.Add(time.Duration(offset) * time.Second).UTC().Format(time.RFC3339)
}

func readBundle(bundleDir string) (bundleID, artifactSHA string, stmts []Statement, err error) {
	manifestPath := filepath.Join(bundleDir, "MANIFEST.sha")
	data, err := os.ReadFile(manifestPath) // #nosec G304
	if err != nil {
		return "", "", nil, fmt.Errorf("vexout: read MANIFEST.sha: %w", err)
	}
	sum := sha256.Sum256(data)
	bundleID = hex.EncodeToString(sum[:])

	stmtRoot := filepath.Join(bundleDir, "statements")
	ents, err := os.ReadDir(stmtRoot)
	if err != nil {
		return "", "", nil, fmt.Errorf("vexout: statements: %w", err)
	}
	var ids []string
	for _, e := range ents {
		if e.IsDir() {
			ids = append(ids, e.Name())
		}
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return "", "", nil, fmt.Errorf("vexout: bundle contains no statements")
	}

	for _, id := range ids {
		stmt, inputs, err := loadStatement(filepath.Join(stmtRoot, id))
		if err != nil {
			return "", "", nil, err
		}
		if artifactSHA == "" {
			artifactSHA = inputs.ArtifactSHA256
		} else if !strings.EqualFold(artifactSHA, inputs.ArtifactSHA256) {
			return "", "", nil, fmt.Errorf("vexout: inconsistent artifact_sha256 in bundle")
		}
		stmts = append(stmts, Statement{
			StatementID:   id,
			CVE:           stmt.CVE,
			ComponentPURL: stmt.PURL,
			Result: decide.Result{
				Verdict:         decide.Verdict(strings.ToUpper(stmt.Verdict)),
				Justification:   decide.Justification(stmt.Justification),
				RuleID:          decide.RuleID(stmt.RuleID),
				ReasonCode:      decide.ReasonCode(stmt.ReasonCode),
				ManifestVersion: readManifestVersion(filepath.Join(stmtRoot, id)),
			},
		})
	}
	return bundleID, artifactSHA, stmts, nil
}

func loadStatement(dir string) (evidence.StatementRecord, evidence.InputsRecord, error) {
	var stmt evidence.StatementRecord
	var inputs evidence.InputsRecord
	stmtPath := filepath.Join(dir, "statement.json")
	inPath := filepath.Join(dir, "inputs.json")
	stmtData, err := os.ReadFile(stmtPath) // #nosec G304
	if err != nil {
		return stmt, inputs, err
	}
	if unmarshalErr := json.Unmarshal(stmtData, &stmt); unmarshalErr != nil {
		return stmt, inputs, unmarshalErr
	}
	inData, err := os.ReadFile(inPath) // #nosec G304
	if err != nil {
		return stmt, inputs, err
	}
	if err := json.Unmarshal(inData, &inputs); err != nil {
		return stmt, inputs, err
	}
	return stmt, inputs, nil
}

func readManifestVersion(stmtDir string) string {
	path := filepath.Join(stmtDir, "versions.json")
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return ""
	}
	var vers evidence.VersionsRecord
	if err := json.Unmarshal(data, &vers); err != nil {
		return ""
	}
	return vers.ManifestVersion
}
