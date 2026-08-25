package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// Integrity refusal reason codes (Principle 1 — fail closed on corpus bytes).
const (
	ReasonArtifactHashMismatch = "artifact-hash-mismatch"
	ReasonArtifactAbsent       = "artifact-absent"
	ReasonArtifactUnhashed     = "artifact-unhashed"
)

// IntegrityError is a typed refusal before any scan work runs.
type IntegrityError struct {
	Reason   string
	Path     string
	Expected string
	Actual   string
}

func (e *IntegrityError) Error() string {
	switch e.Reason {
	case ReasonArtifactAbsent:
		return fmt.Sprintf("scan: %s: artifact absent at %s", e.Reason, e.Path)
	case ReasonArtifactUnhashed:
		return fmt.Sprintf("scan: %s: catalogue sha256 is null for %s", e.Reason, e.Path)
	case ReasonArtifactHashMismatch:
		return fmt.Sprintf("scan: %s: path %s expected %s got %s", e.Reason, e.Path, e.Expected, e.Actual)
	default:
		return fmt.Sprintf("scan: integrity refusal %s: %s", e.Reason, e.Path)
	}
}

// IsIntegrityError reports whether err is (or wraps) an IntegrityError.
func IsIntegrityError(err error) bool {
	var ie *IntegrityError
	return errors.As(err, &ie)
}

// IntegrityErrorOf returns the *IntegrityError if present.
func IntegrityErrorOf(err error) *IntegrityError {
	var ie *IntegrityError
	if errors.As(err, &ie) {
		return ie
	}
	return nil
}

// IntegrityExpectation enables fail-closed catalogue hash checks.
// When NullSHA256 is true, verification refuses with artifact-unhashed
// (catalogue sha256 was null). Otherwise Expected must match on-disk bytes.
type IntegrityExpectation struct {
	NullSHA256 bool
	Expected   string
}

// SHA256File returns the hex SHA-256 of a regular file.
func SHA256File(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is the caller-supplied artifact path under analysis
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SHA256Dir returns a deterministic hash of a directory tree:
// for each file in sorted relative-path order, update with path\0 + fileHash\0.
// Matches the RP-6 corpus cataloger algorithm.
func SHA256Dir(root string) (string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(files)
	h := sha256.New()
	for _, path := range files {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return "", err
		}
		rel = filepath.ToSlash(rel)
		fh, err := SHA256File(path)
		if err != nil {
			return "", err
		}
		_, _ = h.Write([]byte(rel))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(fh))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SHA256Path hashes a file or directory (directory uses SHA256Dir).
func SHA256Path(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if fi.IsDir() {
		return SHA256Dir(path)
	}
	return SHA256File(path)
}

// VerifyArtifactIntegrity fail-closes before scan work.
// path is the on-disk artifact (file or directory).
func VerifyArtifactIntegrity(path string, expect IntegrityExpectation) error {
	if expect.NullSHA256 {
		return &IntegrityError{Reason: ReasonArtifactUnhashed, Path: path}
	}
	if expect.Expected == "" {
		return &IntegrityError{Reason: ReasonArtifactUnhashed, Path: path}
	}
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &IntegrityError{Reason: ReasonArtifactAbsent, Path: path, Expected: expect.Expected}
		}
		return err
	}
	_ = fi
	actual, err := SHA256Path(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &IntegrityError{Reason: ReasonArtifactAbsent, Path: path, Expected: expect.Expected}
		}
		return err
	}
	if actual != expect.Expected {
		return &IntegrityError{
			Reason:   ReasonArtifactHashMismatch,
			Path:     path,
			Expected: expect.Expected,
			Actual:   actual,
		}
	}
	return nil
}

// IntegrityRefusalReport builds a scan summary for an integrity refusal
// (no binaries scanned; refusal counts by typed reason).
func IntegrityRefusalReport(err *IntegrityError) Report {
	r := Report{
		ArtifactDescription: SanitizeForTerminal(err.Path),
		NotAffectedByJust:   map[string]int{},
		RefusedByReason:     map[string]int{err.Reason: 1},
		RefusedTotal:        1,
		IntegrityRefusals:   map[string]int{err.Reason: 1},
		Success:             false,
	}
	return r
}
