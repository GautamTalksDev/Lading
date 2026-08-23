package decide_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestD05_ForbiddenJustificationsAbsent ensures prove-a-negative VEX
// justifications are not present in emitter/decision source (KT-2 / D05).
func TestD05_ForbiddenJustificationsAbsent(t *testing.T) {
	forbidden := []string{
		"vulnerable_code_not_in_execute_path",
		"vulnerable_code_cannot_be_controlled_by_adversary",
		"inline_mitigations_already_exist",
	}

	root := repoRoot(t)
	dirs := []string{
		"internal/decide",
		"internal/vexout",
		"internal/evidence",
		"cmd/lading",
	}

	for _, dir := range dirs {
		scanDir(t, filepath.Join(root, dir), forbidden)
	}
}

func scanDir(t *testing.T, dir string, forbidden []string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path) // #nosec G304
		if err != nil {
			return err
		}
		body := string(data)
		for _, f := range forbidden {
			if strings.Contains(body, f) {
				t.Fatalf("%s contains forbidden justification %q", path, f)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
