//go:build cgo

package manifestderive_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gautamtalksdev/lading/internal/manifestderive"
)

type encloseCase struct {
	ID               string   `json:"id"`
	Commit           string   `json:"commit"`
	Note             string   `json:"note"`
	Symbols          []string `json:"symbols"`
	ExpectedSymbols  []string `json:"expected_symbols"`
	HandChecked      bool     `json:"hand_checked"`
	Files            []string `json:"files"`
}

func TestEnclosingFunctions_HandCheckedRealCommits(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "manifestderive", "enclose")
	raw, err := os.ReadFile(filepath.Join(root, "cases.json")) // #nosec G304
	if err != nil {
		t.Fatal(err)
	}
	var cases []encloseCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, tc := range cases {
		if !tc.HandChecked {
			continue
		}
		checked++
		tc := tc
		t.Run(tc.ID, func(t *testing.T) {
			got := map[string]struct{}{}
			caseDir := filepath.Join(root, tc.ID)
			for _, f := range tc.Files {
				src, err := os.ReadFile(filepath.Join(caseDir, f)) // #nosec G304
				if err != nil {
					t.Fatal(err)
				}
				metaRaw, err := os.ReadFile(filepath.Join(caseDir, f+".meta")) // #nosec G304
				if err != nil {
					t.Fatal(err)
				}
				path, lines := parseMeta(t, string(metaRaw))
				syms, err := manifestderive.EnclosingFunctions(src, lines, path, "")
				if err != nil {
					t.Fatal(err)
				}
				for _, s := range syms {
					got[s] = struct{}{}
				}
			}
			for _, want := range tc.ExpectedSymbols {
				if _, ok := got[want]; !ok {
					t.Fatalf("missing expected symbol %q; got %v (commit %s: %s)",
						want, keys(got), tc.Commit, tc.Note)
				}
			}
		})
	}
	if checked < 20 {
		t.Fatalf("need ≥20 hand-checked cases, got %d", checked)
	}
	t.Logf("hand-checked real fix commits: %d", checked)
}

func parseMeta(t *testing.T, meta string) (path string, lines []int) {
	t.Helper()
	for _, line := range strings.Split(meta, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "path="):
			path = strings.TrimPrefix(line, "path=")
		case strings.HasPrefix(line, "lines="):
			for _, p := range strings.Split(strings.TrimPrefix(line, "lines="), ",") {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				n, err := strconv.Atoi(p)
				if err != nil {
					t.Fatal(err)
				}
				lines = append(lines, n)
			}
		}
	}
	if path == "" || len(lines) == 0 {
		t.Fatalf("bad meta: %q", meta)
	}
	return path, lines
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
