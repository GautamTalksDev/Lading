//go:build cgo

package manifestderive_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gautamtalksdev/lading/internal/manifestderive"
)

func TestEnclosingFunctions_Basic(t *testing.T) {
	src := []byte(`
int helper(void) {
  return 1;
}

int inflate(int x) {
  int a = x;
  a++;
  return a;
}
`)
	got, err := manifestderive.EnclosingFunctions(src, []int{7, 8}, "inflate.c", "c")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "inflate" {
		t.Fatalf("got %v want [inflate]", got)
	}
	got, err = manifestderive.EnclosingFunctions(src, []int{3}, "inflate.c", "c")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "helper" {
		t.Fatalf("got %v want [helper]", got)
	}
}

func TestDerive_FixtureRepo(t *testing.T) {
	repoDir := buildFixtureRepo(t)
	outDir := t.TempDir()
	in := manifestderive.DeriveInput{
		Component: manifestderive.ComponentSpec{
			Name:            "fixturelib",
			Ecosystem:       "native",
			Repo:            "https://example.com/fixturelib.git",
			PURLs:           []string{"pkg:generic/fixturelib"},
			IdentitySymbols: []string{"vuln_parse"},
		},
		CVEs: []manifestderive.CVEFix{
			{
				ID:               "CVE-2099-0001",
				FixCommit:        "HEAD",
				AffectedVersions: []string{"0.1.0"},
			},
		},
	}
	res, err := manifestderive.Derive(in, manifestderive.DeriveOptions{
		LocalRepo:       repoDir,
		OutDir:          outDir,
		ManifestVersion: "0.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("entries=%d", len(res.Entries))
	}
	if res.Entries[0].Err != "" {
		t.Fatal(res.Entries[0].Err)
	}
	found := false
	for _, s := range res.Entries[0].Symbols {
		if s == "vuln_parse" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected vuln_parse in %v", res.Entries[0].Symbols)
	}

	raw, err := os.ReadFile(res.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if strings.Contains(body, "confidence: definitive") {
		t.Fatal("derive must never write confidence: definitive")
	}
	if !strings.Contains(body, "probable") {
		t.Fatal("expected probable confidence")
	}
	if !strings.Contains(body, "status: candidate") {
		t.Fatal("expected candidate meta")
	}
}

func buildFixtureRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...) // #nosec G204
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=fixture",
			"GIT_AUTHOR_EMAIL=fixture@example.com",
			"GIT_COMMITTER_NAME=fixture",
			"GIT_COMMITTER_EMAIL=fixture@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init")
	run("config", "user.email", "fixture@example.com")
	run("config", "user.name", "fixture")

	src1 := `int other(void) { return 0; }

int vuln_parse(const char *s) {
  return (int)s[0];
}
`
	if err := os.WriteFile(filepath.Join(dir, "parse.c"), []byte(src1), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", "parse.c")
	run("commit", "-m", "initial")

	src2 := `int other(void) { return 0; }

int vuln_parse(const char *s) {
  if (s == 0) return -1;
  return (int)s[0];
}
`
	if err := os.WriteFile(filepath.Join(dir, "parse.c"), []byte(src2), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", "parse.c")
	run("commit", "-m", "fix null deref in vuln_parse")
	return dir
}
