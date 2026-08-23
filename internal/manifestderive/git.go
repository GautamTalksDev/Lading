package manifestderive

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Repo is a local git working tree used for commit diffs and blobs.
type Repo struct {
	Dir string
}

// EnsureClone clones url into cacheDir/<name> if missing, or fetches updates.
// Network is used only when the operator runs derive (explicit).
func EnsureClone(url, cacheDir, name string) (*Repo, error) {
	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		return nil, err
	}
	dir := filepath.Join(cacheDir, name)
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		cmd := exec.Command("git", "-C", dir, "fetch", "--tags", "--prune", "origin") // #nosec G204 -- fixed git argv
		if out, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("git fetch: %w\n%s", err, out)
		}
		return &Repo{Dir: dir}, nil
	}
	cmd := exec.Command("git", "clone", "--no-checkout", url, dir) // #nosec G204 -- operator-supplied URL
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("git clone %s: %w\n%s", url, err, out)
	}
	return &Repo{Dir: dir}, nil
}

// OpenRepo opens an existing local repository.
func OpenRepo(dir string) (*Repo, error) {
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return nil, fmt.Errorf("not a git repo: %s", dir)
	}
	return &Repo{Dir: dir}, nil
}

func (r *Repo) git(args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", r.Dir}, args...)...) // #nosec G204 -- git only
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String(), nil
}

// ShowPatch returns the unified diff for commit (no commit message).
func (r *Repo) ShowPatch(commit string) (string, error) {
	return r.git("show", "--format=", "--find-renames", commit)
}

// Blob returns file contents at rev:path (rev may be commit or commit^).
func (r *Repo) Blob(rev, path string) ([]byte, error) {
	out, err := r.git("show", rev+":"+path)
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

// ResolveCommit returns the full SHA for a commit-ish.
func (r *Repo) ResolveCommit(commit string) (string, error) {
	out, err := r.git("rev-parse", commit)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// Parent returns the first parent SHA of commit.
func (r *Repo) Parent(commit string) (string, error) {
	out, err := r.git("rev-parse", commit+"^")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// CommitURL builds a browseable fix-commit URL from a clone URL and SHA.
func CommitURL(repoURL, sha string) string {
	u := strings.TrimSuffix(strings.TrimSpace(repoURL), ".git")
	u = strings.TrimSuffix(u, "/")
	// Normalize git@github.com:org/repo → https://github.com/org/repo
	if strings.HasPrefix(u, "git@") {
		u = strings.Replace(u, ":", "/", 1)
		u = "https://" + strings.TrimPrefix(u, "git@")
	}
	if strings.Contains(u, "github.com") || strings.Contains(u, "gitlab.com") || strings.Contains(u, "bitbucket.org") {
		return u + "/commit/" + sha
	}
	return u + "/commit/" + sha
}
