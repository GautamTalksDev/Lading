package manifestderive

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gautamtalksdev/lading/internal/manifest"
	"gopkg.in/yaml.v3"
)

// DeriveInput is the operator-supplied job for `lading manifest derive`.
type DeriveInput struct {
	Component ComponentSpec `yaml:"component"`
	CVEs      []CVEFix      `yaml:"cves"`
}

// ComponentSpec describes the component shell written into candidates.
type ComponentSpec struct {
	Name            string   `yaml:"name"`
	Ecosystem       string   `yaml:"ecosystem"`
	Repo            string   `yaml:"repo"` // git URL
	PURLs           []string `yaml:"purls"`
	IdentitySymbols []string `yaml:"identity_symbols"`
	IdentityStrings []string `yaml:"identity_strings,omitempty"`
}

// CVEFix pairs a CVE with its known upstream fix commit.
type CVEFix struct {
	ID               string   `yaml:"id"`
	FixCommit        string   `yaml:"fix_commit"`
	AffectedVersions []string `yaml:"affected_versions"`
	Notes            string   `yaml:"notes,omitempty"`
}

// DeriveOptions control clone cache and output paths.
type DeriveOptions struct {
	// CacheDir holds local clones (default: .lading/repos under cwd).
	CacheDir string
	// LocalRepo, if set, skips clone and uses this existing checkout.
	LocalRepo string
	// OutDir is typically manifest/candidates/<ecosystem>.
	OutDir string
	// ManifestVersion stamped on each entry (from manifest/VERSION).
	ManifestVersion string
}

// DeriveResult summarizes one derive run.
type DeriveResult struct {
	OutPath string
	Entries []DerivedEntry
}

// DerivedEntry is one CVE's derivation outcome.
type DerivedEntry struct {
	CVE     string
	Symbols []string
	Commit  string
	Err     string
}

// Derive clones (or opens) the component repo, walks each fix commit via
// local git, and writes a CANDIDATE YAML with confidence=probable only.
// It never writes to manifest/components/ and never sets definitive.
func Derive(in DeriveInput, opt DeriveOptions) (*DeriveResult, error) {
	if err := validateInput(in); err != nil {
		return nil, err
	}
	if opt.OutDir == "" {
		return nil, fmt.Errorf("derive: OutDir required")
	}
	if opt.ManifestVersion == "" {
		opt.ManifestVersion = "0.0.0"
	}

	var repo *Repo
	var err error
	if opt.LocalRepo != "" {
		repo, err = OpenRepo(opt.LocalRepo)
	} else {
		if opt.CacheDir == "" {
			opt.CacheDir = filepath.Join(".lading", "repos")
		}
		repo, err = EnsureClone(in.Component.Repo, opt.CacheDir, in.Component.Name)
	}
	if err != nil {
		return nil, err
	}

	doc := candidateDoc{
		Component: candidateComponent{
			Name:            in.Component.Name,
			Ecosystem:       in.Component.Ecosystem,
			PURLs:           in.Component.PURLs,
			IdentitySymbols: in.Component.IdentitySymbols,
			IdentityStrings: in.Component.IdentityStrings,
		},
		Meta: candidateMeta{
			Status:    "candidate",
			Generated: time.Now().UTC().Format(time.RFC3339),
			Repo:      in.Component.Repo,
			Note:      "AUTOMATION ONLY — confidence is probable; promote manually for definitive",
		},
	}

	result := &DeriveResult{}
	for _, cve := range in.CVEs {
		de, entry, derr := deriveOne(repo, in.Component.Repo, cve, opt.ManifestVersion)
		result.Entries = append(result.Entries, de)
		if derr != nil {
			de.Err = derr.Error()
			result.Entries[len(result.Entries)-1] = de
			continue
		}
		doc.Entries = append(doc.Entries, entry)
	}

	if err := os.MkdirAll(opt.OutDir, 0o750); err != nil {
		return nil, err
	}
	outPath := filepath.Join(opt.OutDir, in.Component.Name+".yaml")
	if err := WriteCandidate(outPath, &doc); err != nil {
		return nil, err
	}
	result.OutPath = outPath
	return result, nil
}

func validateInput(in DeriveInput) error {
	if in.Component.Name == "" {
		return fmt.Errorf("derive: component.name required")
	}
	if in.Component.Ecosystem == "" {
		return fmt.Errorf("derive: component.ecosystem required")
	}
	if in.Component.Repo == "" {
		return fmt.Errorf("derive: component.repo required")
	}
	if len(in.Component.PURLs) == 0 {
		return fmt.Errorf("derive: component.purls required")
	}
	if len(in.Component.IdentitySymbols) == 0 {
		return fmt.Errorf("derive: component.identity_symbols required")
	}
	if len(in.CVEs) == 0 {
		return fmt.Errorf("derive: cves required")
	}
	for i, c := range in.CVEs {
		if c.ID == "" || c.FixCommit == "" {
			return fmt.Errorf("derive: cves[%d] needs id and fix_commit", i)
		}
		if len(c.AffectedVersions) == 0 {
			return fmt.Errorf("derive: cves[%d] needs affected_versions", i)
		}
	}
	return nil
}

func deriveOne(repo *Repo, repoURL string, cve CVEFix, manifestVer string) (DerivedEntry, candidateEntry, error) {
	de := DerivedEntry{CVE: cve.ID, Commit: cve.FixCommit}
	sha, err := repo.ResolveCommit(cve.FixCommit)
	if err != nil {
		return de, candidateEntry{}, err
	}
	de.Commit = sha
	parent, err := repo.Parent(sha)
	if err != nil {
		return de, candidateEntry{}, fmt.Errorf("parent of %s: %w", sha, err)
	}
	patch, err := repo.ShowPatch(sha)
	if err != nil {
		return de, candidateEntry{}, err
	}
	changed, err := ParseUnifiedDiff(patch)
	if err != nil {
		return de, candidateEntry{}, err
	}

	// Group changed lines by path+side.
	type key struct {
		path string
		side Side
	}
	groups := map[key][]int{}
	for _, cl := range changed {
		if !isCFamily(cl.Path) {
			continue
		}
		k := key{path: cl.Path, side: cl.Side}
		groups[k] = append(groups[k], cl.Line)
	}

	nameSet := map[string]struct{}{}
	for k, lines := range groups {
		rev := sha
		if k.side == SideOld {
			rev = parent
		}
		src, err := repo.Blob(rev, k.path)
		if err != nil {
			// Renames / deletions can fail for one side; skip that side.
			continue
		}
		syms, err := EnclosingFunctions(src, uniqueInts(lines), k.path, "")
		if err != nil {
			return de, candidateEntry{}, fmt.Errorf("%s@%s: %w", k.path, rev[:12], err)
		}
		for _, s := range syms {
			nameSet[s] = struct{}{}
		}
	}

	names := make([]string, 0, len(nameSet))
	for n := range nameSet {
		names = append(names, n)
	}
	sort.Strings(names)
	de.Symbols = names

	commitURL := CommitURL(repoURL, sha)
	vs := make([]candidateSymbol, 0, len(names))
	for _, n := range names {
		vs = append(vs, candidateSymbol{
			Name:       n,
			Confidence: string(manifest.ConfidenceProbable), // ALWAYS probable
			Provenance: candidateProvenance{
				UpstreamFixCommit: commitURL,
				Derivation:        string(manifest.DerivationPatchTouched),
				// reviewed_* left empty — promote refuses without them.
			},
		})
	}

	entry := candidateEntry{
		CVE:               cve.ID,
		AffectedVersions:  append([]string(nil), cve.AffectedVersions...),
		VulnerableSymbols: vs,
		Notes:             cve.Notes,
		ManifestVersion:   manifestVer,
	}
	if len(vs) == 0 {
		entry.Notes = strings.TrimSpace(entry.Notes + "\n[derive] no enclosing C/C++ function definitions found for changed lines")
	}
	return de, entry, nil
}

func uniqueInts(in []int) []int {
	seen := map[int]struct{}{}
	var out []int
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

// LoadDeriveInput reads a derive job YAML.
func LoadDeriveInput(path string) (DeriveInput, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return DeriveInput{}, err
	}
	var in DeriveInput
	if err := yaml.Unmarshal(data, &in); err != nil {
		return DeriveInput{}, err
	}
	return in, nil
}

// --- candidate on-disk shape (not loaded by manifest.Load) ---

type candidateDoc struct {
	Component candidateComponent `yaml:"component"`
	Meta      candidateMeta      `yaml:"meta"`
	Entries   []candidateEntry   `yaml:"entries"`
}

type candidateMeta struct {
	Status    string `yaml:"status"`
	Generated string `yaml:"generated"`
	Repo      string `yaml:"repo"`
	Note      string `yaml:"note"`
}

type candidateComponent struct {
	Name            string   `yaml:"name"`
	Ecosystem       string   `yaml:"ecosystem"`
	PURLs           []string `yaml:"purls"`
	IdentitySymbols []string `yaml:"identity_symbols"`
	IdentityStrings []string `yaml:"identity_strings,omitempty"`
}

type candidateEntry struct {
	CVE               string             `yaml:"cve"`
	AffectedVersions  []string           `yaml:"affected_versions"`
	VulnerableSymbols []candidateSymbol  `yaml:"vulnerable_symbols"`
	Notes             string             `yaml:"notes,omitempty"`
	ManifestVersion   string             `yaml:"manifest_version"`
}

type candidateSymbol struct {
	Name       string              `yaml:"name"`
	Confidence string              `yaml:"confidence"`
	Provenance candidateProvenance `yaml:"provenance"`
}

type candidateProvenance struct {
	UpstreamFixCommit string `yaml:"upstream_fix_commit"`
	Derivation        string `yaml:"derivation"`
	ReviewedBy        string `yaml:"reviewed_by,omitempty"`
	ReviewedAt        string `yaml:"reviewed_at,omitempty"`
}
