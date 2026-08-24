// Package manifest loads and validates versioned Lading Manifest data.
//
// The Manifest is DATA under manifest/, never code. Load fails closed on any
// schema or structural error. confidence=probable entries are retained for
// reporting but must never drive not_affected (see Entry.AllowsNotAffected).
package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gautamtalksdev/lading/internal/inventory"
	"gopkg.in/yaml.v3"
)

// Confidence is the evidence strength for a vulnerable-symbol claim.
type Confidence string

const (
	ConfidenceDefinitive Confidence = "definitive"
	ConfidenceProbable   Confidence = "probable"
)

// Derivation describes how the vulnerable symbol was obtained.
type Derivation string

const (
	DerivationPatchTouched  Derivation = "patch-touched-function"
	DerivationAdvisoryNamed Derivation = "advisory-named"
	DerivationManual        Derivation = "manual"
)

// Provenance is required on every vulnerable symbol.
// Missing UpstreamFixCommit fails validation.
type Provenance struct {
	UpstreamFixCommit string     `json:"upstream_fix_commit" yaml:"upstream_fix_commit"`
	Derivation        Derivation `json:"derivation" yaml:"derivation"`
	ReviewedBy        string     `json:"reviewed_by" yaml:"reviewed_by"`
	ReviewedAt        string     `json:"reviewed_at" yaml:"reviewed_at"`
}

// VulnerableSymbol names a symbol tied to a CVE with graded confidence.
type VulnerableSymbol struct {
	Name       string     `json:"name" yaml:"name"`
	Confidence Confidence `json:"confidence" yaml:"confidence"`
	Provenance Provenance `json:"provenance" yaml:"provenance"`
}

// Entry is one CVE record inside a component file.
type Entry struct {
	CVE               string             `json:"cve" yaml:"cve"`
	AffectedVersions  []string           `json:"affected_versions" yaml:"affected_versions"`
	VulnerableSymbols []VulnerableSymbol `json:"vulnerable_symbols" yaml:"vulnerable_symbols"`
	Notes             string             `json:"notes,omitempty" yaml:"notes,omitempty"`
	ManifestVersion   string             `json:"manifest_version" yaml:"manifest_version"`
	ComponentName     string             `json:"-" yaml:"-"`
	SourceFile        string             `json:"-" yaml:"-"`
}

// AllowsNotAffected reports whether this entry may drive a not_affected
// verdict. Any probable-confidence symbol disallows it.
func (e Entry) AllowsNotAffected() bool {
	if len(e.VulnerableSymbols) == 0 {
		return false
	}
	for _, vs := range e.VulnerableSymbols {
		if vs.Confidence != ConfidenceDefinitive {
			return false
		}
	}
	return true
}

// ProvenanceStatus indicates whether a component's upstream_fix_commit URLs
// have been machine-verified as reachable (HTTP 200).
type ProvenanceStatus string

const (
	ProvenanceVerified   ProvenanceStatus = "verified"
	ProvenanceUnverified ProvenanceStatus = "unverified"
)

// Component describes one software component and its CVE entries.
type Component struct {
	ProvenanceStatus ProvenanceStatus `json:"provenance_status,omitempty" yaml:"provenance_status,omitempty"`
	Name             string           `json:"name" yaml:"name"`
	Ecosystem        string           `json:"ecosystem" yaml:"ecosystem"`
	PURLs            []string         `json:"purls" yaml:"purls"`
	IdentitySymbols  []string         `json:"identity_symbols" yaml:"identity_symbols"`
	IdentityStrings  []string         `json:"identity_strings,omitempty" yaml:"identity_strings,omitempty"`
	SourceFile       string           `json:"-" yaml:"-"`
	identityRegexps  []*regexp.Regexp
}

// IsVerified reports whether this component's provenance has been machine-checked.
func (c Component) IsVerified() bool {
	return c.ProvenanceStatus == ProvenanceVerified
}

// fileDoc is the on-disk document shape.
type fileDoc struct {
	Component Component `json:"component" yaml:"component"`
	Entries   []Entry   `json:"entries" yaml:"entries"`
}

// Match is one IdentifyComponent hit.
type Match struct {
	Component Component
	Reason    string // "symbol:<name>" or "string:<regex>"
}

// Manifest is the loaded, validated Manifest corpus.
type Manifest struct {
	semver      string
	contentHash string
	components  []Component
	byCVE       map[string][]Entry
}

// Version returns "semver+contentHash". It changes when any loaded data file changes.
func (m *Manifest) Version() string {
	if m == nil {
		return ""
	}
	return m.semver + "+" + m.contentHash
}

// ContentHash returns the SHA-256 hex digest of the deterministic corpus.
func (m *Manifest) ContentHash() string {
	if m == nil {
		return ""
	}
	return m.contentHash
}

// Semver returns the Manifest release semver from VERSION.
func (m *Manifest) Semver() string {
	if m == nil {
		return ""
	}
	return m.semver
}

// Components returns a copy of loaded components.
func (m *Manifest) Components() []Component {
	if m == nil {
		return nil
	}
	out := make([]Component, len(m.components))
	copy(out, m.components)
	return out
}

// LookupCVE returns all entries for a CVE ID (case-insensitive).
func (m *Manifest) LookupCVE(cve string) ([]Entry, bool) {
	if m == nil {
		return nil, false
	}
	key := strings.ToUpper(strings.TrimSpace(cve))
	ents, ok := m.byCVE[key]
	if !ok || len(ents) == 0 {
		return nil, false
	}
	out := make([]Entry, len(ents))
	copy(out, ents)
	return out, true
}

// IdentifyComponent returns Manifest components indicated by inv.
func (m *Manifest) IdentifyComponent(inv *inventory.Inventory) []Match {
	if m == nil || inv == nil {
		return nil
	}
	symSet := map[string]struct{}{}
	addSym := func(s inventory.Symbol) {
		if s.Normalized != "" {
			symSet[s.Normalized] = struct{}{}
		}
		if s.Raw != "" {
			symSet[s.Raw] = struct{}{}
		}
	}
	for _, s := range inv.DynSyms {
		addSym(s)
	}
	for _, s := range inv.SymTab {
		addSym(s)
	}

	var matches []Match
	for _, c := range m.components {
		hit := false
		for _, id := range c.IdentitySymbols {
			if _, ok := symSet[id]; ok {
				matches = append(matches, Match{Component: c, Reason: "symbol:" + id})
				hit = true
				break
			}
		}
		if hit {
			continue
		}
		for i, re := range c.identityRegexps {
			for _, rs := range inv.RoStrings {
				if re.MatchString(rs) {
					matches = append(matches, Match{
						Component: c,
						Reason:    "string:" + c.IdentityStrings[i],
					})
					hit = true
					break
				}
			}
			if hit {
				break
			}
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Component.Name < matches[j].Component.Name
	})
	return matches
}

// Load reads dir (typically "manifest/"), validates every component file
// against the JSON Schema rules, and returns a Manifest. Any error fails closed.
func Load(dir string) (*Manifest, error) {
	semverBytes, err := os.ReadFile(filepath.Join(dir, "VERSION")) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("manifest: read VERSION: %w", err)
	}
	semver := strings.TrimSpace(string(semverBytes))
	if semver == "" {
		return nil, fmt.Errorf("manifest: VERSION is empty")
	}

	schemaPath := filepath.Join(dir, "schema", "entry.schema.json")
	if _, err := os.Stat(schemaPath); err != nil {
		return nil, fmt.Errorf("manifest: schema: %w", err)
	}

	compRoot := filepath.Join(dir, "components")
	var files []string
	err = filepath.WalkDir(compRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".yaml", ".yml", ".json":
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("manifest: walk components: %w", err)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("manifest: no component files under %s", compRoot)
	}

	h := sha256.New()
	_, _ = h.Write([]byte(semver + "\n"))

	m := &Manifest{
		semver: semver,
		byCVE:  map[string][]Entry{},
	}

	for _, path := range files {
		data, err := os.ReadFile(path) // #nosec G304
		if err != nil {
			return nil, fmt.Errorf("manifest: read %s: %w", path, err)
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			rel = path
		}
		// Hash relative path so Version() is machine-independent.
		_, _ = h.Write([]byte(filepath.ToSlash(rel) + "\n"))
		_, _ = h.Write(data)
		_, _ = h.Write([]byte{0})

		doc, err := parseAndValidate(path, data)
		if err != nil {
			return nil, err
		}
		doc.Component.SourceFile = filepath.ToSlash(rel)
		if doc.Component.ProvenanceStatus == "" {
			doc.Component.ProvenanceStatus = ProvenanceUnverified
		}
		if err := compileIdentity(&doc.Component); err != nil {
			return nil, fmt.Errorf("manifest: %s: %w", path, err)
		}
		m.components = append(m.components, doc.Component)
		for i := range doc.Entries {
			e := doc.Entries[i]
			e.ComponentName = doc.Component.Name
			e.SourceFile = filepath.ToSlash(rel)
			key := strings.ToUpper(e.CVE)
			m.byCVE[key] = append(m.byCVE[key], e)
		}
	}

	m.contentHash = hex.EncodeToString(h.Sum(nil))
	return m, nil
}

func parseAndValidate(path string, data []byte) (*fileDoc, error) {
	var doc fileDoc
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("manifest: %s: json: %w", path, err)
		}
	default:
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("manifest: %s: yaml: %w", path, err)
		}
	}
	js, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("manifest: %s: remarshal: %w", path, err)
	}
	var generic any
	if err := json.Unmarshal(js, &generic); err != nil {
		return nil, fmt.Errorf("manifest: %s: %w", path, err)
	}
	if err := validateAgainstSchema(generic); err != nil {
		return nil, fmt.Errorf("manifest: %s: schema: %w", path, err)
	}
	return &doc, nil
}

func compileIdentity(c *Component) error {
	c.identityRegexps = c.identityRegexps[:0]
	for _, pat := range c.IdentityStrings {
		re, err := regexp.Compile(pat)
		if err != nil {
			return fmt.Errorf("identity_strings %q: %w", pat, err)
		}
		c.identityRegexps = append(c.identityRegexps, re)
	}
	return nil
}

func validateAgainstSchema(doc any) error {
	root, ok := doc.(map[string]any)
	if !ok {
		return fmt.Errorf("document must be an object")
	}
	comp, ok := root["component"].(map[string]any)
	if !ok {
		return fmt.Errorf("missing required property: component")
	}
	for _, k := range []string{"name", "ecosystem", "purls", "identity_symbols"} {
		if _, ok := comp[k]; !ok {
			return fmt.Errorf("component: missing required property: %s", k)
		}
	}
	if err := requireNonEmptyString(comp, "name"); err != nil {
		return fmt.Errorf("component: %w", err)
	}
	if err := requireNonEmptyString(comp, "ecosystem"); err != nil {
		return fmt.Errorf("component: %w", err)
	}
	if err := requireStringArray(comp, "purls", 1); err != nil {
		return fmt.Errorf("component: %w", err)
	}
	if err := requireStringArray(comp, "identity_symbols", 1); err != nil {
		return fmt.Errorf("component: %w", err)
	}
	if _, ok := comp["identity_strings"]; ok {
		if err := requireStringArray(comp, "identity_strings", 0); err != nil {
			return fmt.Errorf("component: %w", err)
		}
	}

	entries, ok := root["entries"].([]any)
	if !ok || len(entries) == 0 {
		return fmt.Errorf("missing or empty required property: entries")
	}
	cveRe := regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	dateRe := regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	for i, raw := range entries {
		e, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("entries[%d]: must be an object", i)
		}
		for _, k := range []string{"cve", "affected_versions", "vulnerable_symbols", "manifest_version"} {
			if _, ok := e[k]; !ok {
				return fmt.Errorf("entries[%d]: missing required property: %s", i, k)
			}
		}
		cve, _ := e["cve"].(string)
		if !cveRe.MatchString(cve) {
			return fmt.Errorf("entries[%d]: cve %q does not match CVE-YYYY-NNNN", i, cve)
		}
		if err := requireStringArray(e, "affected_versions", 1); err != nil {
			return fmt.Errorf("entries[%d]: %w", i, err)
		}
		if err := requireNonEmptyString(e, "manifest_version"); err != nil {
			return fmt.Errorf("entries[%d]: %w", i, err)
		}
		syms, ok := e["vulnerable_symbols"].([]any)
		if !ok || len(syms) == 0 {
			return fmt.Errorf("entries[%d]: vulnerable_symbols must be a non-empty array", i)
		}
		for j, sraw := range syms {
			s, ok := sraw.(map[string]any)
			if !ok {
				return fmt.Errorf("entries[%d].vulnerable_symbols[%d]: must be an object", i, j)
			}
			for _, k := range []string{"name", "confidence", "provenance"} {
				if _, ok := s[k]; !ok {
					return fmt.Errorf("entries[%d].vulnerable_symbols[%d]: missing required property: %s", i, j, k)
				}
			}
			if err := requireNonEmptyString(s, "name"); err != nil {
				return fmt.Errorf("entries[%d].vulnerable_symbols[%d]: %w", i, j, err)
			}
			conf, _ := s["confidence"].(string)
			if conf != string(ConfidenceDefinitive) && conf != string(ConfidenceProbable) {
				return fmt.Errorf("entries[%d].vulnerable_symbols[%d]: confidence must be definitive|probable", i, j)
			}
			prov, ok := s["provenance"].(map[string]any)
			if !ok {
				return fmt.Errorf("entries[%d].vulnerable_symbols[%d]: provenance must be an object", i, j)
			}
			url, _ := prov["upstream_fix_commit"].(string)
			if strings.TrimSpace(url) == "" {
				return fmt.Errorf("entries[%d].vulnerable_symbols[%d]: provenance.upstream_fix_commit is required", i, j)
			}
			if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
				return fmt.Errorf("entries[%d].vulnerable_symbols[%d]: provenance.upstream_fix_commit must be an http(s) URL", i, j)
			}
			der, _ := prov["derivation"].(string)
			switch Derivation(der) {
			case DerivationPatchTouched, DerivationAdvisoryNamed, DerivationManual:
			default:
				return fmt.Errorf("entries[%d].vulnerable_symbols[%d]: invalid derivation %q", i, j, der)
			}
			if err := requireNonEmptyString(prov, "reviewed_by"); err != nil {
				return fmt.Errorf("entries[%d].vulnerable_symbols[%d].provenance: %w", i, j, err)
			}
			reviewedAt, _ := prov["reviewed_at"].(string)
			if !dateRe.MatchString(reviewedAt) {
				return fmt.Errorf("entries[%d].vulnerable_symbols[%d]: reviewed_at must be YYYY-MM-DD", i, j)
			}
			if _, err := time.Parse("2006-01-02", reviewedAt); err != nil {
				return fmt.Errorf("entries[%d].vulnerable_symbols[%d]: reviewed_at: %w", i, j, err)
			}
		}
	}
	return nil
}

func requireNonEmptyString(m map[string]any, key string) error {
	v, ok := m[key].(string)
	if !ok || strings.TrimSpace(v) == "" {
		return fmt.Errorf("%s must be a non-empty string", key)
	}
	return nil
}

func requireStringArray(m map[string]any, key string, min int) error {
	arr, ok := m[key].([]any)
	if !ok {
		return fmt.Errorf("%s must be an array", key)
	}
	if len(arr) < min {
		return fmt.Errorf("%s must have at least %d item(s)", key, min)
	}
	for i, v := range arr {
		s, ok := v.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return fmt.Errorf("%s[%d] must be a non-empty string", key, i)
		}
	}
	return nil
}
