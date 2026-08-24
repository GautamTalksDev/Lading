package manifest

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

//go:embed data/identity-aliases.json
var embeddedIdentityAliases []byte

// AliasStatus is the confidence of a source-name → component mapping.
type AliasStatus string

const (
	AliasStatusDefinitive AliasStatus = "definitive"
	AliasStatusProbable   AliasStatus = "probable"
)

// AliasProvenance is the §4.2 provenance block for an identity alias.
// Probable aliases may leave verification fields empty. Definitive aliases
// MUST populate every required field (validated by parseIdentityAliases).
type AliasProvenance struct {
	ArtifactSHA256          string   `json:"artifact_sha256"`
	Distro                  string   `json:"distro"`
	PackageName             string   `json:"package_name"`
	PackageVersion          string   `json:"package_version"`
	VerifiedAt              string   `json:"verified_at"`
	BinaryPath              string   `json:"binary_path"`
	IdentitySymbolsVerified []string `json:"identity_symbols_verified"`
	ExtractionMethod        string   `json:"extraction_method"`
	ReviewedBy              string   `json:"reviewed_by"`
	VerifiedBy              string   `json:"verified_by,omitempty"`
	URL                     string   `json:"url,omitempty"`
	Notes                   string   `json:"notes,omitempty"`
}

// IdentityAlias maps a distro source package name to an upstream component PURL.
type IdentityAlias struct {
	SourceName string          `json:"source_name"`
	Component  string          `json:"component"`
	Status     AliasStatus     `json:"status"`
	Provenance AliasProvenance `json:"provenance"`
}

var (
	sha256HexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	isoDateRe   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// extractionMethodsAllowed are the only values permitted for definitive aliases (§4.2).
var extractionMethodsAllowed = map[string]struct{}{
	"dpkg-deb-extract": {},
	"apk-extract":      {},
	"rpm2cpio-extract": {},
	"pacman-extract":   {},
}

// extractionMethodsDenied are explicitly insufficient for definitive (§4.1–§4.2).
var extractionMethodsDenied = map[string]struct{}{
	"debian-control":     {},
	"control-file":       {},
	"changelog":          {},
	"copyright":          {},
	"apkbuild":           {},
	"rpm-spec":           {},
	"source-tree":        {},
	"container-layer":    {},
	"oci-export":         {},
	"docker-save":        {},
	"grype-upstream":     {},
	"upstream-qualifier": {},
	"sbom-assertion":     {},
	"third-party":        {},
	"automated-scrape":   {},
}

// IdentityAliases is the loaded identity alias table (data, not code).
type IdentityAliases struct {
	aliases map[string]IdentityAlias
}

// LoadIdentityAliases reads identity-aliases.json from path. When path is empty,
// the embedded default seed file is used.
func LoadIdentityAliases(path string) (*IdentityAliases, error) {
	data := embeddedIdentityAliases
	if path != "" {
		var err error
		data, err = os.ReadFile(path) // #nosec G304
		if err != nil {
			return nil, fmt.Errorf("manifest: identity aliases: %w", err)
		}
	}
	return parseIdentityAliases(data)
}

func parseIdentityAliases(data []byte) (*IdentityAliases, error) {
	var doc struct {
		Aliases []IdentityAlias `json:"aliases"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("manifest: identity aliases: json: %w", err)
	}
	if len(doc.Aliases) == 0 {
		return nil, fmt.Errorf("manifest: identity aliases: empty aliases array")
	}

	ia := &IdentityAliases{aliases: map[string]IdentityAlias{}}
	for i, a := range doc.Aliases {
		key := strings.TrimSpace(a.SourceName)
		if key == "" {
			return nil, fmt.Errorf("manifest: identity aliases[%d]: empty source_name", i)
		}
		if strings.TrimSpace(a.Component) == "" {
			return nil, fmt.Errorf("manifest: identity aliases[%d]: empty component", i)
		}
		switch a.Status {
		case AliasStatusDefinitive, AliasStatusProbable:
		default:
			return nil, fmt.Errorf("manifest: identity aliases[%d]: status must be definitive|probable", i)
		}
		if err := validateAliasProvenance(a); err != nil {
			return nil, fmt.Errorf("manifest: identity aliases[%d] source_name=%q: %w", i, key, err)
		}
		if _, dup := ia.aliases[key]; dup {
			return nil, fmt.Errorf("manifest: identity aliases: duplicate source_name %q", key)
		}
		ia.aliases[key] = a
	}
	return ia, nil
}

// validateAliasProvenance enforces SPEC-IDENTITY §4.2–§4.3.
// Probable: no required verification fields.
// Definitive: complete provenance block or validation fails.
func validateAliasProvenance(a IdentityAlias) error {
	p := a.Provenance
	if a.Status != AliasStatusDefinitive {
		return nil
	}

	if !sha256HexRe.MatchString(strings.ToLower(strings.TrimSpace(p.ArtifactSHA256))) {
		return fmt.Errorf("definitive alias requires provenance.artifact_sha256 (64 hex)")
	}
	if strings.TrimSpace(p.Distro) == "" {
		return fmt.Errorf("definitive alias requires provenance.distro")
	}
	if strings.TrimSpace(p.PackageName) == "" {
		return fmt.Errorf("definitive alias requires provenance.package_name")
	}
	if strings.TrimSpace(p.PackageVersion) == "" {
		return fmt.Errorf("definitive alias requires provenance.package_version")
	}
	if !isoDateRe.MatchString(strings.TrimSpace(p.VerifiedAt)) {
		return fmt.Errorf("definitive alias requires provenance.verified_at (YYYY-MM-DD)")
	}
	if strings.TrimSpace(p.BinaryPath) == "" {
		return fmt.Errorf("definitive alias requires provenance.binary_path")
	}
	if len(p.IdentitySymbolsVerified) == 0 {
		return fmt.Errorf("definitive alias requires non-empty provenance.identity_symbols_verified")
	}
	for j, sym := range p.IdentitySymbolsVerified {
		if strings.TrimSpace(sym) == "" {
			return fmt.Errorf("definitive alias provenance.identity_symbols_verified[%d] is empty", j)
		}
	}
	if strings.TrimSpace(p.ReviewedBy) == "" {
		return fmt.Errorf("definitive alias requires provenance.reviewed_by")
	}

	method := strings.TrimSpace(p.ExtractionMethod)
	if method == "" {
		return fmt.Errorf("definitive alias requires provenance.extraction_method")
	}
	if _, denied := extractionMethodsDenied[method]; denied {
		return fmt.Errorf("definitive alias provenance.extraction_method %q is not evidence (SPEC-IDENTITY §4.1)", method)
	}
	if _, ok := extractionMethodsAllowed[method]; !ok {
		return fmt.Errorf("definitive alias provenance.extraction_method %q is not allowlisted", method)
	}
	return nil
}

// Lookup returns the alias for a distro source package name.
func (ia *IdentityAliases) Lookup(sourceName string) (IdentityAlias, bool) {
	if ia == nil {
		return IdentityAlias{}, false
	}
	a, ok := ia.aliases[strings.TrimSpace(sourceName)]
	return a, ok
}

// BuildIdentityAliasesForTest constructs an in-memory alias table for unit tests.
func BuildIdentityAliasesForTest(aliases ...IdentityAlias) (*IdentityAliases, error) {
	doc := struct {
		Aliases []IdentityAlias `json:"aliases"`
	}{Aliases: aliases}
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return parseIdentityAliases(data)
}

// SourceNames returns sorted source names (for tests and diagnostics).
func (ia *IdentityAliases) SourceNames() []string {
	if ia == nil {
		return nil
	}
	out := make([]string, 0, len(ia.aliases))
	for k := range ia.aliases {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
