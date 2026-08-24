package manifest

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
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

// IdentityAlias maps a distro source package name to an upstream component PURL.
type IdentityAlias struct {
	SourceName             string      `json:"source_name"`
	Component              string      `json:"component"`
	Status                 AliasStatus `json:"status"`
	ProvenanceURL          string      `json:"provenance_url"`
	VerifiedArtifactSHA256 string      `json:"verified_artifact_sha256"`
	ReviewedBy             string      `json:"reviewed_by"`
	ReviewedAt             string      `json:"reviewed_at"`
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
		if _, dup := ia.aliases[key]; dup {
			return nil, fmt.Errorf("manifest: identity aliases: duplicate source_name %q", key)
		}
		ia.aliases[key] = a
	}
	return ia, nil
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
