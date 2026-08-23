package manifestderive

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gautamtalksdev/lading/internal/manifest"
	"gopkg.in/yaml.v3"
)

// PromoteOptions are required human attestation fields.
type PromoteOptions struct {
	ReviewedBy string
	ReviewedAt string // YYYY-MM-DD
	// ComponentsDir is typically manifest/components.
	ComponentsDir string
	// ManifestVersion overrides entry manifest_version when non-empty.
	ManifestVersion string
}

// Promote copies a candidate file into manifest/components/ as definitive,
// after the operator supplies reviewed_by and reviewed_at.
// Refuses if those fields are missing. This is the ONLY path that may write
// confidence: definitive.
func Promote(candidatePath string, opt PromoteOptions) (string, error) {
	if strings.TrimSpace(opt.ReviewedBy) == "" {
		return "", fmt.Errorf("promote: --reviewed-by is required (manual attestation)")
	}
	if strings.TrimSpace(opt.ReviewedAt) == "" {
		return "", fmt.Errorf("promote: --reviewed-at is required (YYYY-MM-DD)")
	}
	if _, err := time.Parse("2006-01-02", opt.ReviewedAt); err != nil {
		return "", fmt.Errorf("promote: reviewed-at must be YYYY-MM-DD: %w", err)
	}
	if opt.ComponentsDir == "" {
		return "", fmt.Errorf("promote: ComponentsDir required")
	}

	abs, err := filepath.Abs(candidatePath)
	if err != nil {
		return "", err
	}
	// Refuse promoting from components/ (already promoted) or unknown trees.
	if strings.Contains(filepath.ToSlash(abs), "/manifest/components/") {
		return "", fmt.Errorf("promote: refuse to read from manifest/components/ (already published)")
	}

	data, err := os.ReadFile(candidatePath) // #nosec G304
	if err != nil {
		return "", err
	}
	var doc candidateDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return "", fmt.Errorf("promote: parse: %w", err)
	}
	if doc.Component.Name == "" || doc.Component.Ecosystem == "" {
		return "", fmt.Errorf("promote: component name/ecosystem required")
	}
	if len(doc.Entries) == 0 {
		return "", fmt.Errorf("promote: no entries in candidate")
	}

	for i := range doc.Entries {
		if len(doc.Entries[i].VulnerableSymbols) == 0 {
			return "", fmt.Errorf("promote: %s has no vulnerable_symbols — nothing to promote", doc.Entries[i].CVE)
		}
		for j := range doc.Entries[i].VulnerableSymbols {
			sym := &doc.Entries[i].VulnerableSymbols[j]
			if sym.Name == "" {
				return "", fmt.Errorf("promote: empty symbol name on %s", doc.Entries[i].CVE)
			}
			if sym.Provenance.UpstreamFixCommit == "" {
				return "", fmt.Errorf("promote: %s/%s missing upstream_fix_commit", doc.Entries[i].CVE, sym.Name)
			}
			// Manual step: elevate to definitive with attestation.
			sym.Confidence = string(manifest.ConfidenceDefinitive)
			sym.Provenance.ReviewedBy = opt.ReviewedBy
			sym.Provenance.ReviewedAt = opt.ReviewedAt
			if sym.Provenance.Derivation == "" {
				sym.Provenance.Derivation = string(manifest.DerivationPatchTouched)
			}
		}
		if opt.ManifestVersion != "" {
			doc.Entries[i].ManifestVersion = opt.ManifestVersion
		}
		if doc.Entries[i].ManifestVersion == "" {
			return "", fmt.Errorf("promote: %s missing manifest_version", doc.Entries[i].CVE)
		}
	}

	outDir := filepath.Join(opt.ComponentsDir, doc.Component.Ecosystem)
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return "", err
	}
	outPath := filepath.Join(outDir, doc.Component.Name+".yaml")

	pub := struct {
		Component candidateComponent `yaml:"component"`
		Entries   []candidateEntry   `yaml:"entries"`
	}{
		Component: doc.Component,
		Entries:   doc.Entries,
	}

	var b strings.Builder
	b.WriteString("# Promoted from candidate — reviewed_by=" + opt.ReviewedBy + " reviewed_at=" + opt.ReviewedAt + "\n")
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(&pub); err != nil {
		return "", err
	}
	_ = enc.Close()

	if err := os.WriteFile(outPath, []byte(b.String()), 0o600); err != nil {
		return "", err
	}
	return outPath, nil
}
