package manifestderive

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gautamtalksdev/lading/internal/manifest"
	"gopkg.in/yaml.v3"
)

var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// ProposeInput is contributor-supplied metadata for one CVE entry.
type ProposeInput struct {
	Component            string
	CVE                  string
	FixCommit            string
	Symbols              []string
	EnclosingFunctions   []string
	AffectedVersions     []string
	Derivation           string
	Notes                string
	Verification         string
	FixturePath          string
	BuildRecipePath      string
	ContributorGitHub    string
}

// ProposeOptions control output locations.
type ProposeOptions struct {
	ManifestDir  string
	ProposalRoot string // default .lading/proposals
	Ecosystem    string // default native
	OpenTemplate bool   // try xdg-open / open on PR template
}

// ProposeResult paths written for the contributor.
type ProposeResult struct {
	CandidatePath string
	ProposalDir   string
	PRTemplatePath string
}

// Propose scaffolds a probable-only candidate YAML and a pre-filled PR template.
// It never writes under manifest/components/ and never sets definitive.
func Propose(in ProposeInput, opt ProposeOptions) (*ProposeResult, error) {
	if err := validateProposeInput(in); err != nil {
		return nil, err
	}
	if opt.ManifestDir == "" {
		return nil, fmt.Errorf("propose: ManifestDir required")
	}
	if opt.Ecosystem == "" {
		opt.Ecosystem = "native"
	}
	if opt.ProposalRoot == "" {
		opt.ProposalRoot = filepath.Join(".lading", "proposals")
	}

	verBytes, err := os.ReadFile(filepath.Join(opt.ManifestDir, "VERSION")) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("propose: read VERSION: %w", err)
	}
	manifestVer := strings.TrimSpace(string(verBytes))

	comp, err := loadComponentShell(opt.ManifestDir, opt.Ecosystem, in.Component)
	if err != nil {
		return nil, err
	}

	if in.Derivation == "" {
		in.Derivation = string(manifest.DerivationPatchTouched)
	}

	symbols := in.Symbols
	if len(symbols) == 0 {
		return nil, fmt.Errorf("propose: at least one --symbol required")
	}

	vs := make([]candidateSymbol, 0, len(symbols))
	for _, name := range symbols {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		vs = append(vs, candidateSymbol{
			Name:       name,
			Confidence: string(manifest.ConfidenceProbable),
			Provenance: candidateProvenance{
				UpstreamFixCommit: strings.TrimSpace(in.FixCommit),
				Derivation:        in.Derivation,
			},
		})
	}

	doc := candidateDoc{
		Component: comp,
		Meta: candidateMeta{
			Status:    "candidate",
			Generated: time.Now().UTC().Format(time.RFC3339),
			Note:      "CONTRIBUTOR PROPOSAL — confidence probable until maintainer promote",
		},
		Entries: []candidateEntry{{
			CVE:               strings.ToUpper(strings.TrimSpace(in.CVE)),
			AffectedVersions:  append([]string(nil), in.AffectedVersions...),
			VulnerableSymbols: vs,
			Notes:             strings.TrimSpace(in.Notes),
			ManifestVersion:   manifestVer,
		}},
	}

	candDir := filepath.Join(opt.ManifestDir, "candidates", opt.Ecosystem)
	if err := os.MkdirAll(candDir, 0o750); err != nil {
		return nil, err
	}
	slug := slugCVE(in.CVE)
	candidatePath := filepath.Join(candDir, in.Component+"-"+slug+".yaml")
	if err := WriteCandidate(candidatePath, &doc); err != nil {
		return nil, err
	}

	proposalDir := filepath.Join(opt.ProposalRoot, in.Component+"-"+slug)
	if err := os.MkdirAll(proposalDir, 0o750); err != nil {
		return nil, err
	}

	prPath := filepath.Join(proposalDir, "PULL_REQUEST.md")
	if err := os.WriteFile(prPath, []byte(renderPRTemplate(in, comp, candidatePath)), 0o644); err != nil {
		return nil, err
	}

	checklistPath := filepath.Join(proposalDir, "CHECKLIST.md")
	if err := os.WriteFile(checklistPath, []byte(proposeChecklist), 0o644); err != nil {
		return nil, err
	}

	res := &ProposeResult{
		CandidatePath:  candidatePath,
		ProposalDir:    proposalDir,
		PRTemplatePath: prPath,
	}

	if opt.OpenTemplate {
		openFile(prPath)
	}
	return res, nil
}

func validateProposeInput(in ProposeInput) error {
	if strings.TrimSpace(in.Component) == "" {
		return fmt.Errorf("propose: component name required")
	}
	cve := strings.ToUpper(strings.TrimSpace(in.CVE))
	if !cvePattern.MatchString(cve) {
		return fmt.Errorf("propose: cve must match CVE-YYYY-NNNN+")
	}
	if strings.TrimSpace(in.FixCommit) == "" || !strings.HasPrefix(in.FixCommit, "http") {
		return fmt.Errorf("propose: --fix-commit must be an https:// upstream fix commit URL")
	}
	if len(in.AffectedVersions) == 0 {
		return fmt.Errorf("propose: at least one --affected-version required")
	}
	if strings.TrimSpace(in.Verification) == "" {
		return fmt.Errorf("propose: --verification required (how you confirmed symbols in a binary)")
	}
	if strings.TrimSpace(in.FixturePath) == "" && strings.TrimSpace(in.BuildRecipePath) == "" {
		return fmt.Errorf("propose: --fixture or --build-recipe required")
	}
	return nil
}

func loadComponentShell(manifestDir, ecosystem, name string) (candidateComponent, error) {
	path := filepath.Join(manifestDir, "components", ecosystem, name+".yaml")
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			return candidateComponent{}, fmt.Errorf(
				"propose: no manifest/components/%s/%s.yaml — add component shell in a prior PR or extend propose flags",
				ecosystem, name,
			)
		}
		return candidateComponent{}, err
	}
	var doc struct {
		Component candidateComponent `yaml:"component"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return candidateComponent{}, fmt.Errorf("propose: parse component: %w", err)
	}
	if doc.Component.Name == "" {
		doc.Component.Name = name
	}
	if doc.Component.Ecosystem == "" {
		doc.Component.Ecosystem = ecosystem
	}
	return doc.Component, nil
}

func slugCVE(cve string) string {
	return strings.ToLower(strings.TrimSpace(cve))
}

const proposeChecklist = `# Manifest contribution checklist

- [ ] Candidate YAML under manifest/candidates/ only (never manifest/components/)
- [ ] confidence: probable on every vulnerable_symbols entry
- [ ] upstream_fix_commit URL opens in browser and matches the fix
- [ ] Enclosing functions listed in PR template match the patch
- [ ] Test fixture binary OR documented build recipe attached
- [ ] bash scripts/validate-manifest-candidates.sh passes locally
- [ ] Do not ask maintainer to set definitive — they promote after review
`

func renderPRTemplate(in ProposeInput, comp candidateComponent, candidatePath string) string {
	encFuncs := strings.Join(in.EnclosingFunctions, ", ")
	if encFuncs == "" {
		encFuncs = strings.Join(in.Symbols, ", ")
	}
	fixture := in.FixturePath
	if fixture == "" {
		fixture = in.BuildRecipePath + " (build recipe — no prebuilt binary)"
	}
	gh := in.ContributorGitHub
	if gh == "" {
		gh = "<your-github-handle>"
	}

	var b strings.Builder
	b.WriteString("## Manifest entry proposal (DATA ONLY)\n\n")
	b.WriteString("> Use GitHub PR template **manifest-entry** if available. This file is generated by\n")
	b.WriteString("> `lading manifest propose`.\n\n")
	fmt.Fprintf(&b, "### Component\n\n- **Name:** %s\n- **Ecosystem:** %s\n- **Candidate file:** %s\n\n",
		comp.Name, comp.Ecosystem, candidatePath)
	fmt.Fprintf(&b, "### CVE\n\n- **ID:** %s\n- **Affected versions:** %s\n\n",
		strings.ToUpper(in.CVE), strings.Join(in.AffectedVersions, ", "))
	fmt.Fprintf(&b, "### Upstream fix commit\n\n%s\n\n", in.FixCommit)
	fmt.Fprintf(&b, "### Enclosing / vulnerable functions\n\n%s\n\nSymbols in candidate YAML: %s\n\n",
		encFuncs, strings.Join(in.Symbols, ", "))
	fmt.Fprintf(&b, "### How I verified (required)\n\n%s\n\n", in.Verification)
	fmt.Fprintf(&b, "### Test fixture or build recipe (required)\n\n%s\n\n", fixture)
	fmt.Fprintf(&b, "### Contributor\n\n@%s\n\n---\n\n", gh)
	b.WriteString("## Maintainer merge (not contributor)\n\n")
	b.WriteString("- [ ] CI green (schema, provenance URL reachability, no definitive in PR)\n")
	b.WriteString("- [ ] Binary/fixture verification reproduced locally\n")
	fmt.Fprintf(&b, "- [ ] `lading manifest promote %s --reviewed-by <maintainer> --reviewed-at YYYY-MM-DD`\n", candidatePath)
	b.WriteString("- [ ] Label **manifest-reviewed** before any `manifest/components/` definitive merge\n")
	b.WriteString("- [ ] `lading manifest coverage && bash scripts/update-readme-coverage.sh`\n")
	return b.String()
}

func openFile(path string) {
	for _, args := range [][]string{
		{"xdg-open", path},
		{"open", path},
	} {
		if _, err := exec.LookPath(args[0]); err != nil {
			continue
		}
		cmd := exec.Command(args[0], args[1:]...) // #nosec G204
		_ = cmd.Start()
		return
	}
}

// WriteCandidate writes a candidate YAML, forcing probable-only symbols.
func WriteCandidate(path string, doc *candidateDoc) error {
	for i := range doc.Entries {
		for j := range doc.Entries[i].VulnerableSymbols {
			doc.Entries[i].VulnerableSymbols[j].Confidence = string(manifest.ConfidenceProbable)
			doc.Entries[i].VulnerableSymbols[j].Provenance.ReviewedBy = ""
			doc.Entries[i].VulnerableSymbols[j].Provenance.ReviewedAt = ""
		}
	}
	var b strings.Builder
	b.WriteString("# CANDIDATE — probable only; promote after maintainer review\n")
	b.WriteString("# Promote: lading manifest promote <this-file> --reviewed-by ... --reviewed-at ...\n")
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return err
	}
	_ = enc.Close()
	return os.WriteFile(path, []byte(b.String()), 0o600)
}
