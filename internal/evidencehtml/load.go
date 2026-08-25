// Package evidencehtml renders a self-contained, deterministic HTML evidence pack
// from on-disk scan outputs (decisions.jsonl, grype.json, evidence-bundle/).
package evidencehtml

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gautamtalksdev/lading/internal/decide"
	"github.com/gautamtalksdev/lading/internal/evidence"
	"github.com/gautamtalksdev/lading/internal/manifest"
	"github.com/gautamtalksdev/lading/internal/purl"
	"gopkg.in/yaml.v3"
)

const FormatVersion = "evidence-html-v1"

// Options selects inputs for one evidence pack.
type Options struct {
	ArtifactPath string
	ScanDir      string
	CatalogPath  string
	CatalogID    string
	ManifestDir  string
	Timestamp    string
}

// Pack is the fully loaded, sorted evidence document model.
type Pack struct {
	FormatVersion string
	Timestamp     string
	Artifact      ArtifactIdentity
	Tools         ToolVersions
	Summary       ScanSummary
	Rows          []Row
	Rederivation  string
	Limitations   []string
}

// ArtifactIdentity is catalogue / on-disk artifact metadata (untrusted input).
type ArtifactIdentity struct {
	ID        string
	Name      string
	Class     string
	SHA256    string
	SourceURL string
	FetchedAt string
	ScanPath  string
}

// ToolVersions records scanner and engine versions embedded in the pack.
type ToolVersions struct {
	LadingFormat    string
	DecideVersion   string
	ManifestVersion string
	GrypeName       string
	GrypeVersion    string
	GrypeDBBuilt    string
}

// ScanSummary is roll-up counts from scan-summary.json.
type ScanSummary struct {
	CVEsIn          int
	NotAffected     int
	Affected        int
	Refused         int
	BinariesScanned int
}

// Row is one CVE decision row in the pack.
type Row struct {
	CVE                   string
	ComponentPURL         string
	Verdict               string
	RuleID                string
	ReasonCode            string
	Justification         string
	Component             string
	EvidenceKind          string
	SymbolsAbsent         []string
	SymbolsPresent        []string
	ComponentIdentified   bool
	ManifestComponent     string
	ManifestProvenance    string
	IdentitySource        string
	IdentityMappingStatus string
	IdentityComponent     string
	BundleStatementID     string
}

// Load reads scan outputs and builds a deterministic Pack.
func Load(opts Options) (Pack, error) {
	if strings.TrimSpace(opts.ScanDir) == "" {
		return Pack{}, fmt.Errorf("evidencehtml: scan-dir required")
	}
	if strings.TrimSpace(opts.Timestamp) == "" {
		return Pack{}, fmt.Errorf("evidencehtml: timestamp required (RFC3339 UTC)")
	}
	if strings.TrimSpace(opts.ArtifactPath) == "" {
		return Pack{}, fmt.Errorf("evidencehtml: artifact path required")
	}

	scanDir, err := filepath.Abs(opts.ScanDir)
	if err != nil {
		return Pack{}, err
	}
	artifactDisplay := filepath.ToSlash(strings.TrimSpace(opts.ArtifactPath))
	scanDisplay := filepath.ToSlash(strings.TrimSpace(opts.ScanDir))

	aliases, err := manifest.LoadIdentityAliases("")
	if err != nil {
		return Pack{}, err
	}

	grype, err := loadGrypeMeta(filepath.Join(scanDir, "grype.json"))
	if err != nil {
		return Pack{}, err
	}
	summary, err := loadScanSummary(filepath.Join(scanDir, "scan-summary.json"))
	if err != nil {
		return Pack{}, err
	}
	decisions, err := loadDecisions(filepath.Join(scanDir, "decisions.jsonl"))
	if err != nil {
		return Pack{}, err
	}

	meta := lookupCatalog(opts.CatalogPath, opts.CatalogID, artifactDisplay)
	meta.ScanPath = artifactDisplay

	var rows []Row
	for _, d := range decisions {
		row := Row{
			CVE:           strings.ToUpper(strings.TrimSpace(d.CVE)),
			ComponentPURL: d.ComponentPURL,
			Verdict:       strings.ToUpper(strings.TrimSpace(d.Verdict)),
			RuleID:        d.RuleID,
			ReasonCode:    d.ReasonCode,
			Justification: d.Justification,
			Component:     d.Component,
		}
		if d.StatementID != "" {
			row.BundleStatementID = d.StatementID
			stmtRoot := filepath.Join(scanDir, "evidence-bundle", "statements")
			stmtDir, confErr := confinedDir(stmtRoot, d.StatementID)
			if confErr != nil {
				return Pack{}, fmt.Errorf("evidencehtml: %s: %w", d.CVE, confErr)
			}
			if err := enrichFromBundle(stmtDir, &row); err != nil && !os.IsNotExist(err) {
				return Pack{}, fmt.Errorf("evidencehtml: %s: %w", d.CVE, err)
			}
		}
		row.IdentitySource, row.IdentityMappingStatus, row.IdentityComponent = identityInfo(d.ComponentPURL, aliases)
		if row.Verdict == "NOT_AFFECTED" {
			row.EvidenceKind = evidenceKind(row)
		}
		rows = append(rows, row)
	}
	sortRows(rows)

	manifestVer := "0.2.0"
	if p := opts.ManifestDir; p != "" {
		verPath := filepath.Join(p, "VERSION")
		//nolint:gosec // G304: p is operator --manifest; basename VERSION is a literal
		if data, err := os.ReadFile(verPath); err == nil {
			manifestVer = strings.TrimSpace(string(data))
		}
	}

	return Pack{
		FormatVersion: FormatVersion,
		Timestamp:     opts.Timestamp,
		Artifact:      meta,
		Tools: ToolVersions{
			LadingFormat:    FormatVersion,
			DecideVersion:   decide.ToolVersion,
			ManifestVersion: manifestVer,
			GrypeName:       grype.Name,
			GrypeVersion:    grype.Version,
			GrypeDBBuilt:    grype.DBBuilt,
		},
		Summary:      summary,
		Rows:         rows,
		Rederivation: buildRederivation(artifactDisplay, scanDisplay, opts),
		Limitations:  defaultLimitations(),
	}, nil
}

// confinedDir joins root/elem and refuses anything that is not a single
// path element under root (statement_id comes from scan JSON).
func confinedDir(root, elem string) (string, error) {
	if strings.TrimSpace(elem) == "" {
		return "", fmt.Errorf("evidencehtml: empty path element")
	}
	if elem == "." || elem == ".." || strings.Contains(elem, "..") || elem != filepath.Base(elem) {
		return "", fmt.Errorf("evidencehtml: path element %q escapes %s", elem, root)
	}
	joined := filepath.Join(root, elem)
	rel, err := filepath.Rel(root, joined)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("evidencehtml: path element %q escapes %s", elem, root)
	}
	return joined, nil
}

func sortRows(rows []Row) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CVE != rows[j].CVE {
			return rows[i].CVE < rows[j].CVE
		}
		return rows[i].ComponentPURL < rows[j].ComponentPURL
	})
}

type decisionLine struct {
	CVE           string `json:"cve"`
	ComponentPURL string `json:"component_purl"`
	Verdict       string `json:"verdict"`
	RuleID        string `json:"rule_id"`
	ReasonCode    string `json:"reason_code,omitempty"`
	Justification string `json:"justification,omitempty"`
	Component     string `json:"component,omitempty"`
	StatementID   string `json:"statement_id"`
}

func loadDecisions(path string) ([]decisionLine, error) {
	//nolint:gosec // G304: path is Join(Abs(scanDir), "decisions.jsonl"); basename is a literal
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read decisions: %w", err)
	}
	var out []decisionLine
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var d decisionLine
		if err := json.Unmarshal([]byte(line), &d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

type grypeMeta struct {
	Name    string
	Version string
	DBBuilt string
}

func loadGrypeMeta(path string) (grypeMeta, error) {
	//nolint:gosec // G304: path is Join(Abs(scanDir), "grype.json"); basename is a literal
	data, err := os.ReadFile(path)
	if err != nil {
		return grypeMeta{}, fmt.Errorf("read grype.json: %w", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return grypeMeta{}, err
	}
	meta := grypeMeta{}
	if desc, ok := doc["descriptor"].(map[string]any); ok {
		meta.Name, _ = desc["name"].(string)
		meta.Version, _ = desc["version"].(string)
		for _, key := range []string{"db", "database"} {
			if db, ok := desc[key].(map[string]any); ok {
				for _, tk := range []string{"built", "built_at", "timestamp", "schema"} {
					if v, ok := db[tk].(string); ok && v != "" {
						meta.DBBuilt = v
						break
					}
				}
			}
		}
	}
	return meta, nil
}

func loadScanSummary(path string) (ScanSummary, error) {
	//nolint:gosec // G304: path is Join(Abs(scanDir), "scan-summary.json"); basename is a literal
	data, err := os.ReadFile(path)
	if err != nil {
		return ScanSummary{}, fmt.Errorf("read scan-summary.json: %w", err)
	}
	var s struct {
		CVEsIn          int `json:"cves_in"`
		NotAffected     int `json:"not_affected"`
		Affected        int `json:"affected"`
		Refused         int `json:"refused"`
		BinariesScanned int `json:"binaries_scanned"`
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return ScanSummary{}, err
	}
	return ScanSummary{
		CVEsIn:          s.CVEsIn,
		NotAffected:     s.NotAffected,
		Affected:        s.Affected,
		Refused:         s.Refused,
		BinariesScanned: s.BinariesScanned,
	}, nil
}

func enrichFromBundle(stmtDir string, row *Row) error {
	var obs evidence.ObservationsRecord
	var slice manifest.Slice

	readJSON := func(name string, dest any) error {
		if name != filepath.Base(name) || strings.Contains(name, "..") {
			return fmt.Errorf("evidencehtml: invalid bundle file %q", name)
		}
		p := filepath.Join(stmtDir, name)
		//nolint:gosec // G304: stmtDir confined by confinedDir; name is a literal basename
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return json.Unmarshal(data, dest)
	}
	if err := readJSON("observations.json", &obs); err != nil {
		return err
	}
	if err := readJSON("manifest-slice.json", &slice); err != nil {
		return err
	}

	row.ManifestComponent = slice.Component.Name
	row.ManifestProvenance = string(slice.Component.ProvenanceStatus)
	row.SymbolsAbsent = append([]string(nil), obs.SymbolsAbsent...)
	sort.Strings(row.SymbolsAbsent)
	for _, s := range obs.SymbolsPresent {
		if s.Normalized != "" {
			row.SymbolsPresent = append(row.SymbolsPresent, s.Normalized)
		}
	}
	sort.Strings(row.SymbolsPresent)
	row.ComponentIdentified = len(obs.IdentityMatches) > 0 || len(obs.IdentityStringsMatch) > 0
	if row.Component == "" {
		row.Component = slice.Component.Name
	}
	return nil
}

func identityInfo(purlStr string, aliases *manifest.IdentityAliases) (source, status, component string) {
	p, err := purl.Canonicalize(strings.TrimSpace(purlStr))
	if err != nil {
		return "", "none", ""
	}
	switch p.Type {
	case "deb", "apk", "rpm":
		name, _, ok := purl.ParseUpstream(p.Raw)
		if !ok {
			return "", "none", ""
		}
		a, ok := aliases.Lookup(name)
		if !ok {
			return name, "none", ""
		}
		return name, string(a.Status), a.Component
	default:
		return p.Name, "direct", p.Name
	}
}

func evidenceKind(row Row) string {
	switch strings.ToLower(row.Justification) {
	case "component_not_present":
		return "component_not_present"
	case "vulnerable_code_not_present":
		if len(row.SymbolsAbsent) > 0 {
			return "symbols_absent"
		}
		return "vulnerable_code_not_present"
	default:
		return row.Justification
	}
}

func lookupCatalog(catalogPath, id, artifactPath string) ArtifactIdentity {
	ai := ArtifactIdentity{Name: filepath.Base(artifactPath)}
	if catalogPath == "" {
		return ai
	}
	//nolint:gosec // G304: catalogPath is operator --catalog; empty is skipped above
	data, err := os.ReadFile(catalogPath)
	if err != nil {
		return ai
	}
	var doc struct {
		Artifacts []struct {
			ID        string `yaml:"id"`
			Class     string `yaml:"class"`
			SHA256    string `yaml:"sha256"`
			SourceURL string `yaml:"source_url"`
			FetchedAt string `yaml:"fetched_at"`
		} `yaml:"artifacts"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return ai
	}
	for _, a := range doc.Artifacts {
		if id != "" {
			if a.ID == id {
				ai.ID = a.ID
				ai.Name = a.ID
				ai.Class = a.Class
				ai.SHA256 = a.SHA256
				ai.SourceURL = a.SourceURL
				ai.FetchedAt = a.FetchedAt
				return ai
			}
			continue
		}
		if strings.Contains(artifactPath, a.ID) {
			ai.ID = a.ID
			ai.Name = a.ID
			ai.Class = a.Class
			ai.SHA256 = a.SHA256
			ai.SourceURL = a.SourceURL
			ai.FetchedAt = a.FetchedAt
			return ai
		}
	}
	return ai
}

func buildRederivation(artifactPath, scanDir string, opts Options) string {
	findings := filepath.ToSlash(filepath.Join(scanDir, "grype.json"))
	manifestDir := opts.ManifestDir
	if manifestDir == "" {
		manifestDir = "manifest"
	}
	manifestDir = filepath.ToSlash(manifestDir)
	return strings.Join([]string{
		"# Re-derive locally (air-gapped after inputs are present):",
		fmt.Sprintf("lading scan %q \\", artifactPath),
		fmt.Sprintf("  --findings %q \\", findings),
		fmt.Sprintf("  --manifest %q \\", manifestDir),
		fmt.Sprintf("  --out %q \\", scanDir),
		fmt.Sprintf("  --timestamp %q \\", opts.Timestamp),
		"  --no-vex",
		fmt.Sprintf("lading evidence --artifact %q \\", artifactPath),
		fmt.Sprintf("  --scan-dir %q \\", scanDir),
		fmt.Sprintf("  --timestamp %q \\", opts.Timestamp),
		"  --out evidence.html --sign-key YOUR.pem",
	}, "\n")
}

func defaultLimitations() []string {
	return []string{
		"This pack does NOT prove regulatory compliance, product safety, or completeness of vulnerability coverage.",
		"This pack does NOT prove scanner findings are true positives — only how the engine responded given manifest + inventory.",
		"Refusals are not exonerations; they record insufficient evidence under evidence-v1 rules.",
		"Identity mappings marked probable are not clearance-grade; definitive mappings require hand-verified provenance.",
		"Artifact metadata (name, URL, dates) is copied from catalogue input and is not authenticated by this document alone.",
	}
}

// SignDetached signs content with an ed25519 PEM private key (PKCS#8 or seed).
func SignDetached(content []byte, keyPEM []byte) ([]byte, error) {
	key, err := parseEd25519PrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(content)
	sig := ed25519.Sign(key, sum[:])
	return []byte("evidence-sig-v1 sha256=" + hex.EncodeToString(sum[:]) + " sig=" + hex.EncodeToString(sig) + "\n"), nil
}

func parseEd25519PrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("evidencehtml: invalid PEM")
	}
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		pk, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("evidencehtml: not ed25519")
		}
		return pk, nil
	case "ED25519 PRIVATE KEY":
		if len(block.Bytes) != ed25519.SeedSize {
			return nil, fmt.Errorf("evidencehtml: bad seed size")
		}
		return ed25519.NewKeyFromSeed(block.Bytes), nil
	default:
		return nil, fmt.Errorf("evidencehtml: unsupported PEM type %q", block.Type)
	}
}
