// Package evidence constructs and verifies content-addressed evidence bundles.
//
// Bundles embed the Manifest slice used at decision time so verification is
// air-gapped and does not depend on an installed manifest/ tree.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gautamtalksdev/lading/internal/decide"
	"github.com/gautamtalksdev/lading/internal/inventory"
	"github.com/gautamtalksdev/lading/internal/manifest"
)

// SpecVersion is the evidence bundle format version (see SPEC-EVIDENCE.md).
const SpecVersion = "evidence-v1"

// BundleFormatVersion labels bundle layout in versions.json.
const BundleFormatVersion = "evidence-bundle-v1"

// StatementRecord is statement.json.
type StatementRecord struct {
	CVE           string `json:"cve"`
	PURL          string `json:"purl"`
	Verdict       string `json:"verdict"`
	Justification string `json:"justification,omitempty"`
	RuleID        string `json:"rule_id"`
	ReasonCode    string `json:"reason_code,omitempty"`
}

// BinaryInput is one scanned binary named in inputs.json.
type BinaryInput struct {
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	Format       string `json:"format"`
	Stripped     bool   `json:"stripped"`
	StaticLinked bool   `json:"static_linked"`
}

// InputsRecord is inputs.json.
type InputsRecord struct {
	ArtifactSHA256 string        `json:"artifact_sha256"`
	Binaries       []BinaryInput `json:"binaries"`
}

// SymbolObservation is one symbol table entry consulted.
type SymbolObservation struct {
	Inventory  string `json:"inventory"`
	Raw        string `json:"raw"`
	Normalized string `json:"normalized"`
	Defined    bool   `json:"defined"`
	Source     string `json:"source"` // dyn_syms | symtab
}

// IdentityMatch records a component identity hit.
type IdentityMatch struct {
	Inventory string `json:"inventory"`
	Component string `json:"component"`
	Reason    string `json:"reason"`
}

// ObservationsRecord is observations.json.
type ObservationsRecord struct {
	SymbolsPresent       []SymbolObservation `json:"symbols_present"`
	SymbolsAbsent        []string            `json:"symbols_absent"`
	IdentityMatches      []IdentityMatch     `json:"identity_matches"`
	IdentityStringsMatch []IdentityMatch     `json:"identity_strings_matched"`
}

// VersionsRecord is versions.json.
type VersionsRecord struct {
	ToolVersion      string `json:"tool_version"`
	ManifestVersion  string `json:"manifest_version"`
	SpecVersion      string `json:"spec_version"`
	DecideVersion    string `json:"decide_version"`
	BundleFormat     string `json:"bundle_format"`
}

// StatementFiles lists per-statement bundle files.
var StatementFiles = []string{
	"statement.json",
	"inputs.json",
	"observations.json",
	"manifest-slice.json",
	"versions.json",
}

// BuildInput is everything needed to materialize one statement bundle.
type BuildInput struct {
	ArtifactPath string
	StatementID  string
	Finding      decide.Finding
	Result       decide.Result
	Inventories  []*inventory.Inventory
	Slice        manifest.Slice
}

// WriteBundleDir writes a content-addressed bundle directory.
func WriteBundleDir(dir string, statements []BuildInput) (bundleID string, err error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	stmtRoot := filepath.Join(dir, "statements")
	if err := os.MkdirAll(stmtRoot, 0o750); err != nil {
		return "", err
	}

	var manifestLines []string
	for i, bi := range statements {
		id := bi.StatementID
		if id == "" {
			id = fmt.Sprintf("%04d", i+1)
		}
		stmtDir := filepath.Join(stmtRoot, id)
		if err := os.MkdirAll(stmtDir, 0o750); err != nil {
			return "", err
		}
		lines, err := writeStatement(dir, stmtDir, bi)
		if err != nil {
			return "", err
		}
		manifestLines = append(manifestLines, lines...)
	}

	sort.Strings(manifestLines)
	var b strings.Builder
	b.WriteString("# evidence-bundle-v1 MANIFEST.sha\n")
	for _, line := range manifestLines {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	manifestBytes := []byte(b.String())
	manifestPath := filepath.Join(dir, "MANIFEST.sha")
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		return "", err
	}

	sum := sha256.Sum256(manifestBytes)
	bundleID = hex.EncodeToString(sum[:])
	idPath := filepath.Join(dir, "BUNDLE.id")
	if err := os.WriteFile(idPath, []byte(bundleID+"\n"), 0o600); err != nil {
		return "", err
	}
	return bundleID, nil
}

func writeStatement(bundleRoot, stmtDir string, bi BuildInput) ([]string, error) {
	artifactSHA, binaries, err := artifactInputs(bi.ArtifactPath, bi.Inventories)
	if err != nil {
		return nil, err
	}

	stmt := StatementRecord{
		CVE:           bi.Result.InputsUsed.CVE,
		PURL:          bi.Finding.ComponentPURL,
		Verdict:       string(bi.Result.Verdict),
		Justification: string(bi.Result.Justification),
		RuleID:        string(bi.Result.RuleID),
		ReasonCode:    string(bi.Result.ReasonCode),
	}
	inputs := InputsRecord{
		ArtifactSHA256: artifactSHA,
		Binaries:       binaries,
	}
	obs := buildObservations(bi.Inventories, bi.Slice, bi.Finding, bi.Result)
	vers := VersionsRecord{
		ToolVersion:     BundleFormatVersion,
		ManifestVersion: bi.Slice.Version,
		SpecVersion:     SpecVersion,
		DecideVersion:   decide.ToolVersion,
		BundleFormat:    BundleFormatVersion,
	}

	files := map[string]any{
		"statement.json":      stmt,
		"inputs.json":         inputs,
		"observations.json":   obs,
		"manifest-slice.json": bi.Slice,
		"versions.json":       vers,
	}

	var lines []string
	for _, name := range StatementFiles {
		data, err := json.MarshalIndent(files[name], "", "  ")
		if err != nil {
			return nil, err
		}
		data = append(data, '\n')
		path := filepath.Join(stmtDir, name)
		if werr := os.WriteFile(path, data, 0o600); werr != nil {
			return nil, werr
		}
		sum := sha256.Sum256(data)
		rel, err := filepath.Rel(bundleRoot, path)
		if err != nil {
			rel = filepath.Join("statements", filepath.Base(stmtDir), name)
		}
		lines = append(lines, fmt.Sprintf("%s  %s", hex.EncodeToString(sum[:]), filepath.ToSlash(rel)))
	}
	return lines, nil
}

func artifactInputs(artifactPath string, invs []*inventory.Inventory) (string, []BinaryInput, error) {
	fi, err := os.Stat(artifactPath)
	if err != nil {
		return "", nil, err
	}
	var artifactSHA string
	var binaries []BinaryInput

	if fi.IsDir() {
		h := sha256.New()
		var paths []string
		for _, inv := range invs {
			if inv == nil {
				continue
			}
			p := inv.Path
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			sum, err := fileSHA256(p)
			if err != nil {
				return "", nil, err
			}
			rel, err := filepath.Rel(artifactPath, p)
			if err != nil {
				rel = filepath.Base(p)
			}
			_, _ = h.Write([]byte(rel + "\n" + sum + "\n"))
			binaries = append(binaries, binaryInputFromInv(rel, invByPath(invs, p)))
		}
		artifactSHA = hex.EncodeToString(h.Sum(nil))
	} else {
		sum, err := fileSHA256(artifactPath)
		if err != nil {
			return "", nil, err
		}
		artifactSHA = sum
		name := filepath.Base(artifactPath)
		if len(invs) == 1 && invs[0] != nil {
			binaries = append(binaries, binaryInputFromInv(name, invs[0]))
		} else if len(invs) > 0 {
			for _, inv := range invs {
				if inv == nil {
					continue
				}
				binaries = append(binaries, binaryInputFromInv(filepath.Base(inv.Path), inv))
			}
		} else {
			binaries = append(binaries, BinaryInput{Path: name, SHA256: sum})
		}
	}
	sort.Slice(binaries, func(i, j int) bool { return binaries[i].Path < binaries[j].Path })
	return artifactSHA, binaries, nil
}

func binaryInputFromInv(path string, inv *inventory.Inventory) BinaryInput {
	if inv == nil {
		return BinaryInput{Path: path}
	}
	return BinaryInput{
		Path:         path,
		SHA256:       inv.SHA256,
		Format:       string(inv.Format),
		Stripped:     inv.Stripped,
		StaticLinked: inv.StaticLinked,
	}
}

func invByPath(invs []*inventory.Inventory, path string) *inventory.Inventory {
	for _, inv := range invs {
		if inv != nil && inv.Path == path {
			return inv
		}
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func buildObservations(
	invs []*inventory.Inventory,
	slice manifest.Slice,
	finding decide.Finding,
	result decide.Result,
) ObservationsRecord {
	m, err := manifest.LoadFromSlice(slice)
	if err != nil {
		return ObservationsRecord{}
	}
	presentSet := map[string]struct{}{}
	for _, s := range result.InputsUsed.SymbolsObserved {
		presentSet[s] = struct{}{}
	}

	var present []SymbolObservation
	var absent []string
	observed := map[string][]SymbolObservation{}

	for _, inv := range invs {
		if inv == nil {
			continue
		}
		id := inv.Path
		if id == "" {
			id = inv.SHA256
		}
		add := func(s inventory.Symbol, source string) {
			key := s.Normalized
			if key == "" {
				key = s.Raw
			}
			obs := SymbolObservation{
				Inventory:  id,
				Raw:        s.Raw,
				Normalized: key,
				Defined:    s.Defined,
				Source:     source,
			}
			observed[key] = append(observed[key], obs)
		}
		for _, s := range inv.DynSyms {
			add(s, "dyn_syms")
		}
		for _, s := range inv.SymTab {
			add(s, "symtab")
		}
	}

	for _, sym := range result.InputsUsed.DefinitiveSymbolsChecked {
		if _, ok := presentSet[sym]; ok {
			for _, o := range observed[sym] {
				present = append(present, o)
			}
		} else {
			absent = append(absent, sym)
		}
	}
	sort.Slice(present, func(i, j int) bool {
		if present[i].Normalized != present[j].Normalized {
			return present[i].Normalized < present[j].Normalized
		}
		return present[i].Inventory < present[j].Inventory
	})
	sort.Strings(absent)

	var idMatches []IdentityMatch
	var strMatches []IdentityMatch
	comp := slice.Component
	for _, inv := range invs {
		if inv == nil {
			continue
		}
		id := inv.Path
		if id == "" {
			id = inv.SHA256
		}
		for _, hit := range m.IdentifyComponent(inv) {
			if hit.Component.Name != comp.Name {
				continue
			}
			rec := IdentityMatch{Inventory: id, Component: hit.Component.Name, Reason: hit.Reason}
			if strings.HasPrefix(hit.Reason, "string:") {
				strMatches = append(strMatches, rec)
			} else {
				idMatches = append(idMatches, rec)
			}
		}
	}
	sortIdentity := func(a []IdentityMatch) {
		sort.Slice(a, func(i, j int) bool {
			if a[i].Inventory != a[j].Inventory {
				return a[i].Inventory < a[j].Inventory
			}
			return a[i].Reason < a[j].Reason
		})
	}
	sortIdentity(idMatches)
	sortIdentity(strMatches)

	_ = finding
	return ObservationsRecord{
		SymbolsPresent:       present,
		SymbolsAbsent:        absent,
		IdentityMatches:      idMatches,
		IdentityStringsMatch: strMatches,
	}
}
