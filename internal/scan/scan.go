package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gautamtalksdev/lading/internal/decide"
	"github.com/gautamtalksdev/lading/internal/evidence"
	"github.com/gautamtalksdev/lading/internal/manifest"
	"github.com/gautamtalksdev/lading/internal/unpack"
	"github.com/gautamtalksdev/lading/internal/vexout"
)

// Options configures a scan run.
type Options struct {
	ArtifactPath string
	ImageRef     string
	SBOMPath     string
	FindingsPath string
	OSVPath      string
	ManifestDir  string
	OutDir       string
	Timestamp    string
	EmitVEX      bool
}

// Result is the full scan outcome.
type Result struct {
	Report      Report
	HasAffected bool
	BundleDir   string
}

// Run executes unpack → inventory → decide → bundle → optional vex emit.
func Run(opts Options) (Result, error) {
	if opts.ManifestDir == "" {
		opts.ManifestDir = "manifest"
	}
	if opts.OutDir == "" {
		opts.OutDir = "."
	}

	unpacked, err := unpack.Unpack(opts.ArtifactPath, unpack.Options{ImageRef: opts.ImageRef})
	if err != nil {
		return Result{}, err
	}
	defer unpacked.Cleanup()

	findings, err := loadFindingSources(opts)
	if err != nil {
		return Result{}, err
	}

	inventories, err := DiscoverBinaries(unpacked.Root, unpacked.SingleFile)
	if err != nil {
		return Result{}, err
	}

	m, err := manifest.Load(opts.ManifestDir)
	if err != nil {
		return Result{}, fmt.Errorf("scan: manifest: %w", err)
	}

	aliases, err := manifest.LoadIdentityAliases("")
	if err != nil {
		return Result{}, fmt.Errorf("scan: identity aliases: %w", err)
	}

	artifactPath := opts.ArtifactPath
	if artifactPath == "" {
		artifactPath = unpacked.Root
	}
	if abs, err := filepath.Abs(artifactPath); err == nil {
		artifactPath = abs
	}

	report := Report{
		ArtifactDescription: SanitizeForTerminal(unpacked.Description),
		NotAffectedByJust:   map[string]int{},
		RefusedByReason:     map[string]int{},
	}
	for _, inv := range inventories {
		report.BinariesScanned++
		if inv.Stripped {
			report.Stripped++
		}
		if inv.StaticLinked {
			report.StaticLinked++
		}
	}
	report.CVEsIn = len(findings)

	var bundleInputs []evidence.BuildInput
	hasAffected := false

	for _, finding := range findings {
		result, err := decide.Evaluate(decide.Input{
			Inventories:     inventories,
			Finding:         finding,
			Manifest:        m,
			IdentityAliases: aliases,
		})
		if err != nil {
			return Result{}, fmt.Errorf("scan: decide %s: %w", finding.CVE, err)
		}
		if result.Verdict == decide.VerdictAffected {
			hasAffected = true
		}
		accumulateVerdict(&report, result)

		comp := result.InputsUsed.ManifestComponent
		if comp == "" {
			comp = "unknown"
		}
		slice, err := manifest.SliceFromManifest(m, comp, finding.CVE)
		if err != nil {
			// Refusals without manifest slice still appear in summary; skip bundle row.
			continue
		}
		bundleInputs = append(bundleInputs, evidence.BuildInput{
			ArtifactPath: artifactPath,
			StatementID:  statementID(finding),
			Finding:      finding,
			Result:       result,
			Inventories:  inventories,
			Slice:        slice,
		})
	}

	report.ComputeCoverage()

	bundleDir := filepath.Join(opts.OutDir, "evidence-bundle")
	if len(bundleInputs) > 0 {
		if _, err := evidence.WriteBundleDir(bundleDir, bundleInputs); err != nil {
			return Result{}, fmt.Errorf("scan: bundle: %w", err)
		}
	}

	if opts.EmitVEX && len(bundleInputs) > 0 {
		ts := opts.Timestamp
		if ts == "" {
			ts = time.Now().UTC().Format(time.RFC3339)
		}
		docIn, err := vexout.LoadFromBundle(bundleDir, ts)
		if err != nil {
			return Result{}, err
		}
		out, err := vexout.Emit(docIn)
		if err != nil {
			return Result{}, err
		}
		writeVEXOutputs(opts.OutDir, out)
	}

	return Result{
		Report:      report,
		HasAffected: hasAffected,
		BundleDir:   bundleDir,
	}, nil
}

func loadFindingSources(opts Options) ([]Finding, error) {
	switch {
	case opts.FindingsPath != "":
		return LoadFindings(opts.FindingsPath)
	case opts.OSVPath != "":
		if opts.SBOMPath == "" {
			return nil, fmt.Errorf("scan: --osv requires --sbom")
		}
		return LoadOSVFindings(opts.OSVPath, opts.SBOMPath)
	default:
		return nil, fmt.Errorf("scan: --findings or --osv required")
	}
}

func accumulateVerdict(r *Report, result decide.Result) {
	switch result.Verdict {
	case decide.VerdictNotAffected:
		r.NotAffectedTotal++
		key := string(result.Justification)
		if key == "" {
			key = "unspecified"
		}
		r.NotAffectedByJust[key]++
	case decide.VerdictAffected:
		r.Affected++
	case decide.VerdictUnderInvestigation:
		r.RefusedTotal++
		key := reasonLabel(result.ReasonCode)
		r.RefusedByReason[key]++
	}
}

func reasonLabel(code decide.ReasonCode) string {
	switch code {
	case decide.ReasonManifestNoEntry:
		return "no manifest entry"
	case decide.ReasonManifestProbableOnly:
		return "probable"
	case decide.ReasonStrippedStaticBinary:
		return "stripped-static"
	case decide.ReasonStrippedInsufficientDynsym:
		return "stripped-dynsym"
	case decide.ReasonSymbolTableUnusable:
		return "symtab-unusable"
	case decide.ReasonPURLMatchInsufficient:
		return "purl-insufficient"
	case decide.ReasonNoIdentityMapping:
		return "no-identity-mapping"
	case decide.ReasonMappingProbableOnly:
		return "mapping-probable-only"
	case decide.ReasonVersionUnderivable:
		return "version-underivable"
	case decide.ReasonIdentityUnverified:
		return "identity-unverified"
	default:
		if code == "" {
			return "unspecified"
		}
		return string(code)
	}
}

func statementID(f Finding) string {
	s := strings.ToLower(strings.TrimSpace(f.CVE))
	s = strings.ReplaceAll(s, ":", "-")
	return s
}

func writeVEXOutputs(dir string, out vexout.Output) {
	files := map[string][]byte{
		"vex.openvex.json": out.OpenVEX,
		"vex.cdx.json":     out.CycloneDX,
		"vex.csaf.json":    out.CSAF,
		"refusals.json":    out.Refusals,
	}
	for name, data := range files {
		_ = os.WriteFile(filepath.Join(dir, name), data, 0o600)
	}
}
