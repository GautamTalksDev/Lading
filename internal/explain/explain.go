// Package explain formats evidence-bundle verdicts for compliance reviewers.
package explain

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gautamtalksdev/lading/internal/decide"
	"github.com/gautamtalksdev/lading/internal/evidence"
	"github.com/gautamtalksdev/lading/internal/manifest"
)

// Options selects which bundle statement to explain.
type Options struct {
	BundleDir string
	CVE       string
	PURL      string // optional disambiguator
}

// Report is one human-oriented explanation.
type Report struct {
	CVE              string
	PURL             string
	Verdict          string
	Justification    string
	RuleID           string
	ReasonCode       string
	ManifestVersion  string
	ManifestComponent string
	PURLMatchQuality string
	StatementPath    string
	SymbolsChecked   []string
	SymbolsPresent   []string
	SymbolsAbsent    []string
	Provenance       []ProvenanceLine
	IdentityMatches  []string
	BinariesScanned  int
}

// ProvenanceLine ties a symbol to upstream review metadata.
type ProvenanceLine struct {
	Symbol            string
	Confidence        string
	UpstreamFixCommit string
	Derivation        string
	ReviewedBy        string
	ReviewedAt        string
}

// Explain loads a bundle statement and builds a compliance-oriented report.
func Explain(opt Options) (Report, error) {
	cve := strings.ToUpper(strings.TrimSpace(opt.CVE))
	if cve == "" {
		return Report{}, fmt.Errorf("explain: CVE required")
	}
	if opt.BundleDir == "" {
		return Report{}, fmt.Errorf("explain: --bundle required")
	}
	stmtDir, stmtID, err := findStatement(opt.BundleDir, cve, opt.PURL)
	if err != nil {
		return Report{}, err
	}

	var stmt evidence.StatementRecord
	var inputs evidence.InputsRecord
	var obs evidence.ObservationsRecord
	var slice manifest.Slice
	var vers evidence.VersionsRecord

	for _, name := range evidence.StatementFiles {
		path := filepath.Join(stmtDir, name)
		data, rerr := os.ReadFile(path) // #nosec G304
		if rerr != nil {
			return Report{}, rerr
		}
		switch name {
		case "statement.json":
			if err := json.Unmarshal(data, &stmt); err != nil {
				return Report{}, err
			}
		case "inputs.json":
			if err := json.Unmarshal(data, &inputs); err != nil {
				return Report{}, err
			}
		case "observations.json":
			if err := json.Unmarshal(data, &obs); err != nil {
				return Report{}, err
			}
		case "manifest-slice.json":
			if err := json.Unmarshal(data, &slice); err != nil {
				return Report{}, err
			}
		case "versions.json":
			if err := json.Unmarshal(data, &vers); err != nil {
				return Report{}, err
			}
		}
	}

	rep := Report{
		CVE:               stmt.CVE,
		PURL:              stmt.PURL,
		Verdict:           strings.ToUpper(stmt.Verdict),
		Justification:     stmt.Justification,
		RuleID:            stmt.RuleID,
		ReasonCode:        stmt.ReasonCode,
		ManifestVersion:   vers.ManifestVersion,
		ManifestComponent: slice.Component.Name,
		StatementPath:     filepath.Join("statements", stmtID),
		SymbolsAbsent:     append([]string(nil), obs.SymbolsAbsent...),
		BinariesScanned:   len(inputs.Binaries),
	}

	for _, s := range obs.SymbolsPresent {
		rep.SymbolsPresent = append(rep.SymbolsPresent, s.Normalized)
	}
	sort.Strings(rep.SymbolsPresent)
	sort.Strings(rep.SymbolsAbsent)

	for _, e := range slice.Entries {
		if !strings.EqualFold(e.CVE, cve) {
			continue
		}
		for _, vs := range e.VulnerableSymbols {
			rep.SymbolsChecked = append(rep.SymbolsChecked, vs.Name)
			rep.Provenance = append(rep.Provenance, ProvenanceLine{
				Symbol:            vs.Name,
				Confidence:        string(vs.Confidence),
				UpstreamFixCommit: vs.Provenance.UpstreamFixCommit,
				Derivation:        string(vs.Provenance.Derivation),
				ReviewedBy:        vs.Provenance.ReviewedBy,
				ReviewedAt:        vs.Provenance.ReviewedAt,
			})
		}
	}
	sort.Strings(rep.SymbolsChecked)

	for _, m := range obs.IdentityMatches {
		rep.IdentityMatches = append(rep.IdentityMatches,
			fmt.Sprintf("%s (%s)", m.Component, m.Reason))
	}
	for _, m := range obs.IdentityStringsMatch {
		rep.IdentityMatches = append(rep.IdentityMatches,
			fmt.Sprintf("%s (%s)", m.Component, m.Reason))
	}
	sort.Strings(rep.IdentityMatches)

	// PURL match quality is not stored in bundle; derive label from rule context.
	rep.PURLMatchQuality = purlQualityHint(stmt.RuleID, stmt.ReasonCode)
	_ = inputs
	return rep, nil
}

func findStatement(bundleDir, cve, wantPURL string) (stmtDir, stmtID string, err error) {
	root := filepath.Join(bundleDir, "statements")
	ents, err := os.ReadDir(root)
	if err != nil {
		return "", "", fmt.Errorf("explain: bundle statements: %w", err)
	}
	var matches []string
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(root, e.Name(), "statement.json")
		data, rerr := os.ReadFile(path) // #nosec G304
		if rerr != nil {
			continue
		}
		var stmt evidence.StatementRecord
		if json.Unmarshal(data, &stmt) != nil {
			continue
		}
		if !strings.EqualFold(stmt.CVE, cve) {
			continue
		}
		if wantPURL != "" && !strings.EqualFold(strings.TrimSpace(stmt.PURL), strings.TrimSpace(wantPURL)) {
			continue
		}
		matches = append(matches, e.Name())
	}
	if len(matches) == 0 {
		return "", "", fmt.Errorf("explain: no statement for %s in bundle", cve)
	}
	if len(matches) > 1 && wantPURL == "" {
		return "", "", fmt.Errorf("explain: multiple statements for %s; pass --purl", cve)
	}
	sort.Strings(matches)
	stmtID = matches[0]
	return filepath.Join(root, stmtID), stmtID, nil
}

func purlQualityHint(ruleID, reasonCode string) string {
	switch reasonCode {
	case string(decide.ReasonPURLMatchInsufficient):
		return "insufficient (below name+version)"
	case string(decide.ReasonIdentityUnverified):
		return "name+version only (identity unverified)"
	default:
		if ruleID == string(decide.RuleD01) || ruleID == string(decide.RuleD02) {
			return "sufficient for manifest lookup"
		}
		return "see bundle observations"
	}
}

// FormatHuman renders a compliance-owner-readable explanation.
func FormatHuman(r Report) string {
	var b strings.Builder
	title := fmt.Sprintf("%s", r.CVE)
	if r.Verdict != "" {
		title += " — " + verdictPlain(r.Verdict, r.Justification)
	}
	_, _ = fmt.Fprintln(&b, title)
	_, _ = fmt.Fprintln(&b)

	_, _ = fmt.Fprintf(&b, "Decision rule: %s\n", ruleHeadline(r.RuleID, r.ReasonCode))
	_, _ = fmt.Fprintln(&b, ruleBody(r))
	_, _ = fmt.Fprintln(&b)

	_, _ = fmt.Fprintln(&b, "What we looked at")
	_, _ = fmt.Fprintf(&b, "  Manifest version:    %s\n", r.ManifestVersion)
	if r.ManifestComponent != "" {
		_, _ = fmt.Fprintf(&b, "  Manifest component:  %s\n", r.ManifestComponent)
	}
	_, _ = fmt.Fprintf(&b, "  Scanner/SBOM claim:    %s\n", r.PURL)
	_, _ = fmt.Fprintf(&b, "  PURL match:            %s\n", r.PURLMatchQuality)
	_, _ = fmt.Fprintf(&b, "  Binaries inventoried:  %d\n", r.BinariesScanned)
	if len(r.IdentityMatches) > 0 {
		_, _ = fmt.Fprintln(&b, "  Component identity hits:")
		for _, m := range r.IdentityMatches {
			_, _ = fmt.Fprintf(&b, "    - %s\n", m)
		}
	}
	_, _ = fmt.Fprintln(&b)

	if len(r.SymbolsChecked) > 0 {
		_, _ = fmt.Fprintln(&b, "Symbols recorded in the manifest for this CVE")
		for _, p := range r.Provenance {
			_, _ = fmt.Fprintf(&b, "  - %s (%s)\n", p.Symbol, p.Confidence)
			if p.UpstreamFixCommit != "" {
				_, _ = fmt.Fprintf(&b, "      upstream fix: %s\n", p.UpstreamFixCommit)
			}
			if p.ReviewedBy != "" {
				_, _ = fmt.Fprintf(&b, "      reviewed by:  %s on %s\n", p.ReviewedBy, p.ReviewedAt)
			}
		}
		_, _ = fmt.Fprintln(&b)
		_, _ = fmt.Fprintln(&b, "Symbol observations in your artifact")
		if len(r.SymbolsPresent) == 0 {
			_, _ = fmt.Fprintln(&b, "  None of the manifest-listed definitive symbols were observed.")
		} else {
			for _, s := range r.SymbolsPresent {
				_, _ = fmt.Fprintf(&b, "  present: %s\n", s)
			}
		}
		for _, s := range r.SymbolsAbsent {
			_, _ = fmt.Fprintf(&b, "  absent (checked): %s\n", s)
		}
		_, _ = fmt.Fprintln(&b)
	}

	_, _ = fmt.Fprintln(&b, closingPlain(r))
	_, _ = fmt.Fprintf(&b, "Bundle statement: %s\n", r.StatementPath)
	_, _ = fmt.Fprintln(&b, "Independent check: lading verify <artifact> <vex.json> <bundle>")
	return b.String()
}

func verdictPlain(verdict, justification string) string {
	switch strings.ToUpper(verdict) {
	case "NOT_AFFECTED":
		switch justification {
		case string(decide.JustificationComponentNotPresent):
			return "Not affected — component not present in the scanned artifact"
		case string(decide.JustificationVulnerableCodeNotPresent):
			return "Not affected — vulnerable code not present in the scanned artifact"
		default:
			return "Not affected"
		}
	case "AFFECTED":
		return "Affected — vulnerable code observed"
	case "UNDER_INVESTIGATION":
		return "Refused — insufficient evidence (under investigation)"
	default:
		return verdict
	}
}

func ruleHeadline(ruleID, reasonCode string) string {
	switch ruleID {
	case string(decide.RuleD01):
		return "D01 — component identity not found in scanned binaries"
	case string(decide.RuleD02):
		return "D02 — manifest-listed vulnerable symbols not observed"
	case string(decide.RuleD03):
		return "D03 — evidence insufficient to claim not affected (" + reasonPlain(reasonCode) + ")"
	case string(decide.RuleD04):
		return "D04 — vulnerable symbol observed in scanned binaries"
	default:
		return ruleID
	}
}

func ruleBody(r Report) string {
	switch r.RuleID {
	case string(decide.RuleD01):
		return "The SBOM names a component, but none of the scanned binaries matched the manifest identity signals (symbols/strings)."
	case string(decide.RuleD02):
		return "The manifest ties this CVE to specific upstream symbols. Those symbols were not found in your binaries, so we assert vulnerable code is not present."
	case string(decide.RuleD04):
		return "At least one manifest-listed vulnerable symbol was observed. This is a positive finding of exposure."
	case string(decide.RuleD03):
		return "LADING refuses to guess. " + refusalDetail(r.ReasonCode)
	default:
		return ""
	}
}

func reasonPlain(code string) string {
	switch decide.ReasonCode(code) {
	case decide.ReasonManifestNoEntry:
		return "no manifest entry"
	case decide.ReasonManifestProbableOnly:
		return "probable-only manifest symbols"
	case decide.ReasonStrippedStaticBinary:
		return "stripped static binary"
	case decide.ReasonStrippedInsufficientDynsym:
		return "stripped binary with insufficient dynamic symbols"
	case decide.ReasonSymbolTableUnusable:
		return "symbol table unusable"
	case decide.ReasonPURLMatchInsufficient:
		return "PURL match too weak"
	case decide.ReasonIdentityUnverified:
		return "identity unverified"
	default:
		if code == "" {
			return "unspecified"
		}
		return code
	}
}

func refusalDetail(code string) string {
	switch decide.ReasonCode(code) {
	case decide.ReasonManifestNoEntry:
		return "There is no reviewed manifest entry for this CVE and component, so we cannot produce re-derivable proof."
	case decide.ReasonManifestProbableOnly:
		return "Manifest symbols exist but none are marked definitive (human-reviewed). Automation output alone cannot clear a CVE."
	case decide.ReasonStrippedStaticBinary:
		return "Stripped static binaries hide the symbols we need. See docs/LIMITS.md."
	default:
		return "See docs/LIMITS.md for coverage boundaries."
	}
}

func closingPlain(r Report) string {
	if r.Verdict == string(decide.VerdictUnderInvestigation) {
		return "This CVE was not cleared. LADING never emits prove-a-negative justifications (execute path, adversary control, inline mitigations)."
	}
	if r.Verdict == string(decide.VerdictNotAffected) {
		return "This statement is backed by the evidence bundle and can be checked without trusting the operator (see VERIFY.md)."
	}
	return "Review the evidence bundle and re-run verification before filing."
}
