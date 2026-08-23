// Package auditvex audits third-party VEX documents against an SBOM for
// inert and over-broad product identity matches.
package auditvex

import (
	"fmt"
	"os"
	"sort"

	"github.com/gautamtalksdev/lading/internal/purl"
)

// Status classifies a VEX statement relative to an SBOM.
type Status string

const (
	StatusOK        Status = "ok"
	StatusInert     Status = "inert"     // Grype failure mode
	StatusOverbroad Status = "overbroad" // Trivy failure mode
)

// Component is one SBOM package identity.
type Component struct {
	Name   string
	PURL   purl.PURL
	IsRoot bool // top-level product; false ⇒ dependency / subcomponent
}

// Match is one graded hit between a VEX product and an SBOM component.
type Match struct {
	Component Component
	Quality   purl.MatchQuality
}

// StatementResult is the audit outcome for one VEX statement.
type StatementResult struct { //nolint:govet // exported report shape preferred over packing
	Document      string
	Vulnerability string
	Detail        string
	Products      []string // raw product PURLs from the statement
	Matches       []Match
	Best          purl.MatchQuality
	Status        Status
}

// Report is the full audit result.
type Report struct {
	Results []StatementResult
}

// HasFailures reports whether any statement is inert or over-broad.
func (r Report) HasFailures() bool {
	for _, s := range r.Results {
		if s.Status == StatusInert || s.Status == StatusOverbroad {
			return true
		}
	}
	return false
}

// Audit loads an SBOM and one or more VEX documents and grades every statement.
func Audit(sbomPath string, vexPaths []string) (Report, error) {
	// #nosec G304 -- paths are caller-supplied SBOM/VEX inputs under analysis
	sbomData, err := os.ReadFile(sbomPath)
	if err != nil {
		return Report{}, fmt.Errorf("auditvex: read sbom: %w", err)
	}
	comps, err := parseSBOM(sbomData)
	if err != nil {
		return Report{}, fmt.Errorf("auditvex: parse sbom: %w", err)
	}

	var report Report
	for _, vp := range vexPaths {
		// #nosec G304 -- paths are caller-supplied VEX inputs under analysis
		data, err := os.ReadFile(vp)
		if err != nil {
			return Report{}, fmt.Errorf("auditvex: read vex %s: %w", vp, err)
		}
		stmts, err := parseVEX(vp, data)
		if err != nil {
			return Report{}, fmt.Errorf("auditvex: parse vex %s: %w", vp, err)
		}
		for _, st := range stmts {
			report.Results = append(report.Results, evaluate(st, comps))
		}
	}
	return report, nil
}

func evaluate(st vexStatement, comps []Component) StatementResult {
	res := StatementResult{
		Document:      st.Document,
		Vulnerability: st.Vulnerability,
		Products:      append([]string(nil), st.ProductPURLs...),
		Best:          purl.None,
		Status:        StatusOK,
	}

	var matches []Match
	for _, raw := range st.ProductPURLs {
		vp, err := purl.Canonicalize(raw)
		if err != nil {
			continue
		}
		for _, c := range comps {
			q := purl.Equivalent(vp, c.PURL)
			if q == purl.None {
				continue
			}
			matches = append(matches, Match{Component: c, Quality: q})
			if q > res.Best {
				res.Best = q
			}
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Quality != matches[j].Quality {
			return matches[i].Quality > matches[j].Quality
		}
		return matches[i].Component.PURL.Canonical() < matches[j].Component.PURL.Canonical()
	})
	res.Matches = matches

	// Grype failure mode: no Exact (or TypeNormalized) identity — the VEX
	// statement would be silently ignored by tools that require string-equal
	// / same-type PURL identity.
	if res.Best < purl.TypeNormalized {
		res.Status = StatusInert
		res.Detail = "inert: no Exact/TypeNormalized SBOM match (Grype-class silent miss)"
		return res
	}

	// Trivy failure mode: statement lands on a subcomponent (dependency),
	// so applying it would suppress findings across unrelated root products
	// that share that dependency.
	subHits := 0
	rootHits := 0
	for _, m := range matches {
		if m.Quality < purl.TypeNormalized {
			continue
		}
		if m.Component.IsRoot {
			rootHits++
		} else {
			subHits++
		}
	}
	if subHits > 0 && rootHits == 0 {
		res.Status = StatusOverbroad
		res.Detail = "overbroad: matched subcomponent only (Trivy-class cross-product suppression)"
		return res
	}

	res.Detail = "ok"
	return res
}
