// Package auditvex audits third-party VEX documents against an SBOM for
// inert and over-broad product identity matches.
package auditvex

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/gautamtalksdev/lading/internal/purl"
)

// Status classifies a VEX statement relative to an SBOM.
type Status string

const (
	StatusOK          Status = "ok"
	StatusInert       Status = "inert"       // Grype failure mode
	StatusOverbroad   Status = "overbroad"   // Trivy failure mode
	StatusVersionless Status = "versionless" // unversioned not_affected PURL
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
	ProductIDs    []string
	Platforms     []string
	VEXStatus     string // CSAF product_status key
	Justification string
	Matches       []Match
	Best          purl.MatchQuality
	Status        Status
}

// Report is the full audit result.
type Report struct {
	Results []StatementResult
}

// HasFailures reports whether any statement is inert, over-broad, or versionless.
func (r Report) HasFailures() bool {
	for _, s := range r.Results {
		if s.Status == StatusInert || s.Status == StatusOverbroad || s.Status == StatusVersionless {
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
		ProductIDs:    append([]string(nil), st.ProductIDs...),
		Platforms:     append([]string(nil), st.Platforms...),
		VEXStatus:     st.Status,
		Justification: st.Justification,
		Best:          purl.None,
		Status:        StatusOK,
	}

	if !isSuppressionStatement(st) {
		res.Detail = fmt.Sprintf("ok: %s statement (does not suppress findings)", st.Status)
		return res
	}

	for _, raw := range st.ProductPURLs {
		if !purlHasVersion(raw) {
			res.Status = StatusVersionless
			res.Detail = fmt.Sprintf(
				"versionless: purl=%s platforms=[%s] justification=%q",
				raw,
				strings.Join(st.Platforms, ", "),
				st.Justification,
			)
			return res
		}
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

	if res.Best < purl.TypeNormalized {
		res.Status = StatusInert
		res.Detail = "inert: no Exact/TypeNormalized SBOM match (Grype-class silent miss)"
		return res
	}

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
