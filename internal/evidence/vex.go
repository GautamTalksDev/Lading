package evidence

import (
	"encoding/json"
	"fmt"
	"strings"
)

// VEXStatement is one expected VEX output row.
type VEXStatement struct {
	Vulnerability string
	ProductPURL   string
	Status        string
	Justification string
}

// ParseVEX reads lading-vex-v1 or OpenVEX JSON.
func ParseVEX(data []byte) ([]VEXStatement, error) {
	var probe map[string]any
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("evidence: vex not JSON: %w", err)
	}
	if fmtVal, ok := probe["format"].(string); ok && strings.EqualFold(fmtVal, "lading-vex-v1") {
		return parseLadingVEX(data)
	}
	if _, ok := probe["statements"]; ok {
		return parseOpenVEX(data)
	}
	return nil, fmt.Errorf("evidence: unrecognized vex format")
}

type ladingVEXDoc struct {
	Format     string `json:"format"`
	Statements []struct {
		Vulnerability string `json:"vulnerability"`
		ProductPURL   string `json:"product_purl"`
		Status        string `json:"status"`
		Justification string `json:"justification,omitempty"`
	} `json:"statements"`
}

func parseLadingVEX(data []byte) ([]VEXStatement, error) {
	var doc ladingVEXDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []VEXStatement
	for _, st := range doc.Statements {
		out = append(out, VEXStatement{
			Vulnerability: strings.ToUpper(strings.TrimSpace(st.Vulnerability)),
			ProductPURL:   st.ProductPURL,
			Status:        strings.ToLower(strings.TrimSpace(st.Status)),
			Justification: strings.TrimSpace(st.Justification),
		})
	}
	return out, nil
}

type openVEX struct {
	Statements []struct {
		Vulnerability struct {
			Name string `json:"name"`
		} `json:"vulnerability"`
		Status         string `json:"status"`
		Justification  string `json:"justification"`
		Justifications []struct {
			Label string `json:"label"`
		} `json:"justifications"`
		Products []openVEXProduct `json:"products"`
	} `json:"statements"`
}

type openVEXProduct struct {
	ID          string `json:"@id"`
	PURL        string `json:"purl"`
	Identifiers *struct {
		PURL string `json:"purl"`
	} `json:"identifiers"`
}

func parseOpenVEX(data []byte) ([]VEXStatement, error) {
	var doc openVEX
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []VEXStatement
	for _, st := range doc.Statements {
		vuln := strings.ToUpper(strings.TrimSpace(st.Vulnerability.Name))
		status := strings.ToLower(strings.TrimSpace(st.Status))
		just := strings.TrimSpace(st.Justification)
		if just == "" {
			for _, j := range st.Justifications {
				if j.Label != "" {
					just = j.Label
					break
				}
			}
		}
		for _, p := range st.Products {
			for _, id := range productPURLs(p) {
				out = append(out, VEXStatement{
					Vulnerability: vuln,
					ProductPURL:   id,
					Status:        status,
					Justification: just,
				})
			}
		}
	}
	return out, nil
}

func productPURLs(p openVEXProduct) []string {
	var out []string
	if strings.HasPrefix(p.ID, "pkg:") {
		out = append(out, p.ID)
	}
	if p.PURL != "" {
		out = append(out, p.PURL)
	}
	if p.Identifiers != nil && p.Identifiers.PURL != "" {
		out = append(out, p.Identifiers.PURL)
	}
	return out
}

// MatchesStatement compares a VEX row to a bundle statement record.
func MatchesStatement(vex VEXStatement, stmt StatementRecord) bool {
	if !strings.EqualFold(vex.Vulnerability, stmt.CVE) {
		return false
	}
	if !purlLooseEqual(vex.ProductPURL, stmt.PURL) {
		return false
	}
	if !statusMatchesVerdict(vex, stmt) {
		return false
	}
	return true
}

func statusMatchesVerdict(vex VEXStatement, stmt StatementRecord) bool {
	switch strings.ToUpper(stmt.Verdict) {
	case "NOT_AFFECTED":
		if vex.Status != "not_affected" {
			return false
		}
		if stmt.Justification != "" && vex.Justification != "" &&
			!strings.EqualFold(vex.Justification, stmt.Justification) {
			return false
		}
		return true
	case "AFFECTED":
		return vex.Status == "affected"
	case "UNDER_INVESTIGATION":
		return vex.Status == "under_investigation"
	default:
		return false
	}
}

func purlLooseEqual(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == b {
		return true
	}
	return stripPURLChecksum(a) == stripPURLChecksum(b)
}

func stripPURLChecksum(p string) string {
	if i := strings.Index(p, "?"); i >= 0 {
		base := p[:i]
		q := p[i+1:]
		if strings.Contains(q, "checksum=") {
			return base
		}
	}
	return p
}
