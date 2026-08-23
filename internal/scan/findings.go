package scan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/gautamtalksdev/lading/internal/auditvex"
	"github.com/gautamtalksdev/lading/internal/decide"
)

// Finding is one CVE against an SBOM component PURL.
type Finding = decide.Finding

// LoadFindings reads grype, trivy, or cve-bin-tool JSON.
func LoadFindings(path string) ([]Finding, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("findings: read: %w", err)
	}
	if out, err := parseGrype(data); err == nil {
		return out, nil
	}
	if out, err := parseTrivy(data); err == nil {
		return out, nil
	}
	if out, err := parseCVEBinTool(data); err == nil {
		return out, nil
	}
	return nil, fmt.Errorf("findings: unrecognized JSON format in %q", path)
}

// LoadOSVFindings matches SBOM components against a local OSV JSONL dump.
func LoadOSVFindings(osvPath string, sbomPath string) ([]Finding, error) {
	components, err := auditvex.LoadSBOM(sbomPath)
	if err != nil {
		return nil, err
	}
	index, err := loadOSVIndex(osvPath)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []Finding
	for _, c := range components {
		purl := c.PURL.Canonical()
		for _, vuln := range index.matchPURL(purl) {
			key := vuln + "\t" + purl
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, Finding{CVE: vuln, ComponentPURL: purl})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("findings: no OSV matches for SBOM components")
	}
	return out, nil
}

func parseGrype(data []byte) ([]Finding, error) {
	var doc struct {
		Matches []struct {
			Vulnerability struct {
				ID string `json:"id"`
			} `json:"vulnerability"`
			Artifact struct {
				PURL string `json:"purl"`
			} `json:"artifact"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return matchesToFindings(doc.Matches, func(m int) (string, string) {
		return doc.Matches[m].Vulnerability.ID, doc.Matches[m].Artifact.PURL
	}, len(doc.Matches))
}

func parseTrivy(data []byte) ([]Finding, error) {
	var doc struct {
		Results []struct {
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID"`
				PkgIdentifier   struct {
					PURL string `json:"PURL"`
				} `json:"PkgIdentifier"`
				PkgName string `json:"PkgName"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var raw [][2]string
	for _, res := range doc.Results {
		for _, v := range res.Vulnerabilities {
			p := v.PkgIdentifier.PURL
			if p == "" && v.PkgName != "" {
				p = "pkg:generic/" + v.PkgName
			}
			raw = append(raw, [2]string{v.VulnerabilityID, p})
		}
	}
	return matchesToFindings(raw, func(m int) (string, string) {
		return raw[m][0], raw[m][1]
	}, len(raw))
}

func parseCVEBinTool(data []byte) ([]Finding, error) {
	var doc []struct {
		CVE   string `json:"cve"`
		PURL  string `json:"purl"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return matchesToFindings(doc, func(m int) (string, string) {
		p := doc[m].PURL
		if p == "" && doc[m].Name != "" {
			p = "pkg:generic/" + doc[m].Name
		}
		return doc[m].CVE, p
	}, len(doc))
}

func matchesToFindings(_ any, at func(int) (string, string), n int) ([]Finding, error) {
	seen := map[string]struct{}{}
	var out []Finding
	for i := 0; i < n; i++ {
		cve, purl := at(i)
		cve = strings.ToUpper(strings.TrimSpace(cve))
		purl = strings.TrimSpace(purl)
		if cve == "" || purl == "" {
			continue
		}
		key := cve + "\t" + purl
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Finding{CVE: cve, ComponentPURL: purl})
	}
	if len(out) == 0 {
		return []Finding{}, nil
	}
	return out, nil
}

type osvIndex struct {
	byPURL map[string][]string
}

func loadOSVIndex(path string) (*osvIndex, error) {
	f, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	idx := &osvIndex{byPURL: map[string][]string{}}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 10*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec struct {
			ID       string `json:"id"`
			Affected []struct {
				Package struct {
					Ecosystem string `json:"ecosystem"`
					Name      string `json:"name"`
				} `json:"package"`
			} `json:"affected"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		id := strings.ToUpper(strings.TrimSpace(rec.ID))
		if id == "" {
			continue
		}
		for _, aff := range rec.Affected {
			key := strings.ToLower(aff.Package.Ecosystem) + "/" + aff.Package.Name
			idx.byPURL[key] = appendUnique(idx.byPURL[key], id)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return idx, nil
}

func (idx *osvIndex) matchPURL(purl string) []string {
	purl = strings.TrimSpace(purl)
	var out []string
	out = append(out, idx.byPURL[purl]...)
	// Loose match on pkg:type/namespace/name@version → ecosystem/name
	if i := strings.Index(purl, "@"); i > 0 {
		purl = purl[:i]
	}
	if strings.HasPrefix(purl, "pkg:") {
		purl = purl[4:]
	}
	if slash := strings.Index(purl, "/"); slash >= 0 {
		eco := strings.ToLower(purl[:slash])
		rest := purl[slash+1:]
		if j := strings.LastIndex(rest, "/"); j >= 0 {
			name := rest[j+1:]
			out = append(out, idx.byPURL[eco+"/"+name]...)
			out = append(out, idx.byPURL[eco+"/"+rest]...)
		} else {
			out = append(out, idx.byPURL[eco+"/"+rest]...)
		}
	}
	return uniqueStrings(out)
}

func appendUnique(list []string, v string) []string {
	for _, s := range list {
		if s == v {
			return list
		}
	}
	return append(list, v)
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
