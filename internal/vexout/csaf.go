package vexout

import (
	"fmt"
	"strings"

	"github.com/gautamtalksdev/lading/internal/decide"
)

type csafDoc struct {
	Document        csafDocument         `json:"document"`
	ProductTree     csafProductTree      `json:"product_tree"`
	Vulnerabilities []csafVulnerability  `json:"vulnerabilities"`
}

type csafDocument struct {
	Category    string         `json:"category"`
	CSAFVersion string         `json:"csaf_version"`
	Title       string         `json:"title"`
	Publisher   csafPublisher  `json:"publisher"`
	Tracking    csafTracking   `json:"tracking"`
	Notes       []csafNote     `json:"notes,omitempty"`
}

type csafNote struct {
	Category string `json:"category"`
	Text     string `json:"text"`
	Audience string `json:"audience,omitempty"`
}

type csafPublisher struct {
	Category  string `json:"category"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type csafTracking struct {
	ID                 string              `json:"id"`
	Version            string              `json:"version"`
	Status             string              `json:"status"`
	InitialReleaseDate string              `json:"initial_release_date"`
	CurrentReleaseDate string              `json:"current_release_date"`
	Generator          csafGenerator       `json:"generator"`
	RevisionHistory    []csafRevision      `json:"revision_history"`
}

type csafGenerator struct {
	Date   string     `json:"date"`
	Engine csafEngine `json:"engine"`
}

type csafEngine struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type csafRevision struct {
	Number  string `json:"number"`
	Date    string `json:"date"`
	Summary string `json:"summary"`
}

type csafProductTree struct {
	Branches []csafBranch `json:"branches"`
}

type csafBranch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Product  *csafProduct `json:"product,omitempty"`
	Branches []csafBranch `json:"branches,omitempty"`
}

type csafProduct struct {
	Name         string            `json:"name"`
	ProductID    string            `json:"product_id"`
	ProductIDs   map[string]string `json:"product_identification_helper,omitempty"`
}

type csafVulnerability struct {
	CVE           string                    `json:"cve"`
	ProductStatus map[string][]string       `json:"product_status"`
	Flags         []csafFlag                `json:"flags,omitempty"`
	Threats       []csafThreat              `json:"threats,omitempty"`
}

type csafFlag struct {
	Label      string   `json:"label"`
	ProductIDs []string `json:"product_ids"`
}

type csafThreat struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids"`
}

type csafVulnKey struct {
	cve    string
	status string
}

func emitCSAF(in DocumentInput) ([]byte, error) {
	products := map[string]csafProductBranch{}
	vulnGroups := map[csafVulnKey]*csafVulnerability{}

	for _, s := range sortedStatements(in) {
		pinned, err := DigestPinnedPURL(s.ComponentPURL, in.ArtifactSHA256)
		if err != nil {
			return nil, err
		}
		pid := csafProductID(pinned)
		if _, ok := products[pid]; !ok {
			products[pid] = csafProductBranch{
				ProductID: pid,
				PURL:      pinned,
				Name:      componentName(pinned),
				Version:   componentVersion(pinned),
			}
		}
		statusKey, err := csafStatusKey(s.Result.Verdict)
		if err != nil {
			return nil, err
		}
		key := csafVulnKey{cve: strings.ToUpper(strings.TrimSpace(s.CVE)), status: statusKey}
		v, ok := vulnGroups[key]
		if !ok {
			v = &csafVulnerability{
				CVE:           key.cve,
				ProductStatus: map[string][]string{},
			}
			vulnGroups[key] = v
		}
		v.ProductStatus[statusKey] = appendUnique(v.ProductStatus[statusKey], pid)
		v.Threats = append(v.Threats, csafThreat{
			Category:   "impact",
			Details:    statementDetail(s, in.BundleID),
			ProductIDs: []string{pid},
		})
		if s.Result.Verdict == decide.VerdictNotAffected && s.Result.Justification != "" {
			v.Flags = append(v.Flags, csafFlag{
				Label:      string(s.Result.Justification),
				ProductIDs: []string{pid},
			})
		}
	}

	doc := csafDoc{
		Document: csafDocument{
			Category:    "csaf_vex",
			CSAFVersion: "2.0",
			Title:       "LADING VEX",
			Publisher: csafPublisher{
				Category:  "vendor",
				Name:      PublisherName,
				Namespace: PublisherNamespace,
			},
			Tracking: csafTracking{
				ID:                 csafTrackingID(in),
				Version:            "1",
				Status:             "final",
				InitialReleaseDate: in.Timestamp,
				CurrentReleaseDate: in.Timestamp,
				Generator: csafGenerator{
					Date: in.Timestamp,
					Engine: csafEngine{
						Name:    "lading",
						Version: decide.ToolVersion,
					},
				},
				RevisionHistory: []csafRevision{{
					Number:  "1",
					Date:    in.Timestamp,
					Summary: "Initial version.",
				}},
			},
			Notes: []csafNote{{
				Category: "legal_disclaimer",
				Text:     DocumentDisclaimer(),
				Audience: "all",
			}},
		},
		ProductTree:     buildCSAFProductTree(products),
		Vulnerabilities: sortedCSAFVulns(vulnGroups),
	}
	return marshalCanonical(doc)
}

type csafProductBranch struct {
	ProductID string
	PURL      string
	Name      string
	Version   string
}

func buildCSAFProductTree(products map[string]csafProductBranch) csafProductTree {
	pids := make([]string, 0, len(products))
	for pid := range products {
		pids = append(pids, pid)
	}
	sortStrings(pids)

	var branches []csafBranch
	for _, pid := range pids {
		p := products[pid]
		ver := p.Version
		if ver == "" {
			ver = "0"
		}
		branches = append(branches, csafBranch{
			Category: "vendor",
			Name:     PublisherName,
			Branches: []csafBranch{{
				Category: "product_name",
				Name:     p.Name,
				Branches: []csafBranch{{
					Category: "product_version",
					Name:     ver,
					Product: &csafProduct{
						Name:      fmt.Sprintf("%s %s", p.Name, ver),
						ProductID: pid,
						ProductIDs: map[string]string{
							"purl": p.PURL,
						},
					},
				}},
			}},
		})
	}
	return csafProductTree{Branches: branches}
}

func sortedCSAFVulns(groups map[csafVulnKey]*csafVulnerability) []csafVulnerability {
	keys := make([]csafVulnKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j].cve < keys[i].cve ||
				(keys[j].cve == keys[i].cve && keys[j].status < keys[i].status) {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	out := make([]csafVulnerability, 0, len(keys))
	for _, k := range keys {
		out = append(out, *groups[k])
	}
	return out
}

func componentVersion(pinnedPURL string) string {
	at := strings.LastIndex(pinnedPURL, "@")
	if at < 0 {
		return ""
	}
	end := len(pinnedPURL)
	if q := strings.Index(pinnedPURL[at:], "?"); q >= 0 {
		end = at + q
	}
	return pinnedPURL[at+1 : end]
}

func appendUnique(list []string, v string) []string {
	for _, s := range list {
		if s == v {
			return list
		}
	}
	return append(list, v)
}
