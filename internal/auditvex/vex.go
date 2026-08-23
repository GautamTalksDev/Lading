//nolint:govet // JSON DTOs; field order follows wire format
package auditvex

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

type vexStatement struct {
	Document      string
	Vulnerability string
	ProductPURLs  []string
}

func parseVEX(path string, data []byte) ([]vexStatement, error) {
	var probe map[string]any
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("vex: not JSON: %w", err)
	}
	docName := filepath.Base(path)
	switch {
	case probe["@context"] != nil || hasOpenVEX(probe):
		return parseOpenVEX(docName, data)
	case probe["bomFormat"] != nil:
		return parseCycloneDXVEX(docName, data)
	case probe["document"] != nil || probe["vulnerabilities"] != nil && probe["product_tree"] != nil:
		return parseCSAF(docName, data)
	default:
		// CSAF sometimes only has document+vulnerabilities.
		if _, ok := probe["document"]; ok {
			return parseCSAF(docName, data)
		}
		return nil, fmt.Errorf("vex: unrecognized format in %s", docName)
	}
}

func hasOpenVEX(probe map[string]any) bool {
	if ctx, ok := probe["@context"].(string); ok && strings.Contains(ctx, "openvex") {
		return true
	}
	if _, ok := probe["statements"]; ok {
		if _, ok2 := probe["author"]; ok2 {
			return true
		}
	}
	return false
}

type openVEXDoc struct {
	Statements []struct {
		Vulnerability struct {
			Name string `json:"name"`
			ID   string `json:"@id"`
		} `json:"vulnerability"`
		Products []struct {
			ID    string `json:"@id"`
			IDs   []string `json:"identifiers"`
			PURL  string `json:"purl"`
		} `json:"products"`
		Status string `json:"status"`
	} `json:"statements"`
}

func parseOpenVEX(docName string, data []byte) ([]vexStatement, error) {
	var doc openVEXDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []vexStatement
	for _, st := range doc.Statements {
		vuln := st.Vulnerability.Name
		if vuln == "" {
			vuln = st.Vulnerability.ID
		}
		var products []string
		for _, p := range st.Products {
			if p.PURL != "" {
				products = append(products, p.PURL)
			}
			if strings.HasPrefix(p.ID, "pkg:") {
				products = append(products, p.ID)
			}
			for _, id := range p.IDs {
				if strings.HasPrefix(id, "pkg:") {
					products = append(products, id)
				}
			}
		}
		products = unique(products)
		if len(products) == 0 {
			continue
		}
		out = append(out, vexStatement{
			Document:      docName,
			Vulnerability: vuln,
			ProductPURLs:  products,
		})
	}
	return out, nil
}

type cdxVEXDoc struct {
	Vulnerabilities []struct {
		ID       string `json:"id"`
		Affects  []struct {
			Ref string `json:"ref"`
		} `json:"affects"`
		Analysis *struct {
			State string `json:"state"`
		} `json:"analysis"`
	} `json:"vulnerabilities"`
	Components []struct {
		BOMRef string `json:"bom-ref"`
		PURL   string `json:"purl"`
	} `json:"components"`
}

func parseCycloneDXVEX(docName string, data []byte) ([]vexStatement, error) {
	var doc cdxVEXDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	refToPURL := map[string]string{}
	for _, c := range doc.Components {
		if c.BOMRef != "" && c.PURL != "" {
			refToPURL[c.BOMRef] = c.PURL
		}
	}
	var out []vexStatement
	for _, v := range doc.Vulnerabilities {
		var products []string
		for _, a := range v.Affects {
			if strings.HasPrefix(a.Ref, "pkg:") {
				products = append(products, a.Ref)
			} else if p, ok := refToPURL[a.Ref]; ok {
				products = append(products, p)
			}
		}
		products = unique(products)
		if len(products) == 0 {
			continue
		}
		out = append(out, vexStatement{
			Document:      docName,
			Vulnerability: v.ID,
			ProductPURLs:  products,
		})
	}
	return out, nil
}

type csafDoc struct {
	Vulnerabilities []struct {
		CVE            string `json:"cve"`
		ProductStatus  map[string][]string `json:"product_status"`
	} `json:"vulnerabilities"`
	ProductTree *struct {
		Branches []csafBranch `json:"branches"`
	} `json:"product_tree"`
}

type csafBranch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Product  *csafProduct `json:"product"`
	Branches []csafBranch `json:"branches"`
}

type csafProduct struct {
	ID           string            `json:"product_id"`
	Name         string            `json:"name"`
	ProductIDs   map[string]string `json:"product_identification_helper"`
}

func parseCSAF(docName string, data []byte) ([]vexStatement, error) {
	var doc csafDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	idToPURL := map[string]string{}
	var walk func([]csafBranch)
	walk = func(branches []csafBranch) {
		for _, b := range branches {
			if b.Product != nil {
				pid := b.Product.ID
				if helper := b.Product.ProductIDs; helper != nil {
					if p := helper["purl"]; p != "" {
						idToPURL[pid] = p
					}
				}
			}
			walk(b.Branches)
		}
	}
	if doc.ProductTree != nil {
		walk(doc.ProductTree.Branches)
	}

	var out []vexStatement
	for _, v := range doc.Vulnerabilities {
		var products []string
		for _, ids := range v.ProductStatus {
			for _, id := range ids {
				if p, ok := idToPURL[id]; ok {
					products = append(products, p)
				} else if strings.HasPrefix(id, "pkg:") {
					products = append(products, id)
				}
			}
		}
		products = unique(products)
		if len(products) == 0 {
			continue
		}
		out = append(out, vexStatement{
			Document:      docName,
			Vulnerability: v.CVE,
			ProductPURLs:  products,
		})
	}
	return out, nil
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
