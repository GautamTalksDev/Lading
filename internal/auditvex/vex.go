//nolint:govet // JSON DTOs; field order follows wire format
package auditvex

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/gautamtalksdev/lading/internal/purl"
)

type vexStatement struct {
	Document      string
	Vulnerability string
	ProductPURLs  []string
	ProductIDs    []string
	Platforms     []string
	Status        string
	Justification string
	IndirectPURL  bool
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
			ID   string   `json:"@id"`
			IDs  []string `json:"identifiers"`
			PURL string   `json:"purl"`
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
			Status:        mapOpenVEXStatus(st.Status),
		})
	}
	return out, nil
}

func mapOpenVEXStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "not_affected":
		return "known_not_affected"
	case "fixed":
		return "fixed"
	case "affected":
		return "known_affected"
	case "under_investigation":
		return "under_investigation"
	default:
		return s
	}
}

type cdxVEXDoc struct {
	Vulnerabilities []struct {
		ID      string `json:"id"`
		Affects []struct {
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
		status := ""
		if v.Analysis != nil {
			status = mapOpenVEXStatus(v.Analysis.State)
		}
		out = append(out, vexStatement{
			Document:      docName,
			Vulnerability: v.ID,
			ProductPURLs:  products,
			Status:        status,
		})
	}
	return out, nil
}

type csafDoc struct {
	Vulnerabilities []csafVulnerability `json:"vulnerabilities"`
	ProductTree     *csafProductTree    `json:"product_tree"`
}

type csafVulnerability struct {
	CVE           string              `json:"cve"`
	ProductStatus map[string][]string `json:"product_status"`
	Flags         []csafFlag          `json:"flags"`
}

type csafFlag struct {
	Label      string   `json:"label"`
	ProductIDs []string `json:"product_ids"`
}

type csafProductTree struct {
	Branches      []csafBranch       `json:"branches"`
	Relationships []csafRelationship `json:"relationships"`
}

type csafBranch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Product  *csafProduct `json:"product"`
	Branches []csafBranch `json:"branches"`
}

type csafProduct struct {
	ID     string            `json:"product_id"`
	Name   string            `json:"name"`
	Helper map[string]string `json:"product_identification_helper"`
}

type csafRelationship struct {
	Category                  string `json:"category"`
	ProductReference          string `json:"product_reference"`
	RelatesToProductReference string `json:"relates_to_product_reference"`
	FullProductName           struct {
		Name      string            `json:"name"`
		ProductID string            `json:"product_id"`
		Helper    map[string]string `json:"product_identification_helper"`
	} `json:"full_product_name"`
}

type csafProductEntry struct {
	PURL     string
	Platform string
	Indirect bool
}

func parseCSAF(docName string, data []byte) ([]vexStatement, error) {
	var doc csafDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	idToProduct := map[string]csafProductEntry{}
	registerProduct := func(productID, platform, rawPURL string, indirect bool) {
		productID = strings.TrimSpace(productID)
		rawPURL = strings.TrimSpace(rawPURL)
		if productID == "" || rawPURL == "" {
			return
		}
		if existing, ok := idToProduct[productID]; ok {
			if existing.PURL == rawPURL {
				if existing.Platform == "" && platform != "" {
					existing.Platform = platform
				}
				if indirect {
					existing.Indirect = true
				}
				idToProduct[productID] = existing
			}
			return
		}
		idToProduct[productID] = csafProductEntry{
			PURL:     rawPURL,
			Platform: platform,
			Indirect: indirect,
		}
	}

	var walkBranches func([]csafBranch)
	walkBranches = func(branches []csafBranch) {
		for _, b := range branches {
			if b.Product != nil {
				pid := b.Product.ID
				if pid == "" {
					pid = b.Product.Name
				}
				if p := helperPURL(b.Product.Helper); p != "" {
					registerProduct(pid, "", p, false)
				}
			}
			walkBranches(b.Branches)
		}
	}
	if doc.ProductTree != nil {
		walkBranches(doc.ProductTree.Branches)
		for _, rel := range doc.ProductTree.Relationships {
			pid := rel.FullProductName.ProductID
			platform := rel.RelatesToProductReference
			if p := helperPURL(rel.FullProductName.Helper); p != "" {
				registerProduct(pid, platform, p, false)
				continue
			}
			if ref, ok := idToProduct[rel.ProductReference]; ok {
				registerProduct(pid, platform, ref.PURL, true)
			}
		}
	}

	var out []vexStatement
	for _, v := range doc.Vulnerabilities {
		for status, ids := range v.ProductStatus {
			for _, id := range ids {
				entry, ok := idToProduct[id]
				if !ok {
					if strings.HasPrefix(id, "pkg:") {
						out = append(out, csafStatement(docName, v.CVE, id, id, "", status, flagJustification(id, v.Flags), false)...)
					}
					continue
				}
				out = append(out, csafStatement(docName, v.CVE, entry.PURL, id, entry.Platform, status, flagJustification(id, v.Flags), entry.Indirect)...)
			}
		}
	}
	return out, nil
}

func csafStatement(docName, cve, purlRaw, productID, platform, status, justification string, indirect bool) []vexStatement {
	purlRaw = strings.TrimSpace(purlRaw)
	if purlRaw == "" {
		return nil
	}
	var platforms []string
	if platform != "" {
		platforms = []string{platform}
	}
	return []vexStatement{{
		Document:      docName,
		Vulnerability: cve,
		ProductPURLs:  []string{purlRaw},
		ProductIDs:    []string{productID},
		Platforms:     platforms,
		Status:        status,
		Justification: justification,
		IndirectPURL:  indirect,
	}}
}

func helperPURL(h map[string]string) string {
	if h == nil {
		return ""
	}
	return strings.TrimSpace(h["purl"])
}

func flagJustification(productID string, flags []csafFlag) string {
	for _, f := range flags {
		for _, pid := range f.ProductIDs {
			if pid == productID {
				return f.Label
			}
		}
	}
	return ""
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

func purlHasVersion(raw string) bool {
	p, err := purl.Canonicalize(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return p.Version != ""
}

func isSuppressionStatement(st vexStatement) bool {
	switch st.Status {
	case "", "known_not_affected":
		return true
	default:
		return false
	}
}
