//nolint:govet // JSON DTOs; field order follows wire format
package auditvex

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/gautamtalksdev/lading/internal/purl"
)

// LoadSBOM reads CycloneDX or SPDX JSON from path.
func LoadSBOM(path string) ([]Component, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("sbom: read: %w", err)
	}
	return parseSBOM(data)
}

// Minimal CycloneDX / SPDX SBOM extraction (JSON only, stdlib).

// Minimal CycloneDX / SPDX SBOM extraction (JSON only, stdlib).

type cdxDoc struct {
	BOMFormat string `json:"bomFormat"`
	Metadata  *struct {
		Component *cdxComp `json:"component"`
	} `json:"metadata"`
	Components []cdxComp `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
}

type cdxComp struct {
	BOMRef string `json:"bom-ref"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	PURL   string `json:"purl"`
}

type spdxDoc struct {
	SPDXVersion string `json:"spdxVersion"`
	Packages    []struct {
		Name     string `json:"name"`
		SPDXID   string `json:"SPDXID"`
		Primary  bool   `json:"primaryPackagePurpose"` // not standard; ignore
		External []struct {
			ReferenceType string `json:"referenceType"`
			ReferenceLocator string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
	Relationships []struct {
		Type string `json:"relationshipType"`
		A    string `json:"spdxElementId"`
		B    string `json:"relatedSpdxElement"`
	} `json:"relationships"`
}

func parseSBOM(data []byte) ([]Component, error) {
	var probe map[string]any
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("sbom: not JSON: %w", err)
	}
	if _, ok := probe["bomFormat"]; ok {
		return parseCycloneDX(data)
	}
	if _, ok := probe["spdxVersion"]; ok {
		return parseSPDX(data)
	}
	return nil, fmt.Errorf("sbom: unrecognized format (need CycloneDX or SPDX JSON)")
}

func parseCycloneDX(data []byte) ([]Component, error) {
	var doc cdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	rootRefs := map[string]bool{}
	if doc.Metadata != nil && doc.Metadata.Component != nil && doc.Metadata.Component.BOMRef != "" {
		rootRefs[doc.Metadata.Component.BOMRef] = true
	}
	// Components depended upon by someone are non-roots if we can tell.
	dependedOn := map[string]bool{}
	for _, d := range doc.Dependencies {
		for _, child := range d.DependsOn {
			dependedOn[child] = true
		}
	}

	var out []Component
	add := func(c cdxComp, forceRoot bool) error {
		if c.PURL == "" {
			return nil
		}
		p, err := purl.Canonicalize(c.PURL)
		if err != nil {
			return fmt.Errorf("sbom component %q: %w", c.Name, err)
		}
		isRoot := forceRoot || rootRefs[c.BOMRef]
		if !forceRoot && c.BOMRef != "" && dependedOn[c.BOMRef] {
			isRoot = false
		}
		// Heuristic: application/firmware/container at top are roots.
		if c.Type == "application" || c.Type == "container" || c.Type == "firmware" || c.Type == "device" {
			if !dependedOn[c.BOMRef] {
				isRoot = true
			}
		}
		out = append(out, Component{Name: c.Name, PURL: p, IsRoot: isRoot})
		return nil
	}

	if doc.Metadata != nil && doc.Metadata.Component != nil {
		if err := add(*doc.Metadata.Component, true); err != nil {
			return nil, err
		}
	}
	for i := range doc.Components {
		if err := add(doc.Components[i], false); err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("sbom: no components with purl")
	}
	return out, nil
}

func parseSPDX(data []byte) ([]Component, error) {
	var doc spdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	described := map[string]bool{}
	for _, r := range doc.Relationships {
		if r.Type == "DESCRIBES" && r.A == "SPDXRef-DOCUMENT" {
			described[r.B] = true
		}
	}
	var out []Component
	for _, pkg := range doc.Packages {
		var raw string
		for _, ref := range pkg.External {
			if ref.ReferenceType == "purl" {
				raw = ref.ReferenceLocator
				break
			}
		}
		if raw == "" {
			continue
		}
		p, err := purl.Canonicalize(raw)
		if err != nil {
			return nil, fmt.Errorf("spdx package %q: %w", pkg.Name, err)
		}
		out = append(out, Component{
			Name:   pkg.Name,
			PURL:   p,
			IsRoot: described[pkg.SPDXID] || len(described) == 0 && len(out) == 0,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("sbom: no SPDX packages with purl")
	}
	return out, nil
}
