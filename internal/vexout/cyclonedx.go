package vexout

import (
	"strings"

	"github.com/gautamtalksdev/lading/internal/decide"
)

type cycloneDXDoc struct {
	BOMFormat   string              `json:"bomFormat"`
	SpecVersion string              `json:"specVersion"`
	SerialNumber string             `json:"serialNumber"`
	Version     int                 `json:"version"`
	Metadata    cycloneDXMetadata   `json:"metadata"`
	Components  []cycloneDXComponent `json:"components"`
	Vulnerabilities []cycloneDXVuln  `json:"vulnerabilities"`
}

type cycloneDXMetadata struct {
	Timestamp  string               `json:"timestamp"`
	Component  cycloneDXComponent   `json:"component"`
	Tools      []cycloneDXTool      `json:"tools"`
	Properties []cycloneDXProperty  `json:"properties,omitempty"`
}

type cycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cycloneDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cycloneDXComponent struct {
	BOMRef string `json:"bom-ref"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	PURL   string `json:"purl"`
	Hashes []cycloneDXHash `json:"hashes,omitempty"`
}

type cycloneDXHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cycloneDXVuln struct {
	ID       string              `json:"id"`
	Analysis cycloneDXAnalysis   `json:"analysis"`
	Affects  []cycloneDXAffects  `json:"affects"`
}

type cycloneDXAnalysis struct {
	State         string `json:"state"`
	Justification string `json:"justification,omitempty"`
	Detail        string `json:"detail"`
	FirstIssued   string `json:"firstIssued"`
	LastUpdated   string `json:"lastUpdated"`
}

type cycloneDXAffects struct {
	Ref string `json:"ref"`
}

func emitCycloneDX(in DocumentInput) ([]byte, error) {
	seed := documentSeed(in, "cyclonedx")
	components := map[string]cycloneDXComponent{}
	var vulns []cycloneDXVuln
	sha := artifactSHA256Hex(in)

	for _, s := range sortedStatements(in) {
		pinned, err := DigestPinnedPURL(s.ComponentPURL, in.ArtifactSHA256)
		if err != nil {
			return nil, err
		}
		ref := productRef(pinned)
		if _, ok := components[ref]; !ok {
			components[ref] = cycloneDXComponent{
				BOMRef: ref,
				Type:   "library",
				Name:   componentName(pinned),
				PURL:   pinned,
				Hashes: []cycloneDXHash{{
					Alg:     "SHA-256",
					Content: sha,
				}},
			}
		}
		state, err := cycloneDXState(s.Result.Verdict)
		if err != nil {
			return nil, err
		}
		analysis := cycloneDXAnalysis{
			State:       state,
			Detail:      statementDetail(s, in.BundleID),
			FirstIssued: in.Timestamp,
			LastUpdated: in.Timestamp,
		}
		if s.Result.Verdict == decide.VerdictNotAffected {
			analysis.Justification = cycloneDXJustification(s.Result.Justification)
		}
		vulns = append(vulns, cycloneDXVuln{
			ID:       strings.ToUpper(strings.TrimSpace(s.CVE)),
			Analysis: analysis,
			Affects:  []cycloneDXAffects{{Ref: ref}},
		})
	}

	compList := make([]cycloneDXComponent, 0, len(components))
	refs := make([]string, 0, len(components))
	for ref := range components {
		refs = append(refs, ref)
	}
	sortStrings(refs)
	for _, ref := range refs {
		compList = append(compList, components[ref])
	}

	artifactPinned, err := DigestPinnedPURL("pkg:generic/lading-artifact@0", in.ArtifactSHA256)
	if err != nil {
		return nil, err
	}

	doc := cycloneDXDoc{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: deterministicUUID(seed),
		Version:      1,
		Metadata: cycloneDXMetadata{
			Timestamp: in.Timestamp,
			Component: cycloneDXComponent{
				BOMRef: "lading:artifact",
				Type:   "application",
				Name:   "lading-scanned-artifact",
				PURL:   artifactPinned,
				Hashes: []cycloneDXHash{{
					Alg:     "SHA-256",
					Content: sha,
				}},
			},
			Tools: []cycloneDXTool{{
				Vendor:  "lading",
				Name:    "lading",
				Version: decide.ToolVersion,
			}},
			Properties: []cycloneDXProperty{{
				Name:  MetadataDisclaimerKey,
				Value: DocumentDisclaimer(),
			}},
		},
		Components:      compList,
		Vulnerabilities: vulns,
	}
	return marshalCanonical(doc)
}

func componentName(pinnedPURL string) string {
	at := strings.LastIndex(pinnedPURL, "@")
	if at < 0 {
		return pinnedPURL
	}
	slash := strings.LastIndex(pinnedPURL[:at], "/")
	if slash < 0 {
		return pinnedPURL[4:at]
	}
	return pinnedPURL[slash+1 : at]
}

func sortStrings(in []string) {
	for i := 0; i < len(in); i++ {
		for j := i + 1; j < len(in); j++ {
			if in[j] < in[i] {
				in[i], in[j] = in[j], in[i]
			}
		}
	}
}
