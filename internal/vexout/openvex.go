package vexout

import (
	"strings"

	"github.com/gautamtalksdev/lading/internal/decide"
)

type openVEXDoc struct {
	Context   string            `json:"@context"`
	ID        string            `json:"@id"`
	Author    string            `json:"author"`
	Role      string            `json:"role,omitempty"`
	Timestamp string            `json:"timestamp"`
	Version   int               `json:"version"`
	Tooling   string            `json:"tooling,omitempty"`
	Statements []openVEXStatement `json:"statements"`
}

type openVEXStatement struct {
	Vulnerability struct {
		Name string `json:"name"`
	} `json:"vulnerability"`
	Products         []openVEXProduct `json:"products"`
	Status           string           `json:"status"`
	Justification    string           `json:"justification,omitempty"`
	ImpactStatement  string           `json:"impact_statement,omitempty"`
	ActionStatement  string           `json:"action_statement,omitempty"`
}

type openVEXProduct struct {
	ID          string `json:"@id"`
	Identifiers *struct {
		PURL string `json:"purl"`
	} `json:"identifiers,omitempty"`
	Hashes *struct {
		SHA256 string `json:"sha-256"`
	} `json:"hashes,omitempty"`
}

func emitOpenVEX(in DocumentInput) ([]byte, error) {
	doc := openVEXDoc{
		Context:   "https://openvex.dev/ns/v0.2.0",
		ID:        documentID(in, "openvex"),
		Author:    Author,
		Role:      "document creator",
		Timestamp: in.Timestamp,
		Version:   1,
		Tooling:   decide.ToolVersion + " | " + DocumentDisclaimer(),
	}
	sha := artifactSHA256Hex(in)
	for _, s := range sortedStatements(in) {
		status, err := openVEXStatus(s.Result.Verdict)
		if err != nil {
			return nil, err
		}
		pinned, err := DigestPinnedPURL(s.ComponentPURL, in.ArtifactSHA256)
		if err != nil {
			return nil, err
		}
		st := openVEXStatement{
			Status:          status,
			ImpactStatement: statementDetail(s, in.BundleID),
		}
		st.Vulnerability.Name = strings.ToUpper(strings.TrimSpace(s.CVE))
		st.Products = []openVEXProduct{{
			ID: pinned,
			Identifiers: &struct {
				PURL string `json:"purl"`
			}{PURL: pinned},
			Hashes: &struct {
				SHA256 string `json:"sha-256"`
			}{SHA256: sha},
		}}
		if s.Result.Verdict == decide.VerdictNotAffected && s.Result.Justification != "" {
			st.Justification = string(s.Result.Justification)
		}
		if s.Result.Verdict == decide.VerdictAffected {
			st.ActionStatement = "Vulnerable code observed in scanned artifact per " + string(s.Result.RuleID) + "."
		}
		doc.Statements = append(doc.Statements, st)
	}
	return marshalCanonical(doc)
}
