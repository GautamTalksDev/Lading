package vexout

import (
	"strings"

	"github.com/gautamtalksdev/lading/internal/decide"
)

type refusalsDoc struct {
	Format     string          `json:"format"`
	BundleID   string          `json:"bundle_id"`
	Disclaimer string          `json:"disclaimer"`
	Count      int             `json:"count"`
	Refusals   []refusalRecord `json:"refusals"`
}

type refusalRecord struct {
	StatementID     string `json:"statement_id,omitempty"`
	CVE             string `json:"cve"`
	ComponentPURL   string `json:"component_purl"`
	ReasonCode      string `json:"reason_code"`
	RuleID          string `json:"rule_id"`
	ManifestVersion string `json:"manifest_version"`
	BundleID        string `json:"bundle_id"`
	Detail          string `json:"detail"`
}

func emitRefusals(in DocumentInput) ([]byte, Summary, error) {
	summary := buildSummary(in.Statements)
	var records []refusalRecord
	for _, s := range sortedStatements(in) {
		if s.Result.Verdict != decide.VerdictUnderInvestigation {
			continue
		}
		pinned, err := DigestPinnedPURL(s.ComponentPURL, in.ArtifactSHA256)
		if err != nil {
			return nil, summary, err
		}
		records = append(records, refusalRecord{
			StatementID:     s.StatementID,
			CVE:             strings.ToUpper(strings.TrimSpace(s.CVE)),
			ComponentPURL:   pinned,
			ReasonCode:      string(s.Result.ReasonCode),
			RuleID:          string(s.Result.RuleID),
			ManifestVersion: s.Result.ManifestVersion,
			BundleID:        in.BundleID,
			Detail:          statementDetail(s, in.BundleID),
		})
	}
	doc := refusalsDoc{
		Format:     RefusalsFormat,
		BundleID:   in.BundleID,
		Disclaimer: DocumentDisclaimer(),
		Count:      len(records),
		Refusals:   records,
	}
	if doc.Refusals == nil {
		doc.Refusals = []refusalRecord{}
	}
	data, err := marshalCanonical(doc)
	return data, summary, err
}
