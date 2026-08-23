package vexout

import (
	"fmt"
	"time"

	"github.com/gautamtalksdev/lading/internal/decide"
)

// Emit produces OpenVEX, CycloneDX 1.6, CSAF 2.0 VEX, and refusals.json.
func Emit(in DocumentInput) (Output, error) {
	if err := validateInput(in); err != nil {
		return Output{}, err
	}
	openVEX, err := emitOpenVEX(in)
	if err != nil {
		return Output{}, err
	}
	cdx, err := emitCycloneDX(in)
	if err != nil {
		return Output{}, err
	}
	csaf, err := emitCSAF(in)
	if err != nil {
		return Output{}, err
	}
	refusals, summary, err := emitRefusals(in)
	if err != nil {
		return Output{}, err
	}
	return Output{
		OpenVEX:   openVEX,
		CycloneDX: cdx,
		CSAF:      csaf,
		Refusals:  refusals,
		Summary:   summary,
	}, nil
}

func validateInput(in DocumentInput) error {
	if in.BundleID == "" {
		return fmt.Errorf("vexout: bundle_id required")
	}
	if in.ArtifactSHA256 == "" {
		return fmt.Errorf("vexout: artifact_sha256 required")
	}
	if in.Timestamp == "" {
		return fmt.Errorf("vexout: timestamp required")
	}
	if _, err := time.Parse(time.RFC3339, in.Timestamp); err != nil {
		return fmt.Errorf("vexout: timestamp must be RFC3339 UTC: %w", err)
	}
	if len(in.Statements) == 0 {
		return fmt.Errorf("vexout: at least one statement required")
	}
	for i, s := range in.Statements {
		if s.CVE == "" {
			return fmt.Errorf("vexout: statement %d: cve required", i)
		}
		if s.ComponentPURL == "" {
			return fmt.Errorf("vexout: statement %d: component_purl required", i)
		}
	}
	return nil
}

func buildSummary(stmts []Statement) Summary {
	sum := Summary{Total: len(stmts)}
	for _, s := range stmts {
		switch s.Result.Verdict {
		case decide.VerdictNotAffected:
			sum.Cleared++
		case decide.VerdictAffected:
			sum.Affected++
		case decide.VerdictUnderInvestigation:
			sum.Refusals++
		}
	}
	return sum
}
