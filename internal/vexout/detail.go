package vexout

import (
	"fmt"
	"strings"

	"github.com/gautamtalksdev/lading/internal/decide"
)

// ImpactDetail names the rule, manifest version, and evidence bundle ID.
func ImpactDetail(ruleID, manifestVersion, bundleID string) string {
	return fmt.Sprintf("rule_id=%s manifest_version=%s bundle_id=%s",
		strings.TrimSpace(ruleID),
		strings.TrimSpace(manifestVersion),
		strings.TrimSpace(bundleID),
	)
}

func statementDetail(s Statement, bundleID string) string {
	return ImpactDetail(string(s.Result.RuleID), s.Result.ManifestVersion, bundleID)
}

func openVEXStatus(v decide.Verdict) (string, error) {
	switch v {
	case decide.VerdictNotAffected:
		return "not_affected", nil
	case decide.VerdictAffected:
		return "affected", nil
	case decide.VerdictUnderInvestigation:
		return "under_investigation", nil
	default:
		return "", fmt.Errorf("vexout: unknown verdict %q", v)
	}
}

func cycloneDXState(v decide.Verdict) (string, error) {
	switch v {
	case decide.VerdictNotAffected:
		return "not_affected", nil
	case decide.VerdictAffected:
		return "exploitable", nil
	case decide.VerdictUnderInvestigation:
		return "in_triage", nil
	default:
		return "", fmt.Errorf("vexout: unknown verdict %q", v)
	}
}

func cycloneDXJustification(j decide.Justification) string {
	switch j {
	case decide.JustificationComponentNotPresent:
		return "code_not_present"
	case decide.JustificationVulnerableCodeNotPresent:
		return "code_not_present"
	default:
		return ""
	}
}

func csafStatusKey(v decide.Verdict) (string, error) {
	switch v {
	case decide.VerdictNotAffected:
		return "known_not_affected", nil
	case decide.VerdictAffected:
		return "known_affected", nil
	case decide.VerdictUnderInvestigation:
		return "under_investigation", nil
	default:
		return "", fmt.Errorf("vexout: unknown verdict %q", v)
	}
}
