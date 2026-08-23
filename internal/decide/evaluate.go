package decide

import (
	"github.com/gautamtalksdev/lading/internal/purl"
)

// Evaluate applies evidence-v1 rules. See SPEC-EVIDENCE.md.
func Evaluate(in Input) (Result, error) {
	ctx, err := buildContext(in)
	if err != nil {
		return Result{}, err
	}

	base := Result{
		ManifestVersion: ctx.manifestVersion,
		ToolVersion:     ToolVersion,
		InputsUsed:      ctx.inputsUsed,
	}

	if code, ok := checkD03(ctx); ok {
		base.Verdict = VerdictUnderInvestigation
		base.RuleID = RuleD03
		base.ReasonCode = code
		return base, nil
	}

	if ctx.anyDefinitivePresent() {
		base.Verdict = VerdictAffected
		base.RuleID = RuleD04
		return base, nil
	}

	if ctx.componentIdentified && len(ctx.definitiveSymbols) > 0 {
		base.Verdict = VerdictNotAffected
		base.Justification = JustificationVulnerableCodeNotPresent
		base.RuleID = RuleD02
		return base, nil
	}

	if !ctx.componentIdentified && ctx.anyUsableSymbolTable() &&
		ctx.purlQuality.AtLeast(purl.TypeNormalized) {
		base.Verdict = VerdictNotAffected
		base.Justification = JustificationComponentNotPresent
		base.RuleID = RuleD01
		return base, nil
	}

	base.Verdict = VerdictUnderInvestigation
	base.RuleID = RuleD03
	base.ReasonCode = ReasonDefaultInsufficient
	return base, nil
}
