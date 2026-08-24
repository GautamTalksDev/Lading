package decide

import (
	"strings"

	"github.com/gautamtalksdev/lading/internal/manifest"
	"github.com/gautamtalksdev/lading/internal/purl"
)

type identityResolution struct {
	findingPURL   purl.PURL
	matchPURL     purl.PURL
	refusal       ReasonCode
	identityMapped bool
}

func resolveIdentity(finding purl.PURL, aliases *manifest.IdentityAliases) identityResolution {
	res := identityResolution{
		findingPURL: finding,
		matchPURL:   finding,
	}
	if aliases == nil || !isDistroPURL(finding) {
		return res
	}

	sourceName, upstreamVer, hasUpstream := purl.ParseUpstream(finding.Raw)
	if !hasUpstream {
		res.refusal = ReasonNoIdentityMapping
		return res
	}

	alias, ok := aliases.Lookup(sourceName)
	if !ok {
		res.refusal = ReasonNoIdentityMapping
		return res
	}

	if alias.Status == manifest.AliasStatusProbable {
		res.refusal = ReasonMappingProbableOnly
		return res
	}

	if strings.TrimSpace(upstreamVer) == "" {
		res.refusal = ReasonVersionUnderivable
		return res
	}

	component := strings.TrimSpace(alias.Component)
	resolvedRaw := component
	if !strings.Contains(component, "@") {
		resolvedRaw = component + "@" + upstreamVer
	}

	resolved, err := purl.Canonicalize(resolvedRaw)
	if err != nil {
		res.refusal = ReasonVersionUnderivable
		return res
	}

	res.matchPURL = resolved
	res.identityMapped = true
	return res
}

func isDistroPURL(p purl.PURL) bool {
	switch p.Type {
	case "deb", "apk", "rpm":
		return true
	default:
		return false
	}
}

func applyIdentityMappedQuality(base purl.MatchQuality, identityMapped bool) purl.MatchQuality {
	if !identityMapped {
		return base
	}
	if base >= purl.TypeNormalized {
		return purl.IdentityMapped
	}
	return base
}
