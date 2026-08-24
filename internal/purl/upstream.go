package purl

import (
	"net/url"
	"strings"
)

// ParseUpstream extracts the upstream source-package name and optional version
// from the upstream= qualifier on deb/rpm/apk PURLs. The qualifier is a
// third-party assertion and must not be treated as evidence.
//
// Returns ok=false when the qualifier is absent. Never guesses.
func ParseUpstream(purlStr string) (name, version string, ok bool) {
	p, err := Canonicalize(strings.TrimSpace(purlStr))
	if err != nil {
		return "", "", false
	}
	switch p.Type {
	case "deb", "apk", "rpm":
	default:
		return "", "", false
	}

	raw, present := p.Qualifiers["upstream"]
	if !present || strings.TrimSpace(raw) == "" {
		return "", "", false
	}

	val := decodeUpstreamValue(raw)
	name, version, _ = strings.Cut(val, "@")
	name = stripSrcRPMName(name)
	if name == "" {
		return "", "", false
	}
	return name, version, true
}

func decodeUpstreamValue(raw string) string {
	dec, err := url.PathUnescape(raw)
	if err != nil {
		return raw
	}
	return dec
}

// stripSrcRPMName recovers the bare source name from an RPM source package
// filename (e.g. vim-8.2.2637-26.el9_8.4.src.rpm → vim).
func stripSrcRPMName(name string) string {
	if !strings.HasSuffix(name, ".src.rpm") {
		return name
	}
	base := strings.TrimSuffix(name, ".src.rpm")
	parts := strings.Split(base, "-")
	if len(parts) >= 3 {
		return parts[0]
	}
	if len(parts) == 2 {
		return parts[0]
	}
	return base
}
