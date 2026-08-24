package purl

import (
	"regexp"
	"strings"
)

// DeriveUpstreamVersion extracts an upstream version from a distro PURL's
// package version when the upstream= qualifier has no @version segment.
// Implements SPEC-IDENTITY §2.1 algorithms deterministically (no guessing).
func DeriveUpstreamVersion(p PURL) (version string, ok bool) {
	raw := strings.TrimSpace(p.Version)
	if raw == "" {
		return "", false
	}
	switch p.Type {
	case "deb":
		return debianUpstreamFromVersion(raw)
	case "apk":
		return alpineUpstreamFromPkgver(raw)
	case "rpm":
		return rpmUpstreamFromNVR(raw)
	default:
		return "", false
	}
}

func debianUpstreamFromVersion(v string) (string, bool) {
	// Strip epoch (N:)
	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[i+1:]
	}
	// Upstream portion before first '-' (Debian revision)
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v = v[:i]
	}
	v = normalizeUpstreamVersion(v)
	if v == "" || strings.Contains(v, "%") {
		return "", false
	}
	return v, true
}

func alpineUpstreamFromPkgver(v string) (string, bool) {
	// Strip -rN revision suffix
	if i := strings.LastIndex(v, "-r"); i >= 0 {
		rev := v[i+2:]
		if rev != "" && isAllDigits(rev) {
			v = v[:i]
		}
	}
	v = normalizeUpstreamVersion(v)
	if v == "" {
		return "", false
	}
	return v, true
}

var rpmReleaseSuffix = regexp.MustCompile(`-\d+(?:\.[A-Za-z0-9_]+)+$`)

func rpmUpstreamFromNVR(v string) (string, bool) {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[i+1:]
	}
	// Drop trailing release tag like -25.el9 or -26.el9_8.4
	v = rpmReleaseSuffix.ReplaceAllString(v, "")
	v = normalizeUpstreamVersion(v)
	if v == "" {
		return "", false
	}
	return v, true
}

var dfsgSuffix = regexp.MustCompile(`(?i)(?:[+.]?(?:dfsg|really|ubuntu)[^.-]*)$`)

func normalizeUpstreamVersion(v string) string {
	v = strings.TrimSpace(v)
	for {
		next := dfsgSuffix.ReplaceAllString(v, "")
		if next == v {
			break
		}
		v = next
	}
	return strings.Trim(v, ".")
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
