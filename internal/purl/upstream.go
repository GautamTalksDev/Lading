package purl

import (
	"net/url"
	"regexp"
	"strings"
)

// ParseUpstream extracts the upstream source-package name and optional version
// from the upstream= qualifier on deb/rpm/apk PURLs. The qualifier is a
// third-party assertion and must not be treated as evidence.
//
// Returns ok=false when the qualifier is absent. Never guesses.
//
// Normalisation (merge defects observed in corpus histograms):
//   - URL-decode before splitting on @ (util-linux%402.41-5)
//   - Strip RPM source filenames (vim-8.2.2637-26.el9_8.4.src.rpm → vim)
//   - Map Debian source-name variants (gnutls28→gnutls, glib2.0→glib, gcc-12→gcc)
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
	name = NormalizeUpstreamSourceName(name)
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
	// Qualifiers may still carry a literal %40 if double-encoded once.
	if strings.Contains(dec, "%") {
		if again, err := url.PathUnescape(dec); err == nil {
			dec = again
		}
	}
	return dec
}

// NormalizeUpstreamSourceName recovers a bare upstream source name so deb/rpm
// siblings share one alias key. Safe for already-bare names.
func NormalizeUpstreamSourceName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	name = stripSrcRPMName(name)
	if mapped, ok := debianSourceVariants[name]; ok {
		return mapped
	}
	return name
}

// debianSourceVariants maps Debian source-package naming quirks to the bare
// upstream name used in identity aliases / Manifest components.
var debianSourceVariants = map[string]string{
	"gnutls28": "gnutls",
	"glib2.0":  "glib",
	"gcc-12":   "gcc",
	"gcc-13":   "gcc",
	"gcc-14":   "gcc",
}

// versionLike matches RPM version / release segments (start with a digit).
var versionLike = regexp.MustCompile(`^\d`)

// stripSrcRPMName recovers the bare source name from an RPM source package
// filename (e.g. vim-8.2.2637-26.el9_8.4.src.rpm → vim,
// util-linux-2.37.4-18.el9.src.rpm → util-linux).
//
// NVR rule: drop trailing hyphen-separated segments that look like version or
// release (start with a digit), from the right, until a non-version segment
// remains. Package names may themselves contain hyphens.
func stripSrcRPMName(name string) string {
	if !strings.HasSuffix(name, ".src.rpm") {
		return name
	}
	base := strings.TrimSuffix(name, ".src.rpm")
	parts := strings.Split(base, "-")
	if len(parts) == 1 {
		return base
	}
	// Drop release (last) then version (new last) when they look version-like.
	for len(parts) > 1 && versionLike.MatchString(parts[len(parts)-1]) {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 {
		return base
	}
	return strings.Join(parts, "-")
}
