package vexout

import (
	"fmt"
	"strings"

	"github.com/gautamtalksdev/lading/internal/purl"
)

// DigestPinnedPURL returns a canonical PURL with a sha256 checksum qualifier
// when artifactSHA256 is present. This pins product identity to the scanned
// artifact digest, not just name/version.
func DigestPinnedPURL(base, artifactSHA256 string) (string, error) {
	p, err := purl.Canonicalize(base)
	if err != nil {
		return "", fmt.Errorf("vexout: digest pin: %w", err)
	}
	hex := strings.ToLower(strings.TrimSpace(artifactSHA256))
	if hex != "" {
		if p.Qualifiers == nil {
			p.Qualifiers = map[string]string{}
		}
		p.Qualifiers["checksum"] = "sha256:" + hex
	}
	return p.Canonical(), nil
}
