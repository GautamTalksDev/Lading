package scan

import (
	"regexp"
	"strings"
)

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]|\x1b\].*?(\x07|\x1b\\)`)

// SanitizeForTerminal strips attacker-controlled terminal control sequences
// from strings extracted from binaries before printing.
func SanitizeForTerminal(s string) string {
	s = ansiPattern.ReplaceAllString(s, "")
	var b strings.Builder
	for _, r := range s {
		if isBidiOverride(r) {
			continue
		}
		if r == '\n' || r == '\t' || (r >= 0x20 && r < 0x7f) {
			b.WriteRune(r)
			continue
		}
		if r < 0x20 {
			continue
		}
		b.WriteRune('?')
	}
	return b.String()
}

func isBidiOverride(r rune) bool {
	switch r {
	case '\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
		'\u2066', '\u2067', '\u2068', '\u2069':
		return true
	default:
		return false
	}
}

// SafeLabel sanitizes and truncates a label for display.
func SafeLabel(s string, max int) string {
	s = SanitizeForTerminal(strings.TrimSpace(s))
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
