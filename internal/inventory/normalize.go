package inventory

import (
	"strings"
	"unicode/utf8"
)

// Normalize derives the comparison key from a demangled (or raw) name.
// Version suffixes belong in Symbol.Version and must already be absent here.
//
// __wrap_ / __real_ / a single leading underscore are stripped from the
// normalized form but remain visible in Raw/Demangled.
func Normalize(demangled string) string {
	s := strings.TrimSpace(demangled)
	for {
		switch {
		case strings.HasPrefix(s, "__wrap_"):
			s = strings.TrimPrefix(s, "__wrap_")
		case strings.HasPrefix(s, "__real_"):
			s = strings.TrimPrefix(s, "__real_")
		case strings.HasPrefix(s, "_") && !strings.HasPrefix(s, "__"):
			s = s[1:]
		default:
			return s
		}
	}
}

// Demangle applies Itanium C++ ABI demangling. Unmangled or undecodable
// names are returned unchanged.
func Demangle(name string) string {
	in := name
	if strings.HasPrefix(in, "__Z") {
		in = in[1:]
	}
	if !strings.HasPrefix(in, "_Z") {
		return name
	}
	d, ok := demangleItanium(in)
	if !ok || d == "" {
		return name
	}
	return d
}

// printableStrings extracts NUL-terminated printable ASCII runs of at least
// minLen from section data only (caller supplies RO section bytes).
func printableStrings(data []byte, minLen int) []string {
	if minLen < 1 {
		minLen = 1
	}
	var out []string
	start := -1
	flush := func(end int) {
		if start < 0 {
			return
		}
		if end-start >= minLen {
			s := string(data[start:end])
			if utf8.ValidString(s) {
				out = append(out, s)
			}
		}
		start = -1
	}
	for i := 0; i < len(data); i++ {
		b := data[i]
		if b >= 32 && b <= 126 {
			if start < 0 {
				start = i
			}
			continue
		}
		if b == 0 {
			flush(i)
			continue
		}
		start = -1
	}
	return out
}
