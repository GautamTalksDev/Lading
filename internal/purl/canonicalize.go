package purl

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Canonicalize parses raw per the Package URL specification and returns a
// normalized PURL. The original raw string is always preserved on the result.
func Canonicalize(raw string) (PURL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return PURL{}, fmt.Errorf("purl: empty string")
	}
	p := PURL{Raw: raw, Qualifiers: map[string]string{}}

	s := raw
	if strings.HasPrefix(strings.ToLower(s), "pkg:") {
		s = s[4:]
	} else {
		return PURL{}, fmt.Errorf("purl: missing pkg: scheme: %q", raw)
	}

	// Split subpath (#) then qualifiers (?) then version (@) — but @ in
	// namespace/name must be percent-encoded per spec. We split carefully.
	var subpath, qualStr string
	if i := strings.Index(s, "#"); i >= 0 {
		subpath = s[i+1:]
		s = s[:i]
	}
	if i := strings.Index(s, "?"); i >= 0 {
		qualStr = s[i+1:]
		s = s[:i]
	}

	typeRest := s
	slash := strings.Index(typeRest, "/")
	if slash < 0 {
		return PURL{}, fmt.Errorf("purl: missing type/name separator: %q", raw)
	}
	p.Type = strings.ToLower(typeRest[:slash])
	path := typeRest[slash+1:]

	// Version: last unencoded @ separates version.
	namePath := path
	if at := strings.LastIndex(path, "@"); at >= 0 {
		p.Version = decodeOnce(path[at+1:])
		namePath = path[:at]
	}

	// Namespace / name: split on last '/'.
	if namePath == "" {
		return PURL{}, fmt.Errorf("purl: empty name: %q", raw)
	}
	if i := strings.LastIndex(namePath, "/"); i >= 0 {
		p.Namespace = decodeOnce(namePath[:i])
		p.Name = decodeOnce(namePath[i+1:])
	} else {
		p.Name = decodeOnce(namePath)
	}
	if p.Name == "" {
		return PURL{}, fmt.Errorf("purl: empty name: %q", raw)
	}

	p.Subpath = decodeOnce(subpath)
	if qualStr != "" {
		q, err := parseQualifiers(qualStr)
		if err != nil {
			return PURL{}, err
		}
		p.Qualifiers = q
	}

	normalizeTypeSpecific(&p)
	return p, nil
}

func decodeOnce(s string) string {
	if s == "" {
		return s
	}
	// Decode percent-encoding exactly once; leave '+' literal (purl uses %20).
	dec, err := url.PathUnescape(s)
	if err != nil {
		return s
	}
	return dec
}

func parseQualifiers(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, part := range strings.Split(s, "&") {
		if part == "" {
			continue
		}
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("purl: malformed qualifier %q", part)
		}
		k := strings.ToLower(decodeOnce(key))
		v := decodeOnce(val)
		out[k] = v
	}
	return out, nil
}

func normalizeTypeSpecific(p *PURL) {
	switch p.Type {
	case "pypi":
		// PEP 503: lowercase, replace _, ., - with - for name; no namespace.
		p.Name = strings.ToLower(p.Name)
		p.Name = strings.NewReplacer("_", "-", ".", "-").Replace(p.Name)
		p.Namespace = ""
	case "npm":
		p.Name = strings.ToLower(p.Name)
		p.Namespace = strings.ToLower(p.Namespace)
	case "golang", "go":
		p.Type = "golang"
		p.Namespace = strings.ToLower(p.Namespace)
		p.Name = strings.ToLower(p.Name)
	case "nuget":
		// Case-insensitive name; no namespace.
		p.Name = strings.ToLower(p.Name)
		p.Namespace = ""
	case "cargo", "crate":
		p.Type = "cargo"
		p.Name = strings.ToLower(p.Name)
		p.Namespace = ""
	case "gem", "rubygems":
		p.Type = "gem"
		p.Name = strings.ToLower(p.Name)
		p.Namespace = ""
	case "deb", "apk", "rpm", "generic", "github", "bitbucket", "gitlab",
		"maven", "composer", "swift", "hex", "huggingface", "mlflow", "oci", "docker":
		// Type already lowercased; leave namespace/name case as decoded unless
		// the type conventionally folds (handled above).
	default:
		// Unknown types: type lowercased only.
	}
}

func formatCanonical(p PURL) string {
	if p.Type == "" || p.Name == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(p.Type)
	b.WriteByte('/')
	if p.Namespace != "" {
		b.WriteString(encodeSeg(p.Namespace))
		b.WriteByte('/')
	}
	b.WriteString(encodeSeg(p.Name))
	if p.Version != "" {
		b.WriteByte('@')
		b.WriteString(encodeSeg(p.Version))
	}
	if len(p.Qualifiers) > 0 {
		keys := make([]string, 0, len(p.Qualifiers))
		for k := range p.Qualifiers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('?')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte('&')
			}
			b.WriteString(url.QueryEscape(k))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(p.Qualifiers[k]))
		}
	}
	if p.Subpath != "" {
		b.WriteByte('#')
		b.WriteString(encodeSeg(p.Subpath))
	}
	return b.String()
}

func encodeSeg(s string) string {
	// Encode path segments; keep '/' in namespace already split.
	return strings.ReplaceAll(url.PathEscape(s), "+", "%20")
}
