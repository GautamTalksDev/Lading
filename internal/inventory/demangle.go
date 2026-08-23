package inventory

import (
	"fmt"
	"strconv"
	"strings"
)

// demangleItanium implements a focused Itanium C++ ABI demangler covering
// the forms produced by our fixtures and common library symbols.
// It returns ok=false when the input is not a well-formed _Z encoding we
// understand; callers then keep the raw name.
func demangleItanium(name string) (string, bool) {
	if !strings.HasPrefix(name, "_Z") {
		return "", false
	}
	p := &itaniumParser{s: name, i: 2}
	n, ok := p.parseName()
	if !ok {
		return "", false
	}
	// Optional function type encoding after the name.
	if p.i < len(p.s) {
		params, pok := p.parseBareFunctionType()
		if pok {
			return n + "(" + strings.Join(params, ", ") + ")", true
		}
	}
	return n, true
}

type itaniumParser struct {
	s string
	i int
}

func (p *itaniumParser) peek() byte {
	if p.i >= len(p.s) {
		return 0
	}
	return p.s[p.i]
}

func (p *itaniumParser) take() byte {
	if p.i >= len(p.s) {
		return 0
	}
	b := p.s[p.i]
	p.i++
	return b
}

func (p *itaniumParser) parseName() (string, bool) {
	switch p.peek() {
	case 'N':
		return p.parseNestedName()
	case 'S':
		return p.parseSubstitution()
	default:
		return p.parseUnqualifiedName()
	}
}

func (p *itaniumParser) parseNestedName() (string, bool) {
	if p.take() != 'N' {
		return "", false
	}
	var parts []string
	for p.peek() != 'E' && p.peek() != 0 {
		// Skip CV-qualifiers / ref-qualifiers that can appear in nested names.
		for p.peek() == 'K' || p.peek() == 'V' || p.peek() == 'r' || p.peek() == 'R' || p.peek() == 'O' {
			p.take()
		}
		if p.peek() == 'E' {
			break
		}
		part, ok := p.parseUnqualifiedName()
		if !ok {
			// Try substitution inside nested name.
			part, ok = p.parseSubstitution()
			if !ok {
				return "", false
			}
		}
		parts = append(parts, part)
	}
	if p.take() != 'E' {
		return "", false
	}
	return strings.Join(parts, "::"), true
}

func (p *itaniumParser) parseUnqualifiedName() (string, bool) {
	// Operator encodings (common subset).
	if strings.HasPrefix(p.s[p.i:], "C1") || strings.HasPrefix(p.s[p.i:], "C2") || strings.HasPrefix(p.s[p.i:], "C3") {
		p.i += 2
		return "<constructor>", true
	}
	if strings.HasPrefix(p.s[p.i:], "D0") || strings.HasPrefix(p.s[p.i:], "D1") || strings.HasPrefix(p.s[p.i:], "D2") {
		p.i += 2
		return "<destructor>", true
	}
	return p.parseSourceName()
}

func (p *itaniumParser) parseSourceName() (string, bool) {
	start := p.i
	for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
		p.i++
	}
	if p.i == start {
		return "", false
	}
	n, err := strconv.Atoi(p.s[start:p.i])
	if err != nil || n <= 0 || p.i+n > len(p.s) {
		return "", false
	}
	name := p.s[p.i : p.i+n]
	p.i += n
	return name, true
}

func (p *itaniumParser) parseSubstitution() (string, bool) {
	if p.take() != 'S' {
		return "", false
	}
	// Std substitutions.
	switch p.peek() {
	case 't':
		p.take()
		return "std", true
	case 'a':
		p.take()
		return "std::allocator", true
	case 'b':
		p.take()
		return "std::basic_string", true
	case 's':
		p.take()
		return "std::string", true
	case 'i':
		p.take()
		return "std::istream", true
	case 'o':
		p.take()
		return "std::ostream", true
	case 'd':
		p.take()
		return "std::iostream", true
	case '_':
		p.take()
		return "std::placeholder", true
	}
	// S_<seq>_ form — treat as opaque.
	for p.peek() != '_' && p.peek() != 0 {
		p.take()
	}
	if p.peek() == '_' {
		p.take()
	}
	return "std::?", true
}

func (p *itaniumParser) parseBareFunctionType() ([]string, bool) {
	var params []string
	for p.i < len(p.s) {
		if p.peek() == 'v' { // void parameter list / end
			p.take()
			if len(params) == 0 {
				return []string{}, true
			}
			break
		}
		t, ok := p.parseType()
		if !ok {
			if len(params) == 0 {
				return nil, false
			}
			break
		}
		params = append(params, t)
	}
	return params, true
}

func (p *itaniumParser) parseType() (string, bool) {
	switch p.peek() {
	case 'v':
		p.take()
		return "void", true
	case 'b':
		p.take()
		return "bool", true
	case 'c':
		p.take()
		return "char", true
	case 'a':
		p.take()
		return "signed char", true
	case 'h':
		p.take()
		return "unsigned char", true
	case 's':
		p.take()
		return "short", true
	case 't':
		p.take()
		return "unsigned short", true
	case 'i':
		p.take()
		return "int", true
	case 'j':
		p.take()
		return "unsigned int", true
	case 'l':
		p.take()
		return "long", true
	case 'm':
		p.take()
		return "unsigned long", true
	case 'x':
		p.take()
		return "long long", true
	case 'y':
		p.take()
		return "unsigned long long", true
	case 'f':
		p.take()
		return "float", true
	case 'd':
		p.take()
		return "double", true
	case 'P':
		p.take()
		inner, ok := p.parseType()
		if !ok {
			return "", false
		}
		return inner + "*", true
	case 'R':
		p.take()
		inner, ok := p.parseType()
		if !ok {
			return "", false
		}
		return inner + "&", true
	case 'O':
		p.take()
		inner, ok := p.parseType()
		if !ok {
			return "", false
		}
		return inner + "&&", true
	case 'K':
		p.take()
		inner, ok := p.parseType()
		if !ok {
			return "", false
		}
		return "const " + inner, true
	case 'N', 'S':
		return p.parseName()
	default:
		// Length-prefixed class name used as a type.
		if p.peek() >= '0' && p.peek() <= '9' {
			return p.parseSourceName()
		}
		return "", false
	}
}

// Keep fmt referenced for potential debug; silence via usage in errors if needed.
var _ = fmt.Sprintf
