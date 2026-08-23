//go:build cgo

package manifestderive

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	tsC "github.com/smacker/go-tree-sitter/c"
	tsCPP "github.com/smacker/go-tree-sitter/cpp"
)

// EnclosingFunctions returns sorted unique function names whose definitions
// enclose any of the given 1-based line numbers in src.
// lang is "c" or "cpp"; empty selects by path extension.
func EnclosingFunctions(src []byte, lines []int, path, lang string) ([]string, error) {
	if len(src) == 0 || len(lines) == 0 {
		return nil, nil
	}
	language, err := pickLanguage(path, lang)
	if err != nil {
		return nil, err
	}
	root, err := sitter.ParseCtx(context.Background(), src, language)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	funcs := collectFunctionSpans(root, src)

	want := map[int]struct{}{}
	for _, ln := range lines {
		want[ln] = struct{}{}
	}
	names := map[string]struct{}{}
	for _, fn := range funcs {
		for ln := range want {
			if ln >= fn.startLine && ln <= fn.endLine {
				if fn.name != "" {
					names[fn.name] = struct{}{}
				}
				break
			}
		}
	}
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

type funcSpan struct {
	name      string
	startLine int // 1-based
	endLine   int
}

func pickLanguage(path, lang string) (*sitter.Language, error) {
	switch strings.ToLower(strings.TrimSpace(lang)) {
	case "c":
		return tsC.GetLanguage(), nil
	case "cpp", "c++", "cxx":
		return tsCPP.GetLanguage(), nil
	case "":
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".c", ".h":
			return tsC.GetLanguage(), nil
		case ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx", ".ipp", ".tcc":
			return tsCPP.GetLanguage(), nil
		default:
			return tsC.GetLanguage(), nil
		}
	default:
		return nil, fmt.Errorf("unknown language %q", lang)
	}
}

// collectFunctionSpans finds function_definition nodes and recovers definitions
// that tree-sitter left under ERROR (common with ZEXPORT / attribute macros).
func collectFunctionSpans(root *sitter.Node, src []byte) []funcSpan {
	var out []funcSpan
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "function_definition":
			name := functionName(n, src)
			out = append(out, funcSpan{
				name:      name,
				startLine: int(n.StartPoint().Row) + 1,
				endLine:   int(n.EndPoint().Row) + 1,
			})
			// Still walk children: nested functions are rare in C but fine.
		case "ERROR":
			out = append(out, recoverFunctionsFromError(n, src)...)
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(root)
	return out
}

// recoverFunctionsFromError pairs function_declarator nodes with a following
// compound_statement inside an ERROR region.
func recoverFunctionsFromError(errNode *sitter.Node, src []byte) []funcSpan {
	var decls []*sitter.Node
	var bodies []*sitter.Node
	var collect func(n *sitter.Node)
	collect = func(n *sitter.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "function_declarator":
			decls = append(decls, n)
		case "compound_statement":
			bodies = append(bodies, n)
			return // don't recurse into body for nested decls as top-level pair targets
		case "function_definition":
			// Already handled by main walk if we recurse; skip pairing.
			return
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			collect(n.NamedChild(i))
		}
	}
	collect(errNode)

	var out []funcSpan
	usedBody := map[int]struct{}{}
	for _, d := range decls {
		name := nameFromDeclarator(d, src)
		if name == "" {
			continue
		}
		dStart := int(d.StartPoint().Row) + 1
		dEnd := int(d.EndPoint().Row) + 1
		// Pair with the first compound_statement that starts at/after declarator end.
		best := -1
		bestStart := int(^uint(0) >> 1)
		for i, b := range bodies {
			if _, ok := usedBody[i]; ok {
				continue
			}
			bStart := int(b.StartPoint().Row) + 1
			if bStart < dEnd {
				continue
			}
			if bStart < bestStart {
				bestStart = bStart
				best = i
			}
		}
		if best < 0 {
			continue
		}
		usedBody[best] = struct{}{}
		b := bodies[best]
		out = append(out, funcSpan{
			name:      name,
			startLine: dStart,
			endLine:   int(b.EndPoint().Row) + 1,
		})
	}
	return out
}

// functionName extracts the defined function's identifier from a
// function_definition node. Walks declarators; does not trust diff trailers.
func functionName(fn *sitter.Node, src []byte) string {
	if fn == nil {
		return ""
	}
	decl := fn.ChildByFieldName("declarator")
	if decl == nil {
		return ""
	}
	return nameFromDeclarator(decl, src)
}

func nameFromDeclarator(n *sitter.Node, src []byte) string {
	if n == nil {
		return ""
	}
	switch n.Type() {
	case "function_declarator":
		inner := n.ChildByFieldName("declarator")
		return nameFromDeclarator(inner, src)
	case "identifier", "field_identifier":
		return n.Content(src)
	case "qualified_identifier", "destructor_name", "operator_name":
		return normalizeSymbol(n.Content(src))
	case "pointer_declarator", "reference_declarator", "array_declarator",
		"parenthesized_declarator", "attributed_declarator":
		inner := n.ChildByFieldName("declarator")
		if inner == nil && n.NamedChildCount() > 0 {
			inner = n.NamedChild(0)
		}
		return nameFromDeclarator(inner, src)
	default:
		for i := 0; i < int(n.NamedChildCount()); i++ {
			ch := n.NamedChild(i)
			if ch.Type() == "function_declarator" {
				return nameFromDeclarator(ch, src)
			}
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if s := nameFromDeclarator(n.NamedChild(i), src); s != "" {
				return s
			}
		}
		return ""
	}
}

func normalizeSymbol(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, " ", "")
	return s
}
