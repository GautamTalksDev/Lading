package manifestderive

import (
	"bufio"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// Side identifies which blob a changed line belongs to.
type Side int

const (
	SideOld Side = iota // deleted line → parent blob
	SideNew             // added line → commit blob
)

// ChangedLine is one added or deleted source line from a unified diff.
// Line is 1-based within Path's blob on Side. Hunk trailer names are ignored.
type ChangedLine struct {
	Path string
	Side Side
	Line int
}

// ParseUnifiedDiff extracts changed line numbers from a unified diff.
// It uses hunk line counters only — it never reads the optional function
// name that follows "@@" (those trailers are unreliable).
func ParseUnifiedDiff(diff string) ([]ChangedLine, error) {
	var out []ChangedLine
	var pathOld, pathNew string
	var oldLine, newLine int
	inHunk := false

	sc := bufio.NewScanner(strings.NewReader(diff))
	// Diffs can contain long lines; raise the limit.
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "--- "):
			inHunk = false
			pathOld = stripDiffPath(strings.TrimPrefix(line, "--- "))
		case strings.HasPrefix(line, "+++ "):
			inHunk = false
			pathNew = stripDiffPath(strings.TrimPrefix(line, "+++ "))
		case strings.HasPrefix(line, "@@"):
			ol, nl, err := parseHunkHeader(line)
			if err != nil {
				return nil, err
			}
			oldLine, newLine = ol, nl
			inHunk = true
		case !inHunk:
			continue
		case strings.HasPrefix(line, "+"):
			path := pathNew
			if path == "" || path == "/dev/null" {
				path = pathOld
			}
			if path != "" && path != "/dev/null" {
				out = append(out, ChangedLine{Path: path, Side: SideNew, Line: newLine})
			}
			newLine++
		case strings.HasPrefix(line, "-"):
			path := pathOld
			if path == "" || path == "/dev/null" {
				path = pathNew
			}
			if path != "" && path != "/dev/null" {
				out = append(out, ChangedLine{Path: path, Side: SideOld, Line: oldLine})
			}
			oldLine++
		default:
			// Context line (starts with space) or "\ No newline..."
			if strings.HasPrefix(line, "\\") {
				continue
			}
			oldLine++
			newLine++
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func stripDiffPath(s string) string {
	s = strings.TrimSpace(s)
	// "a/foo.c\t..." or "b/foo.c"
	if i := strings.IndexByte(s, '\t'); i >= 0 {
		s = s[:i]
	}
	if strings.HasPrefix(s, "a/") || strings.HasPrefix(s, "b/") {
		s = s[2:]
	}
	return s
}

// parseHunkHeader reads "@@ -oldStart,oldCount +newStart,newCount @@ ..." and
// returns the starting line numbers. The trailer after the second @@ is ignored.
func parseHunkHeader(line string) (oldStart, newStart int, err error) {
	// Find the two ranges between @@ markers without caring about the trailer.
	rest := strings.TrimPrefix(line, "@@")
	rest = strings.TrimSpace(rest)
	end := strings.Index(rest, "@@")
	if end >= 0 {
		rest = strings.TrimSpace(rest[:end])
	}
	parts := strings.Fields(rest)
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("malformed hunk header: %q", line)
	}
	oldStart, err = parseRangeStart(parts[0], '-')
	if err != nil {
		return 0, 0, err
	}
	newStart, err = parseRangeStart(parts[1], '+')
	if err != nil {
		return 0, 0, err
	}
	return oldStart, newStart, nil
}

func parseRangeStart(tok string, sign byte) (int, error) {
	if len(tok) < 2 || tok[0] != sign {
		return 0, fmt.Errorf("bad hunk range %q", tok)
	}
	body := tok[1:]
	if i := strings.IndexByte(body, ','); i >= 0 {
		body = body[:i]
	}
	n, err := strconv.Atoi(body)
	if err != nil {
		return 0, fmt.Errorf("bad hunk line %q: %w", tok, err)
	}
	// Unified diff uses 0 for empty file ranges; treat as line 1 for safety.
	if n == 0 {
		return 1, nil
	}
	return n, nil
}

// isCFamily reports whether path should be parsed for C/C++ functions.
func isCFamily(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".ipp", ".tcc":
		return true
	default:
		return false
	}
}
