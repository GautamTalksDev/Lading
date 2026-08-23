package scan

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// Report is the human/machine-readable scan summary.
type Report struct {
	ArtifactDescription string
	BinariesScanned     int
	Stripped            int
	StaticLinked        int
	CVEsIn              int
	NotAffectedTotal    int
	NotAffectedByJust   map[string]int
	Affected            int
	RefusedTotal        int
	RefusedByReason     map[string]int
	CoveragePercent     int
}

// ComputeCoverage sets CoveragePercent from decided / total findings.
func (r *Report) ComputeCoverage() {
	if r.CVEsIn == 0 {
		r.CoveragePercent = 0
		return
	}
	decided := r.NotAffectedTotal + r.Affected
	r.CoveragePercent = (decided * 100) / r.CVEsIn
}

// WriteHuman prints the 7am-readable summary.
func (r Report) WriteHuman(w io.Writer, color bool) {
	if r.NotAffectedByJust == nil {
		r.NotAffectedByJust = map[string]int{}
	}
	if r.RefusedByReason == nil {
		r.RefusedByReason = map[string]int{}
	}
	paint := func(code, s string) string {
		if !color {
			return s
		}
		return "\033[" + code + "m" + s + "\033[0m"
	}
	_, _ = fmt.Fprintf(w, "Scanned:      %d binaries (%d stripped, %d static)\n",
		r.BinariesScanned, r.Stripped, r.StaticLinked)
	_, _ = fmt.Fprintf(w, "CVEs in:      %d\n", r.CVEsIn)
	na := fmt.Sprintf("Not affected:  %d", r.NotAffectedTotal)
	if d := breakdownDetail(r.NotAffectedByJust); d != "" {
		na += "  (" + d + ")"
	}
	_, _ = fmt.Fprintln(w, paint("32", na))
	_, _ = fmt.Fprintf(w, "Affected:      %d\n", r.Affected)
	ref := fmt.Sprintf("Refused:      %d", r.RefusedTotal)
	if d := breakdownDetail(r.RefusedByReason); d != "" {
		ref += "  (" + d + ")"
	}
	_, _ = fmt.Fprintln(w, paint("33", ref))
	_, _ = fmt.Fprintf(w, "Coverage:     %d%% of reported CVEs decided with evidence\n", r.CoveragePercent)
}

// WriteJSON prints a minimal JSON summary.
func (r Report) WriteJSON(w io.Writer) {
	just := sortedMap(r.NotAffectedByJust)
	refused := sortedMap(r.RefusedByReason)
	_, _ = fmt.Fprintf(w, `{"binaries_scanned":%d,"stripped":%d,"static_linked":%d,"cves_in":%d,"not_affected":%d,"not_affected_breakdown":%s,"affected":%d,"refused":%d,"refused_breakdown":%s,"coverage_percent":%d}`+"\n",
		r.BinariesScanned, r.Stripped, r.StaticLinked, r.CVEsIn,
		r.NotAffectedTotal, just, r.Affected, r.RefusedTotal, refused, r.CoveragePercent)
}

func breakdownDetail(parts map[string]int) string {
	if len(parts) == 0 {
		return ""
	}
	keys := make([]string, 0, len(parts))
	for k := range parts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var detail []string
	for _, k := range keys {
		detail = append(detail, fmt.Sprintf("%s %d", SanitizeForTerminal(k), parts[k]))
	}
	return strings.Join(detail, ", ")
}

func sortedMap(m map[string]int) string {
	if len(m) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%q:%d", SanitizeForTerminal(k), m[k])
	}
	b.WriteByte('}')
	return b.String()
}

// IsTerminal reports whether f is a character device (TTY).
func IsTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
