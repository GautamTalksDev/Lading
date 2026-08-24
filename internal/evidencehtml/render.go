package evidencehtml

import (
	"fmt"
	"html"
	"strings"

	"github.com/gautamtalksdev/lading/internal/legal"
)

// Render emits deterministic UTF-8 HTML for a pack.
func Render(p Pack) []byte {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
	b.WriteString("<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"generator\" content=\"")
	b.WriteString(html.EscapeString(p.FormatVersion))
	b.WriteString("\">\n<title>LADING Evidence Pack</title>\n<style>\n")
	b.WriteString("body{font-family:system-ui,sans-serif;margin:2rem;line-height:1.45;max-width:960px}\n")
	b.WriteString("table{border-collapse:collapse;width:100%;margin:1rem 0;font-size:0.9rem}\n")
	b.WriteString("th,td{border:1px solid #ccc;padding:0.35rem 0.5rem;text-align:left;vertical-align:top}\n")
	b.WriteString("th{background:#f4f4f4}code,pre{font-family:ui-monospace,monospace;font-size:0.85rem}\n")
	b.WriteString(".limitation{background:#fff8e6;border:1px solid #e6c200;padding:0.75rem;margin:1rem 0}\n")
	b.WriteString("</style>\n</head>\n<body>\n")

	b.WriteString("<h1>LADING Evidence Pack</h1>\n")
	b.WriteString("<p><strong>Format:</strong> ")
	b.WriteString(html.EscapeString(p.FormatVersion))
	b.WriteString(" · <strong>Generated:</strong> ")
	b.WriteString(html.EscapeString(p.Timestamp))
	b.WriteString("</p>\n")

	b.WriteString("<h2>Artifact identity</h2>\n<table>\n")
	writeRow(&b, "Catalogue ID", p.Artifact.ID)
	writeRow(&b, "Name", p.Artifact.Name)
	writeRow(&b, "Class", p.Artifact.Class)
	writeRow(&b, "SHA-256 (catalogue)", p.Artifact.SHA256)
	writeRow(&b, "Source URL", p.Artifact.SourceURL)
	writeRow(&b, "Fetched at", p.Artifact.FetchedAt)
	writeRow(&b, "Scan path", p.Artifact.ScanPath)
	b.WriteString("</table>\n")

	b.WriteString("<h2>Tool versions</h2>\n<table>\n")
	writeRow(&b, "LADING evidence format", p.Tools.LadingFormat)
	writeRow(&b, "Decision engine", p.Tools.DecideVersion)
	writeRow(&b, "Manifest version", p.Tools.ManifestVersion)
	writeRow(&b, "Scanner", p.Tools.GrypeName+" "+p.Tools.GrypeVersion)
	dbBuilt := p.Tools.GrypeDBBuilt
	if dbBuilt == "" {
		dbBuilt = "(not recorded in grype.json descriptor)"
	}
	writeRow(&b, "Scanner DB timestamp", dbBuilt)
	b.WriteString("</table>\n")

	b.WriteString("<h2>Scan summary</h2>\n<table>\n")
	writeRowInt(&b, "CVEs considered", p.Summary.CVEsIn)
	writeRowInt(&b, "NOT_AFFECTED", p.Summary.NotAffected)
	writeRowInt(&b, "AFFECTED", p.Summary.Affected)
	writeRowInt(&b, "Refused", p.Summary.Refused)
	writeRowInt(&b, "Binaries inventoried", p.Summary.BinariesScanned)
	b.WriteString("</table>\n")

	b.WriteString("<h2>Decisions</h2>\n<table>\n<thead><tr>")
	for _, h := range []string{"CVE", "PURL", "Verdict", "Rule", "Reason", "Detail"} {
		b.WriteString("<th>")
		b.WriteString(html.EscapeString(h))
		b.WriteString("</th>")
	}
	b.WriteString("</tr></thead>\n<tbody>\n")
	for _, row := range p.Rows {
		b.WriteString("<tr><td>")
		b.WriteString(html.EscapeString(row.CVE))
		b.WriteString("</td><td><code>")
		b.WriteString(html.EscapeString(row.ComponentPURL))
		b.WriteString("</code></td><td>")
		b.WriteString(html.EscapeString(row.Verdict))
		b.WriteString("</td><td>")
		b.WriteString(html.EscapeString(row.RuleID))
		b.WriteString("</td><td>")
		b.WriteString(html.EscapeString(row.ReasonCode))
		b.WriteString("</td><td>")
		b.WriteString(html.EscapeString(rowDetail(row)))
		b.WriteString("</td></tr>\n")
	}
	b.WriteString("</tbody></table>\n")

	b.WriteString("<h2>NOT_AFFECTED evidence</h2>\n")
	naCount := 0
	for _, row := range p.Rows {
		if row.Verdict != "NOT_AFFECTED" {
			continue
		}
		naCount++
		b.WriteString("<section>\n<h3>")
		b.WriteString(html.EscapeString(row.CVE))
		b.WriteString(" · ")
		b.WriteString(html.EscapeString(row.ComponentPURL))
		b.WriteString("</h3>\n<table>\n")
		writeRow(&b, "Justification", row.Justification)
		writeRow(&b, "Evidence kind", row.EvidenceKind)
		writeRow(&b, "Manifest component", row.ManifestComponent)
		writeRow(&b, "Manifest provenance", row.ManifestProvenance)
		writeRow(&b, "Identity source", row.IdentitySource)
		writeRow(&b, "Identity mapping", row.IdentityMappingStatus)
		writeRow(&b, "Identity component", row.IdentityComponent)
		writeRow(&b, "Component identified", fmt.Sprintf("%t", row.ComponentIdentified))
		if len(row.SymbolsAbsent) > 0 {
			writeRow(&b, "Symbols absent", strings.Join(row.SymbolsAbsent, ", "))
		}
		if row.BundleStatementID != "" {
			writeRow(&b, "Bundle statement", row.BundleStatementID)
		}
		b.WriteString("</table>\n</section>\n")
	}
	if naCount == 0 {
		b.WriteString("<p><em>None.</em></p>\n")
	}

	b.WriteString("<h2>Refusals</h2>\n")
	refCount := 0
	for _, row := range p.Rows {
		if row.Verdict != "UNDER_INVESTIGATION" {
			continue
		}
		refCount++
	}
	if refCount == 0 {
		b.WriteString("<p><em>None.</em></p>\n")
	} else {
		b.WriteString("<table>\n<thead><tr>")
		for _, h := range []string{"CVE", "PURL", "Rule", "Reason code"} {
			b.WriteString("<th>")
			b.WriteString(html.EscapeString(h))
			b.WriteString("</th>")
		}
		b.WriteString("</tr></thead>\n<tbody>\n")
		for _, row := range p.Rows {
			if row.Verdict != "UNDER_INVESTIGATION" {
				continue
			}
			b.WriteString("<tr><td>")
			b.WriteString(html.EscapeString(row.CVE))
			b.WriteString("</td><td><code>")
			b.WriteString(html.EscapeString(row.ComponentPURL))
			b.WriteString("</code></td><td>")
			b.WriteString(html.EscapeString(row.RuleID))
			b.WriteString("</td><td>")
			b.WriteString(html.EscapeString(row.ReasonCode))
			b.WriteString("</td></tr>\n")
		}
		b.WriteString("</tbody></table>\n")
	}

	b.WriteString("<h2>What this pack does NOT prove</h2>\n")
	for _, lim := range p.Limitations {
		b.WriteString("<p class=\"limitation\">")
		b.WriteString(html.EscapeString(lim))
		b.WriteString("</p>\n")
	}
	b.WriteString("<p><em>")
	b.WriteString(html.EscapeString(legal.DisclaimerShort))
	b.WriteString("</em></p>\n")

	b.WriteString("<h2>Re-derivation</h2>\n<pre>")
	b.WriteString(html.EscapeString(p.Rederivation))
	b.WriteString("</pre>\n")

	b.WriteString("</body>\n</html>\n")
	return []byte(b.String())
}

func rowDetail(row Row) string {
	switch row.Verdict {
	case "NOT_AFFECTED":
		parts := []string{
			"justification=" + row.Justification,
			"evidence=" + row.EvidenceKind,
		}
		if row.ManifestComponent != "" {
			parts = append(parts, "manifest="+row.ManifestComponent)
			parts = append(parts, "provenance="+row.ManifestProvenance)
		}
		if row.IdentityMappingStatus != "" {
			parts = append(parts, fmt.Sprintf("identity=%s (%s→%s)", row.IdentityMappingStatus, row.IdentitySource, row.IdentityComponent))
		}
		if len(row.SymbolsAbsent) > 0 {
			parts = append(parts, "symbols_absent="+strings.Join(row.SymbolsAbsent, ","))
		}
		if row.EvidenceKind == "component_not_present" || !row.ComponentIdentified {
			parts = append(parts, "component_identified=false")
		}
		if row.BundleStatementID != "" {
			parts = append(parts, "bundle="+row.BundleStatementID)
		}
		return strings.Join(parts, "; ")
	case "UNDER_INVESTIGATION":
		return "refusal=" + row.ReasonCode
	case "AFFECTED":
		if len(row.SymbolsPresent) > 0 {
			return "symbols_present=" + strings.Join(row.SymbolsPresent, ",")
		}
		return "affected"
	default:
		return row.Justification
	}
}

func writeRow(b *strings.Builder, label, value string) {
	b.WriteString("<tr><th>")
	b.WriteString(html.EscapeString(label))
	b.WriteString("</th><td>")
	b.WriteString(html.EscapeString(value))
	b.WriteString("</td></tr>\n")
}

func writeRowInt(b *strings.Builder, label string, value int) {
	writeRow(b, label, fmt.Sprintf("%d", value))
}
