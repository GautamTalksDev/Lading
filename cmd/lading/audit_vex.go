package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/gautamtalksdev/lading/internal/auditvex"
	"github.com/spf13/cobra"
)

func newAuditVEXCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "audit-vex <sbom> <vex>...",
		Short: "Audit third-party VEX documents against an SBOM for inert or over-broad matches",
		Long: `Load an SBOM and one or more VEX documents (OpenVEX, CycloneDX, CSAF).
For each statement, report which SBOM components matched and at what
MatchQuality.

Exit 1 if any statement is:
  - inert:       no Exact/TypeNormalized match (Grype-class silent miss)
  - overbroad:   Exact/TypeNormalized match on a subcomponent only
                 (Trivy-class cross-product suppression)
  - versionless: known_not_affected on a PURL with no version

MatchQuality is always reported — never a bare boolean.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			sbom := args[0]
			vexs := args[1:]
			rep, err := auditvex.Audit(sbom, vexs)
			if err != nil {
				return err
			}
			printAuditReport(rep)
			if rep.HasFailures() {
				return errAuditFailed
			}
			return nil
		},
		SilenceUsage: true,
	}
}

var errAuditFailed = fmt.Errorf("audit-vex: inert, over-broad, or versionless statements present")

func printAuditReport(rep auditvex.Report) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "STATUS\tVULN\tBEST\tMATCHES\tDETAIL")
	for _, r := range rep.Results {
		matchSummary := "—"
		if len(r.Matches) > 0 {
			matchSummary = fmt.Sprintf("%d", len(r.Matches))
			for _, m := range r.Matches {
				root := "sub"
				if m.Component.IsRoot {
					root = "root"
				}
				_, _ = fmt.Fprintf(os.Stderr, "  match %s (%s) quality=%s purl=%s\n",
					m.Component.Name, root, m.Quality, m.Component.PURL.Canonical())
			}
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			r.Status, r.Vulnerability, r.Best, matchSummary, r.Detail)
	}
	_ = w.Flush()
}
