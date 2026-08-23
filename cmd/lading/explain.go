package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/gautamtalksdev/lading/internal/explain"
	"github.com/spf13/cobra"
)

func newExplainCmd() *cobra.Command {
	var bundleDir, purl string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "explain <CVE>",
		Short: "Explain why a verdict was reached for a CVE",
		Long: `Print a compliance-oriented explanation for one evidence-bundle
statement: rule ID, symbols consulted, manifest provenance URLs, and what
LADING did not claim.

Requires an evidence bundle produced by lading scan.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if bundleDir == "" {
				return fmt.Errorf("explain: --bundle is required")
			}
			rep, err := explain.Explain(explain.Options{
				BundleDir: bundleDir,
				CVE:       args[0],
				PURL:      purl,
			})
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(rep)
			}
			_, _ = fmt.Fprint(os.Stdout, explain.FormatHuman(rep))
			return nil
		},
		SilenceUsage: true,
	}
	cmd.Flags().StringVar(&bundleDir, "bundle", "", "Evidence bundle directory from lading scan")
	cmd.Flags().StringVar(&purl, "purl", "", "Disambiguate when multiple statements share a CVE")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Machine-readable JSON")
	return cmd
}
