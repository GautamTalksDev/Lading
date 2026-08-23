// Command lading is the CLI entrypoint for the LADING compliance evidence tool.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/gautamtalksdev/lading/internal/legal"
	"github.com/spf13/cobra"
)

const helpDisclaimerBlock = "\n\n---\n" + legal.DisclaimerShort + "\nFull text: DISCLAIMER.md\n"

func main() {
	root := &cobra.Command{
		Use:   "lading",
		Short: "Deterministic compliance evidence for binary vulnerability triage",
		Long: strings.TrimSpace(`
LADING produces re-derivable evidence bundles for regulatory filings.
It does not give legal advice.

` + legal.DisclaimerShort),
	}
	attachHelpDisclaimer(root)
	root.AddCommand(newAuditVEXCmd())
	root.AddCommand(newManifestCmd())
	root.AddCommand(newVerifyCmd())
	root.AddCommand(newVEXCmd())
	root.AddCommand(newSignCmd())
	root.AddCommand(newScanCmd())
	root.AddCommand(newExplainCmd())
	root.AddCommand(newUnpackInternalCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		var se *scanExitError
		if errors.As(err, &se) {
			os.Exit(se.Code)
		}
		os.Exit(1)
	}
}

func attachHelpDisclaimer(cmd *cobra.Command) {
	orig := cmd.HelpFunc()
	cmd.SetHelpFunc(func(c *cobra.Command, args []string) {
		orig(c, args)
		fmt.Fprint(c.OutOrStdout(), helpDisclaimerBlock)
	})
	for _, sub := range cmd.Commands() {
		attachHelpDisclaimer(sub)
	}
}
