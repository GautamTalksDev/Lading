// Command lading is the CLI entrypoint for the LADING compliance evidence tool.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "lading",
		Short: "Deterministic compliance evidence for binary vulnerability triage",
		Long:  "LADING produces re-derivable evidence bundles for regulatory filings. It does not give legal advice.",
	}
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
