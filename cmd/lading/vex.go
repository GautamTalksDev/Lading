package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gautamtalksdev/lading/internal/vexout"
	"github.com/spf13/cobra"
)

func newVEXCmd() *cobra.Command {
	var timestamp string
	var outDir string

	emit := &cobra.Command{
		Use:   "emit --bundle DIR",
		Short: "Emit OpenVEX, CycloneDX 1.6, CSAF 2.0 VEX, and refusals.json",
		Long: `Read a LADING evidence bundle and emit three VEX documents plus
refusals.json. Product identifiers are digest-pinned when an artifact SHA-256
is present. Output is deterministic for identical inputs.

Signing is never automatic — use "lading sign" separately.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			bundle, _ := cmd.Flags().GetString("bundle")
			if bundle == "" {
				return fmt.Errorf("vex emit: --bundle is required")
			}
			in, err := vexout.LoadFromBundle(bundle, timestamp)
			if err != nil {
				return err
			}
			output, err := vexout.Emit(in)
			if err != nil {
				return err
			}
			if outDir == "" {
				outDir = "."
			}
			files := map[string][]byte{
				"vex.openvex.json": output.OpenVEX,
				"vex.cdx.json":     output.CycloneDX,
				"vex.csaf.json":      output.CSAF,
				"refusals.json":      output.Refusals,
			}
			for name, data := range files {
				path := filepath.Join(outDir, name)
				if err := os.WriteFile(path, data, 0o600); err != nil {
					return fmt.Errorf("write %s: %w", path, err)
				}
			}
			printVEXSummary(output.Summary, outDir)
			return nil
		},
		SilenceUsage: true,
	}
	emit.Flags().String("bundle", "", "Evidence bundle directory")
	emit.Flags().StringVar(&timestamp, "timestamp", "", "RFC3339 UTC document timestamp (default: derived from bundle_id)")
	emit.Flags().StringVar(&outDir, "out", ".", "Output directory")

	root := &cobra.Command{
		Use:   "vex",
		Short: "Emit VEX documents from evidence bundles",
	}
	root.AddCommand(emit)
	return root
}

func printVEXSummary(s vexout.Summary, outDir string) {
	_, _ = fmt.Fprintf(os.Stdout, "VEX emit complete → %s\n", outDir)
	_, _ = fmt.Fprintf(os.Stdout, "  cleared (NOT_AFFECTED):     %d\n", s.Cleared)
	_, _ = fmt.Fprintf(os.Stdout, "  refusals (UNDER_INVESTIG.): %d\n", s.Refusals)
	_, _ = fmt.Fprintf(os.Stdout, "  affected:                   %d\n", s.Affected)
	_, _ = fmt.Fprintf(os.Stdout, "  total statements:           %d\n", s.Total)
}
