package main

import (
	"fmt"

	"github.com/gautamtalksdev/lading/internal/evidence"
	"github.com/spf13/cobra"
)

func newVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <artifact> <vex.json> <evidence-bundle>",
		Short: "Independently verify VEX statements against an evidence bundle",
		Long: `Re-derive every verdict from the artifact and the manifest slice embedded
in the evidence bundle. Compare results to the supplied VEX document.

AIR-GAPPED GUARANTEE: lading verify performs ZERO network requests. It reads
only the artifact path, VEX file, and evidence bundle on local disk. No Manifest
tree, registry, or remote API is consulted — verification uses manifest-slice.json
inside the bundle only.`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := evidence.Verify(evidence.VerifyOptions{
				ArtifactPath: args[0],
				VEXPath:      args[1],
				BundleDir:    args[2],
			})
			if err != nil {
				return err
			}
			for _, s := range report.Statements {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\n",
					s.StatementID, s.Status, s.CVE, s.Detail)
			}
			if !report.AllVerified() {
				return fmt.Errorf("verification failed: not all statements VERIFIED")
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "bundle_id=%s ok\n", report.BundleID)
			return nil
		},
	}
	return cmd
}
