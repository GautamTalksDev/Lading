package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

func newSignCmd() *cobra.Command {
	var keyless bool
	var key string
	var output string

	cmd := &cobra.Command{
		Use:   "sign [files...]",
		Short: "Sign output files with cosign (detached; separate from emit)",
		Long: `Sign one or more files using cosign sign-blob (detached signature).
VEX emit never signs automatically — run this command explicitly after review.

Examples:
  lading sign --keyless vex.openvex.json vex.cdx.json vex.csaf.json refusals.json
  lading sign --key cosign.key vex.openvex.json`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if keyless && key != "" {
				return fmt.Errorf("sign: use either --keyless or --key, not both")
			}
			if !keyless && key == "" {
				return fmt.Errorf("sign: specify --keyless or --key")
			}
			if _, err := exec.LookPath("cosign"); err != nil {
				return fmt.Errorf("sign: cosign not found in PATH")
			}
			for _, path := range args {
				if err := signFile(path, keyless, key, output); err != nil {
					return err
				}
			}
			return nil
		},
		SilenceUsage: true,
	}
	cmd.Flags().BoolVar(&keyless, "keyless", false, "Use cosign keyless signing")
	cmd.Flags().StringVar(&key, "key", "", "Path to cosign private key")
	cmd.Flags().StringVar(&output, "output-signature", "", "Signature output path (default: <file>.sig)")
	return cmd
}

func signFile(path string, keyless bool, key, output string) error {
	if output == "" {
		output = path + ".sig"
	}
	var args []string
	if keyless {
		args = []string{"sign-blob", "--yes", "--output-signature", output, path}
	} else {
		args = []string{"sign-blob", "--key", key, "--output-signature", output, path}
	}
	cmd := exec.Command("cosign", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sign %s: %w", path, err)
	}
	_, _ = fmt.Fprintf(os.Stdout, "signed %s → %s\n", path, output)
	return nil
}
