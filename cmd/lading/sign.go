package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

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

// SignArgError is returned when a sign CLI argument would be parsed as a flag.
type SignArgError struct {
	Arg   string // path | key | output
	Value string
}

func (e *SignArgError) Error() string {
	return fmt.Sprintf("sign: %s %q must not begin with -", e.Arg, e.Value)
}

func validateSignArgs(path, key, output string) error {
	for _, a := range []struct {
		name  string
		value string
	}{
		{"path", path},
		{"key", key},
		{"output", output},
	} {
		if a.value != "" && strings.HasPrefix(a.value, "-") {
			return &SignArgError{Arg: a.name, Value: a.value}
		}
	}
	return nil
}

func signFile(path string, keyless bool, key, output string) error {
	if output == "" {
		output = path + ".sig"
	}
	if err := validateSignArgs(path, key, output); err != nil {
		return err
	}
	var args []string
	if keyless {
		args = []string{"sign-blob", "--yes", "--output-signature", output, "--", path}
	} else {
		args = []string{"sign-blob", "--key", key, "--output-signature", output, "--", path}
	}
	//nolint:gosec // G204: cosign is a literal; path/key/output validated by validateSignArgs
	cmd := exec.Command("cosign", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sign %s: %w", path, err)
	}
	_, _ = fmt.Fprintf(os.Stdout, "signed %s → %s\n", path, output)
	return nil
}
