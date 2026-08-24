package main

import (
	"fmt"
	"os"

	"github.com/gautamtalksdev/lading/internal/scan"
	"github.com/gautamtalksdev/lading/internal/unpack"
	"github.com/spf13/cobra"
)

type scanExitError struct {
	Code int
	Err  error
}

func (e *scanExitError) Error() string { return e.Err.Error() }

func newScanCmd() *cobra.Command {
	var (
		sbomPath         string
		findingsPath     string
		osvPath          string
		imageRef         string
		manifestDir      string
		outDir           string
		timestamp        string
		jsonOut          bool
		noVEX            bool
		expectSHA256     string
		expectSHA256Set  bool
		catalogSHA256Null bool
	)

	cmd := &cobra.Command{
		Use:   "scan [artifact]",
		Short: "Scan an artifact: unpack, inventory, decide, and emit evidence",
		Long: `The primary LADING command. Accepts a directory tree, single binary,
tarball/rootfs archive, or OCI image (tar or --image on Linux).

Pipeline: unpack → inventory every binary → SBOM/findings → decide → emit.

On macOS and Windows only directories and single binaries are accepted;
archives and images require Linux sandboxed unpacking (podman/docker).

Exit codes: 0 clean, 1 affected CVEs present, 2 operational error
(including artifact integrity refusals: hash mismatch, absent, unhashed).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			artifact := ""
			if len(args) > 0 {
				artifact = args[0]
			}
			if imageRef != "" && artifact == "" {
				// OK: image-only scan
			} else if artifact == "" {
				return &scanExitError{Code: 2, Err: fmt.Errorf("scan: artifact path or --image required")}
			}

			opts := scan.Options{
				ArtifactPath: artifact,
				ImageRef:     imageRef,
				SBOMPath:     sbomPath,
				FindingsPath: findingsPath,
				OSVPath:      osvPath,
				ManifestDir:  manifestDir,
				OutDir:       outDir,
				Timestamp:    timestamp,
				EmitVEX:      !noVEX,
			}
			if catalogSHA256Null || expectSHA256Set {
				ie := &scan.IntegrityExpectation{
					NullSHA256: catalogSHA256Null,
					Expected:   expectSHA256,
				}
				opts.Integrity = ie
			}

			res, err := scan.Run(opts)
			if err != nil {
				if scan.IsIntegrityError(err) {
					if jsonOut {
						res.Report.WriteJSON(os.Stdout)
					} else {
						res.Report.WriteHuman(os.Stdout, scan.IsTerminal(os.Stdout))
					}
					return &scanExitError{Code: 2, Err: err}
				}
				return &scanExitError{Code: 2, Err: err}
			}

			if jsonOut {
				res.Report.WriteJSON(os.Stdout)
			} else {
				res.Report.WriteHuman(os.Stdout, scan.IsTerminal(os.Stdout))
			}

			if res.HasAffected {
				return &scanExitError{Code: 1, Err: errScanAffected}
			}
			return nil
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&sbomPath, "sbom", "", "SBOM path (CycloneDX or SPDX JSON)")
	cmd.Flags().StringVar(&findingsPath, "findings", "", "Scanner findings JSON (grype/trivy/cve-bin-tool)")
	cmd.Flags().StringVar(&osvPath, "osv", "", "Local OSV database JSONL (requires --sbom)")
	cmd.Flags().StringVar(&imageRef, "image", "", "OCI image reference (Linux sandbox only)")
	cmd.Flags().StringVar(&manifestDir, "manifest", "manifest", "Lading Manifest directory")
	cmd.Flags().StringVar(&outDir, "out", ".", "Output directory for bundle and VEX")
	cmd.Flags().StringVar(&timestamp, "timestamp", "", "RFC3339 UTC timestamp for VEX emit")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Machine-readable JSON summary")
	cmd.Flags().BoolVar(&noVEX, "no-vex", false, "Skip VEX document emission")
	cmd.Flags().StringVar(&expectSHA256, "expect-sha256", "", "Fail closed unless artifact bytes match this hex SHA-256")
	cmd.Flags().BoolVar(&catalogSHA256Null, "catalog-sha256-null", false, "Refuse with artifact-unhashed (catalogue sha256 was null)")
	cmd.PreRun = func(cmd *cobra.Command, args []string) {
		expectSHA256Set = cmd.Flags().Changed("expect-sha256")
	}

	return cmd
}

var errScanAffected = fmt.Errorf("scan: affected CVEs present")

func newUnpackInternalCmd() *cobra.Command {
	var input, output string
	cmd := &cobra.Command{
		Use:    "__unpack-internal",
		Hidden: true,
		Short:  "Sandbox child: extract archive with hard limits",
		RunE: func(cmd *cobra.Command, args []string) error {
			if input == "" || output == "" {
				return fmt.Errorf("unpack-internal: --input and --output required")
			}
			return unpack.ExtractInput(input, output)
		},
		SilenceUsage: true,
	}
	cmd.Flags().StringVar(&input, "input", "", "Archive file")
	cmd.Flags().StringVar(&output, "output", "", "Output directory")
	return cmd
}
