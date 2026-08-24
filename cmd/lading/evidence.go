package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gautamtalksdev/lading/internal/evidencehtml"
	"github.com/spf13/cobra"
)

func newEvidenceCmd() *cobra.Command {
	var (
		outPath     string
		scanDir     string
		catalogPath string
		catalogID   string
		manifestDir string
		timestamp   string
		signKey     string
	)

	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Render a self-contained, signed HTML evidence pack from scan outputs",
		Long: `Produce a single HTML file plus detached ed25519 signature from on-disk
scan results (decisions.jsonl, grype.json, evidence-bundle/). No network.

Requires a prior lading scan (or corpus results directory). Pass --timestamp
(RFC3339 UTC) for deterministic output.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			artifact := ""
			if len(args) > 0 {
				artifact = args[0]
			}
			flagArtifact, _ := cmd.Flags().GetString("artifact")
			if artifact == "" {
				artifact = flagArtifact
			}
			if artifact == "" {
				return fmt.Errorf("evidence: --artifact required")
			}
			if outPath == "" {
				return fmt.Errorf("evidence: --out required")
			}
			if scanDir == "" {
				return fmt.Errorf("evidence: --scan-dir required (directory with decisions.jsonl)")
			}
			if timestamp == "" {
				return fmt.Errorf("evidence: --timestamp required (RFC3339 UTC, e.g. 2026-08-24T00:00:00Z)")
			}
			if signKey == "" {
				return fmt.Errorf("evidence: --sign-key required (ed25519 PEM private key)")
			}

			pack, err := evidencehtml.Load(evidencehtml.Options{
				ArtifactPath: artifact,
				ScanDir:      scanDir,
				CatalogPath:  catalogPath,
				CatalogID:    catalogID,
				ManifestDir:  manifestDir,
				Timestamp:    timestamp,
			})
			if err != nil {
				return fmt.Errorf("evidence: %w", err)
			}

			htmlBytes := evidencehtml.Render(pack)
			if err := os.WriteFile(outPath, htmlBytes, 0o644); err != nil {
				return fmt.Errorf("evidence: write html: %w", err)
			}

			keyPEM, err := os.ReadFile(signKey)
			if err != nil {
				return fmt.Errorf("evidence: read sign key: %w", err)
			}
			sig, err := evidencehtml.SignDetached(htmlBytes, keyPEM)
			if err != nil {
				return fmt.Errorf("evidence: sign: %w", err)
			}
			sigPath := outPath + ".sig"
			if err := os.WriteFile(sigPath, sig, 0o644); err != nil {
				return fmt.Errorf("evidence: write signature: %w", err)
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (%d bytes)\n", filepath.ToSlash(outPath), len(htmlBytes))
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", filepath.ToSlash(sigPath))
			return nil
		},
		SilenceUsage: true,
	}

	cmd.Flags().String("artifact", "", "Artifact path or catalogue identity (required)")
	cmd.Flags().StringVar(&outPath, "out", "", "Output HTML path (required)")
	cmd.Flags().StringVar(&scanDir, "scan-dir", "", "Scan output directory with decisions.jsonl (required)")
	cmd.Flags().StringVar(&catalogPath, "catalog", "", "Optional ARTIFACTS.yaml for identity metadata")
	cmd.Flags().StringVar(&catalogID, "catalog-id", "", "Catalogue artifact id (when path does not imply it)")
	cmd.Flags().StringVar(&manifestDir, "manifest", "", "Manifest tree (for version label; default manifest/)")
	cmd.Flags().StringVar(&timestamp, "timestamp", "", "Fixed generation timestamp RFC3339 UTC (required)")
	cmd.Flags().StringVar(&signKey, "sign-key", "", "ed25519 PEM private key for detached signature (required)")
	return cmd
}
