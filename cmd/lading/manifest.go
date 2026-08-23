package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gautamtalksdev/lading/internal/manifestderive"
	"github.com/spf13/cobra"
)

func newManifestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "manifest",
		Short: "Manifest operator tools (derive, propose, promote, coverage)",
	}
	cmd.AddCommand(newManifestDeriveCmd())
	cmd.AddCommand(newManifestProposeCmd())
	cmd.AddCommand(newManifestPromoteCmd())
	cmd.AddCommand(newManifestCoverageCmd())
	return cmd
}

func newManifestDeriveCmd() *cobra.Command {
	var (
		jobFile   string
		manifest  string
		cacheDir  string
		localRepo string
		outDir    string
	)
	cmd := &cobra.Command{
		Use:   "derive",
		Short: "Derive probable candidate entries from upstream fix commits (Linux operator)",
		Long: strings.TrimSpace(`
Clone or use a local git repo, read each fix commit via git (no per-CVE HTTP API),
parse changed C/C++ sources with tree-sitter, and write CANDIDATE YAML under
manifest/candidates/. Confidence is ALWAYS probable. Never writes definitive
and never writes under manifest/components/.
`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if runtime.GOOS == "windows" {
				return fmt.Errorf("manifest derive is an operator command for Linux (git + CGO tree-sitter)")
			}
			if jobFile == "" {
				return fmt.Errorf("--job is required")
			}
			in, err := manifestderive.LoadDeriveInput(jobFile)
			if err != nil {
				return err
			}
			manDir, err := resolveManifestDir(manifest)
			if err != nil {
				return err
			}
			verBytes, err := os.ReadFile(filepath.Join(manDir, "VERSION")) // #nosec G304
			if err != nil {
				return err
			}
			if outDir == "" {
				outDir = filepath.Join(manDir, "candidates", in.Component.Ecosystem)
			}
			res, err := manifestderive.Derive(in, manifestderive.DeriveOptions{
				CacheDir:        cacheDir,
				LocalRepo:       localRepo,
				OutDir:          outDir,
				ManifestVersion: strings.TrimSpace(string(verBytes)),
			})
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote candidate %s\n", res.OutPath)
			for _, e := range res.Entries {
				if e.Err != "" {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s: ERROR %s\n", e.CVE, e.Err)
					continue
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s: %v (probable)\n", e.CVE, e.Symbols)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&jobFile, "job", "", "derive job YAML (component + cves)")
	cmd.Flags().StringVar(&manifest, "manifest", "manifest", "manifest directory")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", filepath.Join(".lading", "repos"), "local git clone cache")
	cmd.Flags().StringVar(&localRepo, "local-repo", "", "use existing checkout instead of cloning")
	cmd.Flags().StringVar(&outDir, "out", "", "candidate output directory (default: manifest/candidates/<ecosystem>)")
	return cmd
}

func newManifestProposeCmd() *cobra.Command {
	var (
		fixCommit     string
		symbols       []string
		encFuncs      []string
		affectedVers  []string
		derivation    string
		notes         string
		verification  string
		fixture       string
		buildRecipe   string
		githubUser    string
		manifestDir   string
		proposalRoot  string
		openTemplate  bool
	)
	cmd := &cobra.Command{
		Use:   "propose <component> <cve>",
		Short: "Scaffold a probable candidate entry and pre-filled PR template",
		Long: strings.TrimSpace(`
Contributor entry point for Manifest DATA only. Writes under manifest/candidates/
(probable confidence) and generates .lading/proposals/<component>-<cve>/PULL_REQUEST.md.
Never writes manifest/components/ and never sets definitive.
`),
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			manDir, err := resolveManifestDir(manifestDir)
			if err != nil {
				return err
			}
			res, err := manifestderive.Propose(manifestderive.ProposeInput{
				Component:          args[0],
				CVE:                args[1],
				FixCommit:          fixCommit,
				Symbols:            symbols,
				EnclosingFunctions: encFuncs,
				AffectedVersions:   affectedVers,
				Derivation:         derivation,
				Notes:              notes,
				Verification:       verification,
				FixturePath:        fixture,
				BuildRecipePath:    buildRecipe,
				ContributorGitHub:  githubUser,
			}, manifestderive.ProposeOptions{
				ManifestDir:  manDir,
				ProposalRoot: proposalRoot,
				OpenTemplate: openTemplate,
			})
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "candidate: %s\n", res.CandidatePath)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "PR template: %s\n", res.PRTemplatePath)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "next: commit candidate + open PR using .github/PULL_REQUEST_TEMPLATE/manifest_entry.md\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&fixCommit, "fix-commit", "", "upstream fix commit URL (required)")
	cmd.Flags().StringSliceVar(&symbols, "symbol", nil, "vulnerable symbol name (repeatable, required)")
	cmd.Flags().StringSliceVar(&encFuncs, "enclosing-function", nil, "enclosing function names from patch (repeatable)")
	cmd.Flags().StringSliceVar(&affectedVers, "affected-version", nil, "exact affected version string (repeatable, required)")
	cmd.Flags().StringVar(&derivation, "derivation", "", "provenance derivation (default: patch-touched-function)")
	cmd.Flags().StringVar(&notes, "notes", "", "free-form entry notes")
	cmd.Flags().StringVar(&verification, "verification", "", "how you verified symbols in a binary (required)")
	cmd.Flags().StringVar(&fixture, "fixture", "", "path to test fixture binary")
	cmd.Flags().StringVar(&buildRecipe, "build-recipe", "", "path to documented build recipe (if no fixture)")
	cmd.Flags().StringVar(&githubUser, "github", "", "your GitHub handle (without @)")
	cmd.Flags().StringVar(&manifestDir, "manifest", "manifest", "manifest directory")
	cmd.Flags().StringVar(&proposalRoot, "proposal-dir", filepath.Join(".lading", "proposals"), "local proposal output root")
	cmd.Flags().BoolVar(&openTemplate, "open", false, "open PR template with xdg-open/open when available")
	_ = cmd.MarkFlagRequired("fix-commit")
	_ = cmd.MarkFlagRequired("verification")
	return cmd
}

func newManifestPromoteCmd() *cobra.Command {
	var (
		reviewedBy string
		reviewedAt string
		manifest   string
	)
	cmd := &cobra.Command{
		Use:   "promote <candidate.yaml>",
		Short: "Manually promote a candidate to definitive under manifest/components/",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			manDir, err := resolveManifestDir(manifest)
			if err != nil {
				return err
			}
			verBytes, err := os.ReadFile(filepath.Join(manDir, "VERSION")) // #nosec G304
			if err != nil {
				return err
			}
			out, err := manifestderive.Promote(args[0], manifestderive.PromoteOptions{
				ReviewedBy:      reviewedBy,
				ReviewedAt:      reviewedAt,
				ComponentsDir:   filepath.Join(manDir, "components"),
				ManifestVersion: strings.TrimSpace(string(verBytes)),
			})
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "promoted → %s\n", out)
			// Regenerate coverage after promotion.
			rep, err := manifestderive.ComputeCoverage(manDir)
			if err != nil {
				return fmt.Errorf("promoted but coverage failed: %w", err)
			}
			if err := manifestderive.WriteCoverageMarkdown(manDir, rep); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "updated %s\n", filepath.Join(manDir, "COVERAGE.md"))
			return nil
		},
	}
	cmd.Flags().StringVar(&reviewedBy, "reviewed-by", "", "operator handle (required)")
	cmd.Flags().StringVar(&reviewedAt, "reviewed-at", "", "review date YYYY-MM-DD (required)")
	cmd.Flags().StringVar(&manifest, "manifest", "manifest", "manifest directory")
	_ = cmd.MarkFlagRequired("reviewed-by")
	_ = cmd.MarkFlagRequired("reviewed-at")
	return cmd
}

func newManifestCoverageCmd() *cobra.Command {
	var manifest string
	cmd := &cobra.Command{
		Use:   "coverage",
		Short: "Regenerate manifest/COVERAGE.md from components (+ candidates)",
		RunE: func(cmd *cobra.Command, args []string) error {
			manDir, err := resolveManifestDir(manifest)
			if err != nil {
				return err
			}
			rep, err := manifestderive.ComputeCoverage(manDir)
			if err != nil {
				return err
			}
			if err := manifestderive.WriteCoverageMarkdown(manDir, rep); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", filepath.Join(manDir, "COVERAGE.md"))
			for _, c := range rep.Components {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s: definitive=%d probable=%d none=%d\n",
					c.Name, c.Definitive, c.Probable, c.None)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&manifest, "manifest", "manifest", "manifest directory")
	return cmd
}

func resolveManifestDir(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(abs, "VERSION")); err != nil {
		return "", fmt.Errorf("manifest dir %s: %w", abs, err)
	}
	return abs, nil
}
