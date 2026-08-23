package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gautamtalksdev/lading/internal/decide"
	"github.com/gautamtalksdev/lading/internal/inventory"
	"github.com/gautamtalksdev/lading/internal/manifest"
)

type probeIn struct {
	Finding struct {
		CVE           string `json:"cve"`
		ComponentPURL string `json:"component_purl"`
	} `json:"finding"`
	Manifest struct {
		Version   string `json:"version"`
		Component struct {
			Name            string   `json:"name"`
			Ecosystem       string   `json:"ecosystem"`
			PURLs           []string `json:"purls"`
			IdentitySymbols []string `json:"identity_symbols"`
		} `json:"component"`
		Entry struct {
			CVE               string `json:"cve"`
			AffectedVersions  []string `json:"affected_versions"`
			VulnerableSymbols []struct {
				Name       string `json:"name"`
				Confidence string `json:"confidence"`
			} `json:"vulnerable_symbols"`
			ManifestVersion string `json:"manifest_version"`
		} `json:"entry"`
	} `json:"manifest"`
	Inventories []struct {
		File string `json:"file"`
	} `json:"inventories"`
}

type probeOut struct {
	Verdict       string `json:"verdict"`
	RuleID        string `json:"rule_id"`
	Justification string `json:"justification,omitempty"`
	ReasonCode    string `json:"reason_code,omitempty"`
}

func main() {
	var inputs []probeIn
	if err := json.NewDecoder(os.Stdin).Decode(&inputs); err != nil {
		fmt.Fprintf(os.Stderr, "decode: %v\n", err)
		os.Exit(1)
	}
	root, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	var outs []probeOut
	for _, in := range inputs {
		var invs []*inventory.Inventory
		for _, ref := range in.Inventories {
			p := filepath.Join(root, "testdata", "inventory", "bin", ref.File)
			inv, err := inventory.Scan(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "scan %s: %v\n", ref.File, err)
				os.Exit(1)
			}
			invs = append(invs, inv)
		}
		comp := manifest.Component{
			Name:            in.Manifest.Component.Name,
			Ecosystem:       in.Manifest.Component.Ecosystem,
			PURLs:           in.Manifest.Component.PURLs,
			IdentitySymbols: in.Manifest.Component.IdentitySymbols,
		}
		var vulnSyms []manifest.VulnerableSymbol
		for _, vs := range in.Manifest.Entry.VulnerableSymbols {
			conf := manifest.ConfidenceProbable
			if vs.Confidence == "definitive" {
				conf = manifest.ConfidenceDefinitive
			}
			vulnSyms = append(vulnSyms, manifest.VulnerableSymbol{
				Name:       vs.Name,
				Confidence: conf,
				Provenance: manifest.Provenance{
					UpstreamFixCommit: "https://example.com/commit/fix",
					Derivation:        manifest.DerivationManual,
					ReviewedBy:        "probe",
					ReviewedAt:        "2026-08-23",
				},
			})
		}
		entry := manifest.Entry{
			CVE:               in.Manifest.Entry.CVE,
			AffectedVersions:  in.Manifest.Entry.AffectedVersions,
			VulnerableSymbols: vulnSyms,
			ManifestVersion:   in.Manifest.Entry.ManifestVersion,
		}
		m, err := manifest.BuildForTest(in.Manifest.Version, comp, []manifest.Entry{entry})
		if err != nil {
			fmt.Fprintf(os.Stderr, "manifest: %v\n", err)
			os.Exit(1)
		}
		got, err := decide.Evaluate(decide.Input{
			Inventories: invs,
			Finding: decide.Finding{
				CVE:           in.Finding.CVE,
				ComponentPURL: in.Finding.ComponentPURL,
			},
			Manifest: m,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "evaluate: %v\n", err)
			os.Exit(1)
		}
		outs = append(outs, probeOut{
			Verdict:       string(got.Verdict),
			RuleID:        string(got.RuleID),
			Justification: string(got.Justification),
			ReasonCode:    string(got.ReasonCode),
		})
	}
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(outs); err != nil {
		panic(err)
	}
}
