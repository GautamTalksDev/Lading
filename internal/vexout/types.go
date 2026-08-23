package vexout

import (
	"github.com/gautamtalksdev/lading/internal/decide"
	"github.com/gautamtalksdev/lading/internal/legal"
)

const (
	// Author is the default VEX document author.
	Author = "LADING"
	// PublisherName is the CSAF publisher name.
	PublisherName = "LADING"
	// PublisherNamespace is the CSAF publisher namespace IRI.
	PublisherNamespace = "https://lading.dev"
	// RefusalsFormat labels refusals.json.
	RefusalsFormat = "lading-refusals-v1"
	// MetadataDisclaimerKey is the CycloneDX metadata property name.
	MetadataDisclaimerKey = "lading:disclaimer"
)

// DocumentDisclaimer is embedded in every emitted VEX-family document.
func DocumentDisclaimer() string {
	return legal.DisclaimerShort
}

// Statement is one evaluated CVE/component decision bound to evidence.
type Statement struct {
	StatementID   string
	CVE           string
	ComponentPURL string
	Result        decide.Result
}

// DocumentInput is the full deterministic emit tuple.
type DocumentInput struct {
	BundleID       string
	ArtifactSHA256 string
	Timestamp      string // RFC3339 UTC; required for byte-identical output
	Statements     []Statement
}

// Summary counts outcomes for CLI display.
type Summary struct {
	Total    int
	Cleared  int // NOT_AFFECTED
	Affected int
	Refusals int // UNDER_INVESTIGATION
}

// Output holds all emitted documents.
type Output struct {
	OpenVEX   []byte
	CycloneDX []byte
	CSAF      []byte
	Refusals  []byte
	Summary   Summary
}
