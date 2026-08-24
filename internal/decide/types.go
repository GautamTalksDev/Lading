package decide

import (
	"github.com/gautamtalksdev/lading/internal/inventory"
	"github.com/gautamtalksdev/lading/internal/manifest"
)

// ToolVersion is the evidence spec / engine version recorded on every result.
const ToolVersion = "evidence-v1"

// Verdict is the top-level decision outcome.
type Verdict string

const (
	VerdictNotAffected         Verdict = "NOT_AFFECTED"
	VerdictAffected            Verdict = "AFFECTED"
	VerdictUnderInvestigation  Verdict = "UNDER_INVESTIGATION"
)

// Justification is the VEX-style status for NOT_AFFECTED verdicts only.
type Justification string

const (
	JustificationComponentNotPresent       Justification = "component_not_present"
	JustificationVulnerableCodeNotPresent  Justification = "vulnerable_code_not_present"
)

// RuleID identifies which rule produced the verdict.
type RuleID string

const (
	RuleD01 RuleID = "D01"
	RuleD02 RuleID = "D02"
	RuleD03 RuleID = "D03"
	RuleD04 RuleID = "D04"
)

// ReasonCode is a machine-readable D03 refusal reason.
type ReasonCode string

const (
	ReasonNoIdentityMapping         ReasonCode = "no_identity_mapping"
	ReasonMappingProbableOnly       ReasonCode = "mapping_probable_only"
	ReasonVersionUnderivable        ReasonCode = "version_underivable"
	ReasonPURLMatchInsufficient     ReasonCode = "purl_match_insufficient"
	ReasonManifestNoEntry             ReasonCode = "manifest_no_entry"
	ReasonManifestProbableOnly        ReasonCode = "manifest_probable_only"
	ReasonSymbolTableUnusable         ReasonCode = "symbol_table_unusable"
	ReasonStrippedStaticBinary        ReasonCode = "stripped_static_binary"
	ReasonStrippedInsufficientDynsym  ReasonCode = "stripped_insufficient_dynsym"
	ReasonProvenanceUnverified        ReasonCode = "provenance_unverified"
	ReasonIdentityUnverified          ReasonCode = "identity_unverified"
	ReasonDefaultInsufficient         ReasonCode = "default_insufficient"
)

// Finding is one vulnerability report against an SBOM component.
type Finding struct {
	CVE           string
	ComponentPURL string
}

// InputsUsed records which inputs drove the verdict (re-derivable bundle).
type InputsUsed struct {
	CVE                      string   `json:"cve"`
	ComponentPURL            string   `json:"component_purl"`
	ManifestComponent        string   `json:"manifest_component"`
	PURLMatchQuality         string   `json:"purl_match_quality"`
	Inventories              []string `json:"inventories"`
	DefinitiveSymbolsChecked []string `json:"definitive_symbols_checked"`
	SymbolsObserved          []string `json:"symbols_observed"`
	ComponentInventories     []string `json:"component_inventories"`
}

// Result is one deterministic verdict.
type Result struct {
	Verdict          Verdict       `json:"verdict"`
	Justification    Justification `json:"justification,omitempty"`
	RuleID           RuleID        `json:"rule_id"`
	ReasonCode       ReasonCode    `json:"reason_code,omitempty"`
	ManifestVersion  string        `json:"manifest_version"`
	ToolVersion      string        `json:"tool_version"`
	InputsUsed       InputsUsed    `json:"inputs_used"`
}

// Input is the full evaluation tuple.
type Input struct {
	Inventories     []*inventory.Inventory
	Finding         Finding
	Manifest        *manifest.Manifest
	IdentityAliases *manifest.IdentityAliases
}
