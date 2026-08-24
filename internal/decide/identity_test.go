package decide_test

import (
	"testing"

	"github.com/gautamtalksdev/lading/internal/decide"
	"github.com/gautamtalksdev/lading/internal/inventory"
	"github.com/gautamtalksdev/lading/internal/manifest"
	"github.com/gautamtalksdev/lading/internal/purl"
)

func TestIdentity_ProbableNeverClears(t *testing.T) {
	t.Parallel()

	aliases, err := manifest.LoadIdentityAliases("")
	if err != nil {
		t.Fatal(err)
	}

	m, err := manifest.BuildForTest("0.2.0", manifest.Component{
		Name:      "curl",
		Ecosystem: "native",
		PURLs:     []string{"pkg:generic/curl@8.4.0"},
		IdentitySymbols: []string{
			"curl_easy_perform",
		},
	}, []manifest.Entry{{
		CVE:              "CVE-2023-38545",
		AffectedVersions: []string{"8.4.0"},
		VulnerableSymbols: []manifest.VulnerableSymbol{{
			Name:       "Curl_cookie",
			Confidence: manifest.ConfidenceDefinitive,
			Provenance: manifest.Provenance{
				UpstreamFixCommit: "https://example.com/commit/fix",
				Derivation:        manifest.DerivationManual,
				ReviewedBy:        "test",
				ReviewedAt:        "2026-08-24",
			},
		}},
		ManifestVersion: "0.2.0",
	}})
	if err != nil {
		t.Fatal(err)
	}

	// Distro finding with upstream=curl hits probable alias — must refuse, never clear.
	got, err := decide.Evaluate(decide.Input{
		Manifest:        m,
		IdentityAliases: aliases,
		Finding: decide.Finding{
			CVE:           "CVE-2023-38545",
			ComponentPURL: "pkg:deb/debian/curl@8.4.0-1?arch=amd64&distro=debian-12&upstream=curl",
		},
		Inventories: []*inventory.Inventory{{
			Path:   "clean",
			Format: inventory.FormatELF,
			DynSyms: []inventory.Symbol{
				{Normalized: "curl_easy_perform"},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != decide.VerdictUnderInvestigation {
		t.Fatalf("verdict=%s want UNDER_INVESTIGATION", got.Verdict)
	}
	if got.ReasonCode != decide.ReasonMappingProbableOnly {
		t.Fatalf("reason=%s want mapping_probable_only", got.ReasonCode)
	}
	if got.Verdict == decide.VerdictNotAffected {
		t.Fatal("probable alias must not produce not_affected")
	}
}

func TestIdentity_DirectDistroMatchIgnoresProbableUpstream(t *testing.T) {
	t.Parallel()

	aliases, err := manifest.LoadIdentityAliases("")
	if err != nil {
		t.Fatal(err)
	}

	m, err := manifest.BuildForTest("0.2.0", manifest.Component{
		ProvenanceStatus: manifest.ProvenanceVerified,
		Name:             "openssl",
		Ecosystem:        "native",
		PURLs:            []string{"pkg:deb/debian/libssl3"},
		IdentitySymbols:  []string{"OPENSSL_init_ssl"},
	}, []manifest.Entry{{
		CVE:              "CVE-2026-14456",
		AffectedVersions: []string{"3.0.11"},
		VulnerableSymbols: []manifest.VulnerableSymbol{{
			Name:       "port_default_packet_handler",
			Confidence: manifest.ConfidenceDefinitive,
			Provenance: manifest.Provenance{
				UpstreamFixCommit: "https://example.com/commit/fix",
				Derivation:        manifest.DerivationManual,
				ReviewedBy:        "test",
				ReviewedAt:        "2026-08-24",
			},
		}},
		ManifestVersion: "0.2.0",
	}})
	if err != nil {
		t.Fatal(err)
	}

	// upstream=openssl is probable, but pkg:deb/debian/libssl3 already
	// type-matches the Manifest — must not refuse via mapping_probable_only.
	got, err := decide.Evaluate(decide.Input{
		Manifest:        m,
		IdentityAliases: aliases,
		Finding: decide.Finding{
			CVE:           "CVE-2026-14456",
			ComponentPURL: "pkg:deb/debian/libssl3@3.0.11-1?arch=amd64&distro=debian-12&upstream=openssl",
		},
		Inventories: []*inventory.Inventory{{
			Path:   "libssl.so",
			Format: inventory.FormatELF,
			DynSyms: []inventory.Symbol{
				{Normalized: "OPENSSL_init_ssl"},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ReasonCode == decide.ReasonMappingProbableOnly {
		t.Fatal("direct TypeNormalized match must not be blocked by probable upstream alias")
	}
	if got.Verdict != decide.VerdictUnderInvestigation {
		t.Fatalf("verdict=%s reason=%s want UNDER_INVESTIGATION", got.Verdict, got.ReasonCode)
	}
	if got.ReasonCode != decide.ReasonSymbolNotObservable {
		t.Fatalf("reason=%s want symbol_not_observable for internal QUIC handler", got.ReasonCode)
	}
}

func TestIdentity_DefinitiveProducesIdentityMapped(t *testing.T) {
	t.Parallel()

	aliases, err := manifest.BuildIdentityAliasesForTest(manifest.IdentityAlias{
		SourceName: "expat",
		Component:  "pkg:generic/libexpat",
		Status:     manifest.AliasStatusDefinitive,
		Provenance: manifest.AliasProvenance{
			ArtifactSHA256:          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Distro:                  "debian",
			PackageName:             "libexpat1",
			PackageVersion:          "2.5.0-1+deb12u1",
			VerifiedAt:              "2026-08-24",
			BinaryPath:              "usr/lib/x86_64-linux-gnu/libexpat.so.1.8.10",
			IdentitySymbolsVerified: []string{"XML_ParserCreate"},
			ExtractionMethod:        "dpkg-deb-extract",
			ReviewedBy:              "test",
			URL:                     "https://sources.debian.org/src/expat/",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	m, err := manifest.BuildForTest("0.2.0", manifest.Component{
		Name:      "libexpat",
		Ecosystem: "native",
		PURLs:     []string{"pkg:generic/libexpat@2.5.0"},
		IdentitySymbols: []string{
			"XML_ParserCreate",
		},
	}, []manifest.Entry{{
		CVE:              "CVE-2022-25315",
		AffectedVersions: []string{"2.5.0"},
		VulnerableSymbols: []manifest.VulnerableSymbol{{
			Name:       "storeRawNames",
			Confidence: manifest.ConfidenceDefinitive,
			Provenance: manifest.Provenance{
				UpstreamFixCommit: "https://example.com/commit/fix",
				Derivation:        manifest.DerivationManual,
				ReviewedBy:        "test",
				ReviewedAt:        "2026-08-24",
			},
		}},
		ManifestVersion: "0.2.0",
	}})
	if err != nil {
		t.Fatal(err)
	}

	got, err := decide.Evaluate(decide.Input{
		Manifest:        m,
		IdentityAliases: aliases,
		Finding: decide.Finding{
			CVE:           "CVE-2022-25315",
			ComponentPURL: "pkg:deb/debian/libexpat1@2.5.0-1%2Bdeb12u1?arch=amd64&distro=debian-12&upstream=expat@2.5.0",
		},
		Inventories: []*inventory.Inventory{{
			Path:   "clean",
			Format: inventory.FormatELF,
			DynSyms: []inventory.Symbol{
				{Normalized: "XML_ParserCreate"},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.InputsUsed.PURLMatchQuality != purl.IdentityMapped.String() {
		t.Fatalf("purl_match_quality=%q want identity_mapped", got.InputsUsed.PURLMatchQuality)
	}
	if got.InputsUsed.PURLMatchQuality == purl.Exact.String() {
		t.Fatal("identity resolution must not report exact")
	}
}

func TestIdentity_NoUpstreamQualifier(t *testing.T) {
	t.Parallel()

	aliases, err := manifest.LoadIdentityAliases("")
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.BuildForTest("0.2.0", manifest.Component{
		Name:            "zlib",
		Ecosystem:       "native",
		PURLs:           []string{"pkg:generic/zlib"},
		IdentitySymbols: []string{"inflate"},
	}, []manifest.Entry{{
		CVE:              "CVE-2022-37434",
		AffectedVersions: []string{"1.2.12"},
		VulnerableSymbols: []manifest.VulnerableSymbol{{
			Name:       "inflate",
			Confidence: manifest.ConfidenceDefinitive,
			Provenance: manifest.Provenance{
				UpstreamFixCommit: "https://example.com/commit/fix",
				Derivation:        manifest.DerivationManual,
				ReviewedBy:        "test",
				ReviewedAt:        "2026-08-24",
			},
		}},
		ManifestVersion: "0.2.0",
	}})
	if err != nil {
		t.Fatal(err)
	}

	got, err := decide.Evaluate(decide.Input{
		Manifest:        m,
		IdentityAliases: aliases,
		Finding: decide.Finding{
			CVE:           "CVE-2022-37434",
			ComponentPURL: "pkg:deb/debian/zlib1g",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ReasonCode != decide.ReasonNoIdentityMapping {
		t.Fatalf("reason=%s want no_identity_mapping", got.ReasonCode)
	}
}

func TestProvenance_UnverifiedCannotClear(t *testing.T) {
	t.Parallel()

	comp := manifest.Component{
		ProvenanceStatus: manifest.ProvenanceUnverified,
		Name:             "curl",
		Ecosystem:        "native",
		PURLs:            []string{"pkg:generic/curl@8.4.0"},
		IdentitySymbols:  []string{"curl_easy_perform"},
	}
	m, err := manifest.BuildForTest("0.2.0", comp, []manifest.Entry{{
		CVE:              "CVE-2023-38545",
		AffectedVersions: []string{"8.4.0"},
		VulnerableSymbols: []manifest.VulnerableSymbol{{
			Name:       "curl_easy_perform",
			Confidence: manifest.ConfidenceDefinitive,
			Provenance: manifest.Provenance{
				UpstreamFixCommit: "https://example.com/commit/fix",
				Derivation:        manifest.DerivationManual,
				ReviewedBy:        "test",
				ReviewedAt:        "2026-08-24",
			},
		}},
		ManifestVersion: "0.2.0",
	}})
	if err != nil {
		t.Fatal(err)
	}

	got, err := decide.Evaluate(decide.Input{
		Manifest: m,
		Finding: decide.Finding{
			CVE:           "CVE-2023-38545",
			ComponentPURL: "pkg:generic/curl@8.4.0",
		},
		Inventories: []*inventory.Inventory{{
			Path:   "clean-binary",
			Format: inventory.FormatELF,
			DynSyms: []inventory.Symbol{
				{Normalized: "curl_easy_perform"},
				{Normalized: "curl_global_init"},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict == decide.VerdictNotAffected {
		t.Fatal("unverified component must not produce not_affected")
	}
	if got.ReasonCode != decide.ReasonProvenanceUnverified {
		t.Fatalf("reason=%s want provenance_unverified", got.ReasonCode)
	}
}

func TestProvenance_VerifiedCanClear(t *testing.T) {
	t.Parallel()

	comp := manifest.Component{
		ProvenanceStatus: manifest.ProvenanceVerified,
		Name:             "openssl",
		Ecosystem:        "native",
		PURLs:            []string{"pkg:generic/openssl@3.0.7"},
		IdentitySymbols:  []string{"OPENSSL_init_ssl"},
	}
	m, err := manifest.BuildForTest("0.2.0", comp, []manifest.Entry{{
		CVE:              "CVE-2023-0286",
		AffectedVersions: []string{"3.0.7"},
		VulnerableSymbols: []manifest.VulnerableSymbol{{
			Name:                 "GENERAL_NAME_cmp",
			Confidence:           manifest.ConfidenceDefinitive,
			DynsymExportVerified: true,
			Provenance: manifest.Provenance{
				UpstreamFixCommit: "https://example.com/commit/fix",
				Derivation:        manifest.DerivationManual,
				ReviewedBy:        "test",
				ReviewedAt:        "2026-08-24",
			},
		}},
		ManifestVersion: "0.2.0",
	}})
	if err != nil {
		t.Fatal(err)
	}

	got, err := decide.Evaluate(decide.Input{
		Manifest: m,
		Finding: decide.Finding{
			CVE:           "CVE-2023-0286",
			ComponentPURL: "pkg:generic/openssl@3.0.7",
		},
		Inventories: []*inventory.Inventory{{
			Path:   "libssl.so",
			Format: inventory.FormatELF,
			DynSyms: []inventory.Symbol{
				{Normalized: "OPENSSL_init_ssl"},
				{Normalized: "SSL_CTX_new"},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != decide.VerdictNotAffected {
		t.Fatalf("verified component should clear: verdict=%s reason=%s", got.Verdict, got.ReasonCode)
	}
}
