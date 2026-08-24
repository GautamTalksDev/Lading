package manifest_test

import (
	"strings"
	"testing"

	"github.com/gautamtalksdev/lading/internal/manifest"
)

func TestLoadIdentityAliases_EmbeddedSeed(t *testing.T) {
	t.Parallel()

	ia, err := manifest.LoadIdentityAliases("")
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"binutils", "curl", "expat", "glibc", "imagemagick",
		"krb5", "mariadb", "openssl", "systemd", "util-linux",
	}
	got := ia.SourceNames()
	if len(got) != len(want) {
		t.Fatalf("count=%d want %d: %v", len(got), len(want), got)
	}
	for i, name := range want {
		if got[i] != name {
			t.Fatalf("names=%v want %v", got, want)
		}
	}

	a, ok := ia.Lookup("expat")
	if !ok {
		t.Fatal("missing expat alias")
	}
	if a.Status != manifest.AliasStatusDefinitive {
		t.Fatalf("status=%q want definitive", a.Status)
	}
	if a.Component != "pkg:generic/libexpat" {
		t.Fatalf("component=%q", a.Component)
	}
	if a.Provenance.ReviewedBy != "hand" || a.Provenance.VerifiedBy != "hand" {
		t.Fatalf("verified_by/reviewed_by=%q/%q want hand", a.Provenance.VerifiedBy, a.Provenance.ReviewedBy)
	}
	if a.Provenance.PackageVersion != "2.5.0-1+deb12u2" {
		t.Fatalf("package_version=%q", a.Provenance.PackageVersion)
	}
	if len(a.Provenance.IdentitySymbolsVerified) < 3 {
		t.Fatalf("identity_symbols_verified=%v", a.Provenance.IdentitySymbolsVerified)
	}

	// Only expat is definitive; histogram seeds stay probable.
	for _, name := range []string{"imagemagick", "binutils", "curl", "openssl", "krb5"} {
		x, ok := ia.Lookup(name)
		if !ok {
			t.Fatalf("missing probable alias %q", name)
		}
		if x.Status != manifest.AliasStatusProbable {
			t.Fatalf("%s status=%q want probable", name, x.Status)
		}
	}

	// Interpreter/toolchain packages must not be seeded.
	for _, banned := range []string{"perl", "python3.11", "python3.12"} {
		if _, ok := ia.Lookup(banned); ok {
			t.Fatalf("banned alias %q must not be present", banned)
		}
	}
}

func completeDefinitiveProvenance() manifest.AliasProvenance {
	return manifest.AliasProvenance{
		ArtifactSHA256:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Distro:                  "debian",
		PackageName:             "libexpat1",
		PackageVersion:          "2.5.0-1+deb12u1",
		VerifiedAt:              "2026-08-24",
		BinaryPath:              "usr/lib/x86_64-linux-gnu/libexpat.so.1.8.10",
		IdentitySymbolsVerified: []string{"XML_ParserCreate"},
		ExtractionMethod:        "dpkg-deb-extract",
		ReviewedBy:              "test-reviewer",
		URL:                     "https://sources.debian.org/src/expat/",
	}
}

func TestDefinitiveAlias_CompleteProvenanceLoads(t *testing.T) {
	t.Parallel()

	ia, err := manifest.BuildIdentityAliasesForTest(manifest.IdentityAlias{
		SourceName: "expat",
		Component:  "pkg:generic/libexpat",
		Status:     manifest.AliasStatusDefinitive,
		Provenance: completeDefinitiveProvenance(),
	})
	if err != nil {
		t.Fatal(err)
	}
	a, ok := ia.Lookup("expat")
	if !ok || a.Status != manifest.AliasStatusDefinitive {
		t.Fatalf("expected definitive expat alias, ok=%v status=%q", ok, a.Status)
	}
}

func TestDefinitiveAlias_IncompleteProvenanceFailsValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		mut  func(*manifest.AliasProvenance)
		want string
	}{
		{
			name: "missing_artifact_sha256",
			mut:  func(p *manifest.AliasProvenance) { p.ArtifactSHA256 = "" },
			want: "artifact_sha256",
		},
		{
			name: "missing_distro",
			mut:  func(p *manifest.AliasProvenance) { p.Distro = "" },
			want: "distro",
		},
		{
			name: "missing_package_name",
			mut:  func(p *manifest.AliasProvenance) { p.PackageName = "" },
			want: "package_name",
		},
		{
			name: "missing_package_version",
			mut:  func(p *manifest.AliasProvenance) { p.PackageVersion = "" },
			want: "package_version",
		},
		{
			name: "missing_verified_at",
			mut:  func(p *manifest.AliasProvenance) { p.VerifiedAt = "" },
			want: "verified_at",
		},
		{
			name: "missing_binary_path",
			mut:  func(p *manifest.AliasProvenance) { p.BinaryPath = "" },
			want: "binary_path",
		},
		{
			name: "empty_identity_symbols",
			mut:  func(p *manifest.AliasProvenance) { p.IdentitySymbolsVerified = nil },
			want: "identity_symbols_verified",
		},
		{
			name: "missing_extraction_method",
			mut:  func(p *manifest.AliasProvenance) { p.ExtractionMethod = "" },
			want: "extraction_method",
		},
		{
			name: "missing_reviewed_by",
			mut:  func(p *manifest.AliasProvenance) { p.ReviewedBy = "" },
			want: "reviewed_by",
		},
		{
			name: "empty_provenance_block",
			mut:  func(p *manifest.AliasProvenance) { *p = manifest.AliasProvenance{} },
			want: "artifact_sha256",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := completeDefinitiveProvenance()
			tc.mut(&p)
			_, err := manifest.BuildIdentityAliasesForTest(manifest.IdentityAlias{
				SourceName: "expat",
				Component:  "pkg:generic/libexpat",
				Status:     manifest.AliasStatusDefinitive,
				Provenance: p,
			})
			if err == nil {
				t.Fatal("expected validation failure for definitive alias without complete provenance")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%q want substring %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "definitive") {
				t.Fatalf("error should mention definitive: %q", err.Error())
			}
		})
	}
}

func TestDefinitiveAlias_DeniedExtractionMethodFails(t *testing.T) {
	t.Parallel()

	denied := []string{
		"debian-control",
		"changelog",
		"grype-upstream",
		"upstream-qualifier",
		"container-layer",
		"third-party",
		"automated-scrape",
	}
	for _, method := range denied {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			p := completeDefinitiveProvenance()
			p.ExtractionMethod = method
			_, err := manifest.BuildIdentityAliasesForTest(manifest.IdentityAlias{
				SourceName: "expat",
				Component:  "pkg:generic/libexpat",
				Status:     manifest.AliasStatusDefinitive,
				Provenance: p,
			})
			if err == nil {
				t.Fatalf("expected rejection for extraction_method=%q", method)
			}
		})
	}
}

func TestProbableAlias_IncompleteProvenanceOK(t *testing.T) {
	t.Parallel()

	_, err := manifest.BuildIdentityAliasesForTest(manifest.IdentityAlias{
		SourceName: "expat",
		Component:  "pkg:generic/libexpat",
		Status:     manifest.AliasStatusProbable,
		Provenance: manifest.AliasProvenance{
			URL: "https://sources.debian.org/src/expat/",
		},
	})
	if err != nil {
		t.Fatalf("probable alias with partial provenance must load: %v", err)
	}
}
