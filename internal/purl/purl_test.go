package purl_test

import (
	"testing"

	"github.com/gautamtalksdev/lading/internal/purl"
)

func TestCanonicalize_PreservesRawAndNormalizes(t *testing.T) {
	raw := "pkg:NPM/%40angular/core@14.0.0?arch=x86_64&os=linux"
	p, err := purl.Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Raw != raw {
		t.Fatalf("Raw not preserved: %q", p.Raw)
	}
	if p.Type != "npm" {
		t.Fatalf("type=%q", p.Type)
	}
	if p.Namespace != "@angular" {
		t.Fatalf("namespace=%q", p.Namespace)
	}
	if p.Name != "core" {
		t.Fatalf("name=%q", p.Name)
	}
	can := p.Canonical()
	// Qualifiers sorted (arch before os). '@' in namespace remains literal after decode.
	if can != "pkg:npm/@angular/core@14.0.0?arch=x86_64&os=linux" {
		t.Fatalf("canonical=%q", can)
	}
}

func TestCanonicalize_PyPI(t *testing.T) {
	p, err := purl.Canonicalize("pkg:pypi/Django_Debug_Toolbar@3.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "django-debug-toolbar" {
		t.Fatalf("name=%q", p.Name)
	}
}

func TestEquivalent_Exact(t *testing.T) {
	a, _ := purl.Canonicalize("pkg:npm/lodash@4.17.21")
	b, _ := purl.Canonicalize("pkg:NPM/lodash@4.17.21")
	q := purl.Equivalent(a, b)
	if q != purl.Exact {
		t.Fatalf("got %v want Exact", q)
	}
}

func TestEquivalent_CrossType_AtMostNameVersionOnly(t *testing.T) {
	// Cross-type must never be Exact (documented ecosystem bug surface).
	a, _ := purl.Canonicalize("pkg:generic/openssl@3.0.2")
	b, _ := purl.Canonicalize("pkg:deb/debian/openssl@3.0.2")
	q := purl.Equivalent(a, b)
	if q != purl.NameVersionOnly {
		t.Fatalf("got %v want NameVersionOnly", q)
	}
	if q == purl.Exact || q == purl.TypeNormalized {
		t.Fatal("cross-type must not be Exact/TypeNormalized")
	}
}

func TestEquivalent_DigestConflict(t *testing.T) {
	a, _ := purl.Canonicalize("pkg:generic/openssl@3.0.2?checksum=sha256:aaa")
	b, _ := purl.Canonicalize("pkg:generic/openssl@3.0.2?checksum=sha256:bbb")
	q := purl.Equivalent(a, b)
	if q != purl.None {
		t.Fatalf("digest conflict: got %v want None", q)
	}
}

func TestEquivalent_NameOnly(t *testing.T) {
	a, _ := purl.Canonicalize("pkg:npm/lodash@4.17.21")
	b, _ := purl.Canonicalize("pkg:npm/lodash@4.17.20")
	q := purl.Equivalent(a, b)
	if q != purl.NameOnly {
		t.Fatalf("got %v want NameOnly", q)
	}
}

func TestEquivalent_UnversionedTemplate_TypeNormalized(t *testing.T) {
	a, _ := purl.Canonicalize("pkg:deb/debian/libssl3@3.0.19-1")
	b, _ := purl.Canonicalize("pkg:deb/debian/libssl3")
	q := purl.Equivalent(a, b)
	if q != purl.TypeNormalized {
		t.Fatalf("got %v want TypeNormalized", q)
	}
}

func TestMatchQuality_NoBareBoolean(t *testing.T) {
	// Public API surface check: Equivalent returns MatchQuality, not bool.
	a, _ := purl.Canonicalize("pkg:generic/foo@1")
	b, _ := purl.Canonicalize("pkg:generic/foo@1")
	q := purl.Equivalent(a, b)
	_ = q.String()
	_ = q.AtLeast(purl.Exact)
}

func TestCanonicalize_PercentDecodeOnce(t *testing.T) {
	p, err := purl.Canonicalize("pkg:generic/foo%2Fbar@1.0")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "foo/bar" {
		t.Fatalf("name=%q", p.Name)
	}
}
