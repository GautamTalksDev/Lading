package purl_test

import (
	"testing"

	"github.com/gautamtalksdev/lading/internal/purl"
)

func TestParseUpstream(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		purl        string
		wantName    string
		wantVersion string
		wantOK      bool
	}{
		{
			name:        "percent40 decode",
			purl:        "pkg:deb/debian/bsdutils@1%3A2.38.1-5%2Bdeb12u3?arch=amd64&distro=debian-12&upstream=util-linux%402.38.1-5%2Bdeb12u3",
			wantName:    "util-linux",
			wantVersion: "2.38.1-5+deb12u3",
			wantOK:      true,
		},
		{
			name:        "plain upstream name",
			purl:        "pkg:deb/debian/libexpat1@2.5.0-1%2Bdeb12u1?arch=amd64&distro=debian-12&upstream=expat",
			wantName:    "expat",
			wantVersion: "",
			wantOK:      true,
		},
		{
			name:   "src rpm strip",
			purl:   "pkg:rpm/rocky/vim@8.2.2637-26.el9_8.4?upstream=vim-8.2.2637-26.el9_8.4.src.rpm",
			wantName: "vim",
			wantOK:   true,
		},
		{
			name:   "absent qualifier",
			purl:   "pkg:deb/debian/zlib1g@1.2.11",
			wantOK: false,
		},
		{
			name:   "non-distro type",
			purl:   "pkg:generic/openssl@3.0.7?upstream=openssl",
			wantOK: false,
		},
		{
			name:   "empty upstream value",
			purl:   "pkg:deb/debian/curl@7.88.1?upstream=",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotName, gotVer, ok := purl.ParseUpstream(tc.purl)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v (name=%q version=%q)", ok, tc.wantOK, gotName, gotVer)
			}
			if !tc.wantOK {
				return
			}
			if gotName != tc.wantName {
				t.Fatalf("name=%q want %q", gotName, tc.wantName)
			}
			if gotVer != tc.wantVersion {
				t.Fatalf("version=%q want %q", gotVer, tc.wantVersion)
			}
		})
	}
}

func TestMatchQuality_IdentityMappedOrdering(t *testing.T) {
	t.Parallel()
	order := []purl.MatchQuality{
		purl.None,
		purl.NameOnly,
		purl.NameVersionOnly,
		purl.TypeNormalized,
		purl.IdentityMapped,
		purl.Exact,
	}
	for i := 1; i < len(order); i++ {
		if !order[i].AtLeast(order[i-1]) {
			t.Fatalf("%v should be >= %v", order[i], order[i-1])
		}
		if order[i-1].AtLeast(order[i]) && order[i-1] != order[i] {
			t.Fatalf("%v should not be >= %v", order[i-1], order[i])
		}
	}
	if purl.IdentityMapped.String() != "identity_mapped" {
		t.Fatalf("string=%q", purl.IdentityMapped.String())
	}
}
