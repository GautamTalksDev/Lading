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
			name:        "percent40_decode_before_split",
			purl:        "pkg:deb/debian/bsdutils@1%3A2.38.1-5%2Bdeb12u3?arch=amd64&distro=debian-12&upstream=util-linux%402.38.1-5%2Bdeb12u3",
			wantName:    "util-linux",
			wantVersion: "2.38.1-5+deb12u3",
			wantOK:      true,
		},
		{
			name:        "percent40_histogram_form",
			purl:        "pkg:deb/debian/bsdutils@1%3A2.41-5?upstream=util-linux%402.41-5",
			wantName:    "util-linux",
			wantVersion: "2.41-5",
			wantOK:      true,
		},
		{
			name:        "plain_upstream_name",
			purl:        "pkg:deb/debian/libexpat1@2.5.0-1%2Bdeb12u1?arch=amd64&distro=debian-12&upstream=expat",
			wantName:    "expat",
			wantVersion: "",
			wantOK:      true,
		},
		{
			name:     "src_rpm_strip_simple",
			purl:     "pkg:rpm/rocky/vim@8.2.2637-26.el9_8.4?upstream=vim-8.2.2637-26.el9_8.4.src.rpm",
			wantName: "vim",
			wantOK:   true,
		},
		{
			name:     "src_rpm_strip_hyphenated_name",
			purl:     "pkg:rpm/rhel/util-linux@2.37.4-18.el9?upstream=util-linux-2.37.4-18.el9.src.rpm",
			wantName: "util-linux",
			wantOK:   true,
		},
		{
			name:     "src_rpm_openssl",
			purl:     "pkg:rpm/rocky/openssl@3.0.7-25.el9?upstream=openssl-3.0.7-25.el9.src.rpm",
			wantName: "openssl",
			wantOK:   true,
		},
		{
			name:     "debian_variant_gnutls28",
			purl:     "pkg:deb/debian/libgnutls30@3.7.9-2?upstream=gnutls28",
			wantName: "gnutls",
			wantOK:   true,
		},
		{
			name:     "debian_variant_glib2.0",
			purl:     "pkg:deb/debian/libglib2.0-0@2.74.6-2?upstream=glib2.0",
			wantName: "glib",
			wantOK:   true,
		},
		{
			name:     "debian_variant_gcc-12",
			purl:     "pkg:deb/debian/gcc-12@12.2.0-14?upstream=gcc-12",
			wantName: "gcc",
			wantOK:   true,
		},
		{
			name:     "absent_qualifier",
			purl:     "pkg:deb/debian/zlib1g@1.2.11",
			wantOK:   false,
		},
		{
			name:   "non_distro_type",
			purl:   "pkg:generic/openssl@3.0.7?upstream=openssl",
			wantOK: false,
		},
		{
			name:   "empty_upstream_value",
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

func TestNormalizeUpstreamSourceName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in, want string
	}{
		{"vim-8.2.2637-26.el9_8.4.src.rpm", "vim"},
		{"util-linux-2.37.4-18.el9.src.rpm", "util-linux"},
		{"openssl-3.0.7-25.el9.src.rpm", "openssl"},
		{"krb5-1.20.1-6.el9.src.rpm", "krb5"},
		{"gnutls28", "gnutls"},
		{"glib2.0", "glib"},
		{"gcc-12", "gcc"},
		{"gcc-13", "gcc"},
		{"expat", "expat"},
		{"util-linux", "util-linux"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			if got := purl.NormalizeUpstreamSourceName(tc.in); got != tc.want {
				t.Fatalf("NormalizeUpstreamSourceName(%q)=%q want %q", tc.in, got, tc.want)
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
