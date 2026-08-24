package groundtruth_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gautamtalksdev/lading/internal/decide"
	"github.com/gautamtalksdev/lading/internal/inventory"
	"github.com/gautamtalksdev/lading/internal/manifest"
)

// TestD01Probe_OpenSSLAbsentOnBusybox is a post-kill-test probe (not KT-1/KT-2
// evidence): one real shipped binary with no OpenSSL linkage, scanner-style
// libssl3 PURL, expect D01 component_not_present.
func TestD01Probe_OpenSSLAbsentOnBusybox(t *testing.T) {
	root := filepath.Join("..", "..")
	busybox := filepath.Join(root, ".lading", "profile-rootfs", "oci-busybox-latest", "bin", "busybox")
	if _, err := os.Stat(busybox); err != nil {
		t.Skipf("busybox probe binary absent (%v); run corpus-download + profile extract", err)
	}

	inv, err := inventory.Scan(busybox)
	if err != nil {
		t.Fatalf("inventory.Scan: %v", err)
	}
	if inv.Stripped && inv.StaticLinked {
		t.Fatalf("probe precondition: busybox must not be static-linked for D01 dynsym path")
	}
	if len(inv.DynSyms) == 0 {
		t.Fatalf("probe precondition: busybox .dynsym empty — cannot exercise D01")
	}

	m, err := manifest.Load(filepath.Join(root, "manifest"))
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	aliases, err := manifest.LoadIdentityAliases(filepath.Join(root, "manifest", "data", "identity-aliases.json"))
	if err != nil {
		t.Fatalf("LoadIdentityAliases: %v", err)
	}

	// Grype-style distro PURL for libssl3; component is absent from busybox.
	finding := decide.Finding{
		CVE:           "CVE-2023-0286",
		ComponentPURL: "pkg:deb/debian/libssl3@3.0.20-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl",
	}
	got, err := decide.Evaluate(decide.Input{
		Inventories:     []*inventory.Inventory{inv},
		Finding:         finding,
		Manifest:        m,
		IdentityAliases: aliases,
	})
	if err != nil {
		t.Fatalf("decide.Evaluate: %v", err)
	}

	t.Logf("verdict=%s rule=%s justification=%s reason=%s component_inv=%v",
		got.Verdict, got.RuleID, got.Justification, got.ReasonCode, got.InputsUsed.ComponentInventories)

	if got.Verdict != decide.VerdictNotAffected {
		t.Fatalf("want NOT_AFFECTED (D01), got verdict=%s rule=%s reason=%s", got.Verdict, got.RuleID, got.ReasonCode)
	}
	if got.RuleID != decide.RuleD01 {
		t.Fatalf("want D01, got rule=%s reason=%s", got.RuleID, got.ReasonCode)
	}
	if got.Justification != decide.JustificationComponentNotPresent {
		t.Fatalf("want component_not_present, got %s", got.Justification)
	}
	if len(got.InputsUsed.ComponentInventories) != 0 {
		t.Fatalf("component must not be identified; got inventories %v", got.InputsUsed.ComponentInventories)
	}

	// Independent binary check recorded in the probe trail.
	observed := map[string]struct{}{}
	for _, s := range inv.DynSyms {
		if s.Normalized != "" {
			observed[s.Normalized] = struct{}{}
		}
	}
	for _, sym := range []string{"OPENSSL_init_ssl", "GENERAL_NAME_cmp", "SSL_CTX_new", "TLS_method"} {
		if _, ok := observed[sym]; ok {
			t.Fatalf("openssl identity symbol %s present in busybox .dynsym", sym)
		}
	}
	if strings.Contains(inv.Path, "busybox") {
		t.Log("probe artifact: oci-busybox-latest/bin/busybox — DT_NEEDED: libm, libresolv, libc only; no libssl/libcrypto on rootfs")
	}
}
