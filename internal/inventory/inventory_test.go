package inventory_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gautamtalksdev/lading/internal/inventory"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	p := filepath.Join(filepath.Dir(file), "..", "..", "testdata", "inventory", "bin", name)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("fixture %s missing (run make -C testdata/inventory): %v", name, err)
	}
	return p
}

func TestScan_DynStrippedELF(t *testing.T) {
	inv, err := inventory.Scan(fixture(t, "dyn_stripped_elf"))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Format != inventory.FormatELF {
		t.Fatalf("Format=%s", inv.Format)
	}
	if !inv.Stripped {
		t.Fatal("expected Stripped=true")
	}
	if inv.StaticLinked {
		t.Fatal("expected StaticLinked=false")
	}
	if len(inv.Needed) == 0 {
		t.Fatal("expected DT_NEEDED")
	}
	if len(inv.SymTab) != 0 {
		t.Fatalf("stripped binary should have empty SymTab, got %d", len(inv.SymTab))
	}
	if !containsString(inv.RoStrings, "LADING_RODATA_MARKER") {
		t.Fatalf("missing rostring; got %v", inv.RoStrings)
	}
	assertSortedSymbols(t, inv)
}

func TestScan_DynUnstrippedELF(t *testing.T) {
	inv, err := inventory.Scan(fixture(t, "dyn_unstripped_elf"))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Stripped {
		t.Fatal("expected Stripped=false")
	}
	if inv.StaticLinked {
		t.Fatal("expected StaticLinked=false")
	}
	if !hasSymbolNamed(inv.SymTab, "lading_export") && !hasSymbolNormalized(inv.SymTab, "lading_export") {
		t.Fatalf("expected lading_export in SymTab; got %d syms", len(inv.SymTab))
	}
}

func TestScan_StaticStrippedELF(t *testing.T) {
	inv, err := inventory.Scan(fixture(t, "static_stripped_elf"))
	if err != nil {
		t.Fatal(err)
	}
	if !inv.Stripped {
		t.Fatal("expected Stripped=true")
	}
	if !inv.StaticLinked {
		t.Fatal("expected StaticLinked=true")
	}
	if len(inv.Needed) != 0 {
		t.Fatalf("static binary must have empty Needed, got %v", inv.Needed)
	}
	// Hard case: stripped + static ⇒ virtually no usable exported symbols.
	if len(inv.DynSyms) > 5 {
		t.Fatalf("static stripped should yield almost no DynSyms, got %d", len(inv.DynSyms))
	}
	if len(inv.SymTab) != 0 {
		t.Fatalf("stripped ⇒ empty SymTab, got %d", len(inv.SymTab))
	}
}

func TestScan_CXXMangled(t *testing.T) {
	inv, err := inventory.Scan(fixture(t, "cxx_mangled_elf"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range append(append([]inventory.Symbol{}, inv.SymTab...), inv.DynSyms...) {
		if strings.Contains(s.Raw, "_ZN6lading5greetEPKc") || strings.HasPrefix(s.Raw, "_ZN6lading") {
			if s.Demangled == s.Raw {
				t.Fatalf("expected demangle of %q, got identical Demangled", s.Raw)
			}
			if !strings.Contains(s.Demangled, "lading") && !strings.Contains(s.Normalized, "lading") {
				t.Fatalf("demangled=%q normalized=%q", s.Demangled, s.Normalized)
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no C++ mangled lading symbol found")
	}
}

func TestScan_SymbolVersioning(t *testing.T) {
	inv, err := inventory.Scan(fixture(t, "symver_ssl_elf"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range inv.DynSyms {
		if strings.Contains(s.Raw, "OPENSSL_init_ssl") || s.Normalized == "OPENSSL_init_ssl" {
			found = true
			if s.Version == "" && !strings.Contains(s.Raw, "@") {
				// Version may live in Version field from versym, or in Raw as @VER.
				t.Fatalf("OPENSSL_init_ssl missing version: %+v", s)
			}
			if strings.Contains(s.Normalized, "@") {
				t.Fatalf("Normalized must not contain version: %q", s.Normalized)
			}
			break
		}
	}
	if !found {
		t.Fatalf("OPENSSL_init_ssl not found in DynSyms (%d)", len(inv.DynSyms))
	}
}

func TestScan_WeakAndIFUNC(t *testing.T) {
	inv, err := inventory.Scan(fixture(t, "weak_ifunc_elf"))
	if err != nil {
		t.Fatal(err)
	}
	var sawWeak, sawIFUNC bool
	for _, s := range append(append([]inventory.Symbol{}, inv.SymTab...), inv.DynSyms...) {
		if s.Normalized == "weak_sym" || s.Raw == "weak_sym" {
			if s.Bind != "WEAK" {
				t.Fatalf("weak_sym Bind=%s", s.Bind)
			}
			sawWeak = true
		}
		if s.Normalized == "resolved" || s.Raw == "resolved" {
			if s.Type != "IFUNC" {
				t.Fatalf("resolved Type=%s want IFUNC", s.Type)
			}
			sawIFUNC = true
		}
	}
	if !sawWeak || !sawIFUNC {
		t.Fatalf("sawWeak=%v sawIFUNC=%v", sawWeak, sawIFUNC)
	}
}

func TestScan_PE(t *testing.T) {
	inv, err := inventory.Scan(fixture(t, "sample_pe.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Format != inventory.FormatPE {
		t.Fatalf("Format=%s", inv.Format)
	}
	if inv.Arch != "amd64" {
		t.Fatalf("Arch=%s", inv.Arch)
	}
	if inv.StaticLinked {
		t.Fatal("PE Go binary should import DLLs")
	}
	if len(inv.Needed) == 0 && len(inv.DynSyms) == 0 {
		t.Fatal("expected imports")
	}
}

func TestScan_MachO(t *testing.T) {
	inv, err := inventory.Scan(fixture(t, "sample_macho"))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Format != inventory.FormatMachO {
		t.Fatalf("Format=%s", inv.Format)
	}
	if inv.Arch != "amd64" {
		t.Fatalf("Arch=%s", inv.Arch)
	}
}

func TestScan_TruncatedELF_WarningNotPanic(t *testing.T) {
	inv, err := inventory.Scan(fixture(t, "truncated_elf"))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Format != inventory.FormatELF && inv.Format != inventory.FormatUnknown {
		t.Fatalf("Format=%s", inv.Format)
	}
	if len(inv.Warnings) == 0 {
		t.Fatal("expected Warnings for truncated ELF")
	}
}

func TestScan_TooLarge(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "huge.bin")
	f, err := os.Create(p) // #nosec G304 -- temp path under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	// Sparse file: size check uses Stat, never reads contents.
	if truncErr := f.Truncate(600 << 20); truncErr != nil {
		_ = f.Close()
		t.Fatal(truncErr)
	}
	_ = f.Close()

	_, err = inventory.Scan(p)
	if err == nil {
		t.Fatal("expected error for 600 MiB file")
	}
	var too *inventory.ErrTooLarge
	if !errorAs(err, &too) {
		t.Fatalf("want *ErrTooLarge, got %T: %v", err, err)
	}
}

func TestScan_DeterministicSerialize(t *testing.T) {
	path := fixture(t, "dyn_unstripped_elf")
	a, err := inventory.Scan(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := inventory.Scan(path)
	if err != nil {
		t.Fatal(err)
	}
	sa, err := inventory.Serialize(a)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := inventory.Serialize(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sa, sb) {
		t.Fatalf("non-deterministic serialize\nA=%s\nB=%s", sa, sb)
	}
}

func TestDemangleAndNormalize(t *testing.T) {
	cases := []struct {
		in, wantDemangleContains, wantNorm string
	}{
		{"_ZN6lading5greetEPKc", "lading", "lading::greet"},
		{"plain_sym", "plain_sym", "plain_sym"},
		{"__wrap_puts", "__wrap_puts", "puts"},
		{"_foo", "_foo", "foo"},
	}
	for _, tc := range cases {
		d := inventory.Demangle(tc.in)
		if !strings.Contains(d, tc.wantDemangleContains) {
			t.Fatalf("Demangle(%q)=%q want contains %q", tc.in, d, tc.wantDemangleContains)
		}
		n := inventory.Normalize(d)
		if tc.wantNorm != "" && !strings.HasPrefix(n, strings.Split(tc.wantNorm, "(")[0]) {
			// Allow demangler to add parameter lists.
			if n != tc.wantNorm && !strings.Contains(n, "lading") && tc.in != "__wrap_puts" && tc.in != "_foo" && tc.in != "plain_sym" {
				t.Fatalf("Normalize(%q)=%q", d, n)
			}
		}
		if tc.in == "__wrap_puts" && n != "puts" {
			t.Fatalf("Normalize(__wrap_puts demangled)=%q want puts", n)
		}
		if tc.in == "_foo" && inventory.Normalize(tc.in) != "foo" {
			t.Fatalf("Normalize(_foo)=%q", inventory.Normalize(tc.in))
		}
	}
}

func TestUnknownFormat(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.bin")
	if err := os.WriteFile(p, []byte("not a binary!!!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := inventory.Scan(p)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Format != inventory.FormatUnknown {
		t.Fatalf("Format=%s", inv.Format)
	}
	if len(inv.Warnings) == 0 {
		t.Fatal("expected warning")
	}
}

func assertSortedSymbols(t *testing.T, inv *inventory.Inventory) {
	t.Helper()
	check := func(syms []inventory.Symbol) {
		for i := 1; i < len(syms); i++ {
			if syms[i-1].Normalized > syms[i].Normalized {
				t.Fatalf("unsorted: %q > %q", syms[i-1].Normalized, syms[i].Normalized)
			}
			if syms[i-1].Normalized == syms[i].Normalized && syms[i-1].Raw > syms[i].Raw {
				t.Fatalf("unsorted raw: %q > %q", syms[i-1].Raw, syms[i].Raw)
			}
		}
	}
	check(inv.DynSyms)
	check(inv.SymTab)
}

func containsString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func hasSymbolNamed(syms []inventory.Symbol, name string) bool {
	for _, s := range syms {
		if s.Raw == name || strings.HasPrefix(s.Raw, name+"@") {
			return true
		}
	}
	return false
}

func hasSymbolNormalized(syms []inventory.Symbol, name string) bool {
	for _, s := range syms {
		if s.Normalized == name {
			return true
		}
	}
	return false
}

func errorAs(err error, target **inventory.ErrTooLarge) bool {
	e, ok := err.(*inventory.ErrTooLarge)
	if !ok {
		return false
	}
	*target = e
	return true
}
