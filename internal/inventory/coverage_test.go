package inventory

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	p := filepath.Join(filepath.Dir(file), "..", "..", "testdata", "inventory", "bin", name)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("missing %s: %v", p, err)
	}
	return p
}

func TestScan_SymverDef_VERDEF(t *testing.T) {
	inv, err := Scan(fixturePath(t, "symver_def.so"))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Format != FormatELF {
		t.Fatalf("format %s", inv.Format)
	}
	found := false
	for _, s := range inv.DynSyms {
		if s.Normalized == "lading_ver_foo" || s.Normalized == "lading_ver_bar" {
			if s.Version == "" {
				t.Fatalf("expected version on %v", s)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("expected versioned symbols; dyn=%d", len(inv.DynSyms))
	}
}

func TestScan_RoStringsCap(t *testing.T) {
	inv, err := ScanWithOptions(fixturePath(t, "sample_macho"), Options{MaxRoStrings: 3, MinRoStringLen: 6})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.RoStrings) > 3 {
		t.Fatalf("cap exceeded: %d", len(inv.RoStrings))
	}
	saw := false
	for _, w := range inv.Warnings {
		if w.Code == "rostrings_capped" {
			saw = true
		}
	}
	if !saw && len(inv.RoStrings) == 3 {
		// Cap warning expected when truncated.
		t.Fatal("expected rostrings_capped warning")
	}
}

func TestScan_CorruptPE(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.exe")
	// MZ header but truncated PE.
	if err := os.WriteFile(p, []byte{'M', 'Z', 0, 0, 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := Scan(p)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Format != FormatPE {
		t.Fatalf("format %s", inv.Format)
	}
	if len(inv.Warnings) == 0 {
		t.Fatal("expected pe parse warning")
	}
}

func TestScan_CorruptMachO(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.macho")
	if err := os.WriteFile(p, []byte{0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := Scan(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Warnings) == 0 {
		t.Fatal("expected macho parse warning")
	}
}

func TestScan_FatMachO(t *testing.T) {
	inv, err := Scan(fixturePath(t, "sample_macho_fat"))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Format != FormatMachO {
		t.Fatalf("format %s", inv.Format)
	}
	saw := false
	for _, w := range inv.Warnings {
		if w.Code == "macho_fat" {
			saw = true
		}
	}
	if !saw {
		t.Fatal("expected macho_fat warning")
	}
}

func TestScan_ELFRoStringsCap(t *testing.T) {
	inv, err := ScanWithOptions(fixturePath(t, "dyn_unstripped_elf"), Options{MaxRoStrings: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.RoStrings) > 1 {
		t.Fatalf("cap: %d", len(inv.RoStrings))
	}
}

func TestScan_PERoStringsCap(t *testing.T) {
	inv, err := ScanWithOptions(fixturePath(t, "sample_pe.exe"), Options{MaxRoStrings: 2, MinRoStringLen: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.RoStrings) > 2 {
		t.Fatalf("cap: %d", len(inv.RoStrings))
	}
}


func TestElfBindTypeExhaustive(t *testing.T) {
	for b := 0; b < 8; b++ {
		for ty := 0; ty < 16; ty++ {
			info := byte((b << 4) | ty)
			bind, typ := elfBindType(info)
			if bind == "" || typ == "" {
				t.Fatalf("empty for info=%d", info)
			}
		}
	}
}

func TestCstringAtEdges(t *testing.T) {
	if cstringAt(nil, 0) != "" {
		t.Fatal("nil")
	}
	if cstringAt([]byte("ab\x00c"), 0) != "ab" {
		t.Fatal("cstr")
	}
	if cstringAt([]byte("ab"), 5) != "" {
		t.Fatal("oob")
	}
	if cstringAt([]byte("ab"), -1) != "" {
		t.Fatal("neg")
	}
}

func TestFinalizeNilSlices(t *testing.T) {
	inv := &Inventory{}
	finalize(inv)
	if inv.DynSyms == nil || inv.SymTab == nil || inv.Needed == nil || inv.RoStrings == nil || inv.Warnings == nil {
		t.Fatal("expected empty non-nil slices")
	}
}

func TestMakeSymbolVersioned(t *testing.T) {
	s := makeSymbol("foo@@V1", "GLOBAL", "FUNC", true, "")
	if s.Version != "V1" || s.Normalized != "foo" {
		t.Fatalf("%+v", s)
	}
	s = makeSymbol("bar", "GLOBAL", "FUNC", false, "HINT")
	if s.Version != "HINT" {
		t.Fatalf("%+v", s)
	}
}

func TestParseGNUBuildID(t *testing.T) {
	if parseGNUBuildID(nil) != "" {
		t.Fatal("nil")
	}
	if parseGNUBuildID(make([]byte, 8)) != "" {
		t.Fatal("short")
	}
	// namesz=4 ("GNU\0"), descsz=4, type=3, name padded, desc=deadbeef
	data := make([]byte, 24)
	binary.LittleEndian.PutUint32(data[0:], 4)
	binary.LittleEndian.PutUint32(data[4:], 4)
	binary.LittleEndian.PutUint32(data[8:], 3)
	copy(data[12:], []byte("GNU\x00"))
	copy(data[16:], []byte{0xde, 0xad, 0xbe, 0xef})
	got := parseGNUBuildID(data)
	if got != "deadbeef" {
		t.Fatalf("got %q", got)
	}
	// wrong type
	binary.LittleEndian.PutUint32(data[8:], 1)
	if parseGNUBuildID(data) != "" {
		t.Fatal("wrong type")
	}
	// descsz overflow
	binary.LittleEndian.PutUint32(data[8:], 3)
	binary.LittleEndian.PutUint32(data[4:], 100)
	if parseGNUBuildID(data) != "" {
		t.Fatal("overflow")
	}
}

func TestSectionDataMissing(t *testing.T) {
	// Open a real ELF and ask for a missing section name via sectionData.
	f, err := elf.Open(fixturePath(t, "dyn_stripped_elf"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if sectionData(f, ".no_such_section_lading") != nil {
		t.Fatal("expected nil")
	}
	if sectionData(f, ".dynstr") == nil {
		t.Fatal("expected dynstr")
	}
}
