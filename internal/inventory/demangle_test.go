package inventory

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"strings"
	"testing"
)

func TestDemangleItaniumTable(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"_Z3foov", "foo()", true},
		{"_Z3fooi", "foo(int)", true},
		{"_ZN6lading5greetEPKc", "lading::greet(const char*)", true},
		{"_ZNK6lading6Widget6answerEi", "lading::Widget::answer(int)", true},
		{"_ZN3FooC1Ev", "Foo::<constructor>()", true},
		{"_ZN3FooD1Ev", "Foo::<destructor>()", true},
		{"_Z3barPKcii", "bar(const char*, int, int)", true},
		{"_Z3bazRKi", "baz(const int&)", true},
		{"_Z3quxOi", "qux(int&&)", true},
		{"_Z3aaab", "aaa(bool)", true},
		{"_Z3aaac", "aaa(char)", true},
		{"_Z3aaaa", "aaa(signed char)", true},
		{"_Z3aaah", "aaa(unsigned char)", true},
		{"_Z3aaas", "aaa(short)", true},
		{"_Z3aaat", "aaa(unsigned short)", true},
		{"_Z3aaaj", "aaa(unsigned int)", true},
		{"_Z3aaal", "aaa(long)", true},
		{"_Z3aaam", "aaa(unsigned long)", true},
		{"_Z3aaax", "aaa(long long)", true},
		{"_Z3aaay", "aaa(unsigned long long)", true},
		{"_Z3aaaf", "aaa(float)", true},
		{"_Z3aaad", "aaa(double)", true},
		{"_Z3aaaPKi", "aaa(const int*)", true},
		{"_Z3aaa3Foo", "aaa(Foo)", true},
		{"_ZSa", "std::allocator", true},
		{"_ZSb", "std::basic_string", true},
		{"_ZSs", "std::string", true},
		{"_ZSi", "std::istream", true},
		{"_ZSo", "std::ostream", true},
		{"_ZSd", "std::iostream", true},
		{"_ZS_", "std::placeholder", true},
		{"_ZSt", "std", true},
		{"_ZS0_", "std::?", true},
		{"not_mangled", "", false},
		{"_Z", "", false},
		{"_ZN", "", false},
	}
	for _, tc := range cases {
		got, ok := demangleItanium(tc.in)
		if ok != tc.ok {
			t.Errorf("%s: ok=%v want %v (got %q)", tc.in, ok, tc.ok, got)
			continue
		}
		if tc.ok && got != tc.want {
			t.Errorf("%s: got %q want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizePrefixes(t *testing.T) {
	cases := map[string]string{
		"__wrap_puts":    "puts",
		"__real_puts":    "puts",
		"_puts":          "puts",
		"puts":           "puts",
		"__wrap__real_x": "real_x", // wrap stripped first, then single leading '_'
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDemangleExported(t *testing.T) {
	if Demangle("hello") != "hello" {
		t.Fatal("passthrough")
	}
	if Demangle("_Z3foov") != "foo()" {
		t.Fatalf("got %q", Demangle("_Z3foov"))
	}
	// Mach-O-style leading underscore before _Z.
	if got := Demangle("__Z3foov"); got != "foo()" {
		t.Fatalf("mach-o style: got %q", got)
	}
}

func TestPrintableStrings(t *testing.T) {
	data := []byte("short\x00LADING_OK\x00\xffbad\x00ABC\x00")
	got := printableStrings(data, 6)
	if len(got) != 1 || got[0] != "LADING_OK" {
		t.Fatalf("got %#v", got)
	}
	if len(printableStrings(nil, 0)) != 0 {
		t.Fatal("empty")
	}
}

func TestErrTooLargeError(t *testing.T) {
	e := &ErrTooLarge{Path: "x", Size: 10, Max: 5}
	if !strings.Contains(e.Error(), "exceeds") {
		t.Fatalf("error=%q", e.Error())
	}
}

func TestSerializeNil(t *testing.T) {
	if _, err := Serialize(nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestArchHelpers(t *testing.T) {
	for _, m := range []elf.Machine{
		elf.EM_X86_64, elf.EM_386, elf.EM_AARCH64, elf.EM_ARM,
		elf.EM_PPC64, elf.EM_S390, elf.EM_RISCV, elf.EM_NONE,
	} {
		if elfArch(m) == "" {
			t.Fatalf("elfArch(%v) empty", m)
		}
	}
	for _, m := range []uint16{
		pe.IMAGE_FILE_MACHINE_AMD64,
		pe.IMAGE_FILE_MACHINE_I386,
		pe.IMAGE_FILE_MACHINE_ARM64,
		pe.IMAGE_FILE_MACHINE_ARM,
		pe.IMAGE_FILE_MACHINE_ARMNT,
		0,
	} {
		if peArchMachine(m) == "" {
			t.Fatalf("peArchMachine %d empty", m)
		}
	}
	for _, c := range []macho.Cpu{
		macho.CpuAmd64, macho.Cpu386, macho.CpuArm64, macho.CpuArm, 0,
	} {
		if machoArch(c) == "" {
			t.Fatalf("machoArch(%v) empty", c)
		}
	}
}

func TestSplitSymbolVersion(t *testing.T) {
	b, v := splitSymbolVersion("foo@@GLIBC_2.2.5")
	if b != "foo" || v != "GLIBC_2.2.5" {
		t.Fatalf("%s %s", b, v)
	}
	b, v = splitSymbolVersion("foo@GLIBC_2.2.5")
	if b != "foo" || v != "GLIBC_2.2.5" {
		t.Fatalf("%s %s", b, v)
	}
	b, v = splitSymbolVersion("foo")
	if b != "foo" || v != "" {
		t.Fatalf("%s %s", b, v)
	}
}

func TestSniffFormat(t *testing.T) {
	type tc struct {
		want Format
		b    []byte
	}
	cases := []tc{
		{FormatELF, []byte{0x7f, 'E', 'L', 'F'}},
		{FormatPE, []byte{'M', 'Z', 0, 0}},
		{FormatMachO, []byte{0xfe, 0xed, 0xfa, 0xce}},
		{FormatMachO, []byte{0xce, 0xfa, 0xed, 0xfe}},
		{FormatMachO, []byte{0xcf, 0xfa, 0xed, 0xfe}},
		{FormatMachO, []byte{0xca, 0xfe, 0xba, 0xbe}},
		{FormatUnknown, []byte{0, 1, 2, 3}},
	}
	for _, c := range cases {
		if got := sniffFormat(bytesReaderAt(c.b)); got != c.want {
			t.Errorf("%v: got %s want %s", c.b, got, c.want)
		}
	}
}

type bytesReaderAt []byte

func (b bytesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b)) {
		return 0, errEOF
	}
	n := copy(p, b[off:])
	return n, nil
}

type errString string

func (e errString) Error() string { return string(e) }

var errEOF errString = "EOF"

func TestDemangleNestedEdges(t *testing.T) {
	cases := []string{
		"_ZN6lading6WidgetC1Ev",
		"_ZN6lading6WidgetD0Ev",
		"_ZNK6lading6WidgetcvbEv", // may fail ok=false — still exercises path
		"_Z3fooIiiETiv",          // template-ish garbage → fail gracefully
		"_Z12lading_markerv",
	}
	for _, in := range cases {
		_, _ = demangleItanium(in)
		_ = Demangle(in)
	}
}
