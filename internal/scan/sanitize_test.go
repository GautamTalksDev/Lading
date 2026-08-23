package scan_test

import (
	"strings"
	"testing"

	"github.com/gautamtalksdev/lading/internal/scan"
)

func TestSanitizeForTerminal_StripsANSI(t *testing.T) {
	in := "hello \x1b[31mRED\x1b[0m world"
	got := scan.SanitizeForTerminal(in)
	if strings.Contains(got, "\x1b") {
		t.Fatalf("ANSI not stripped: %q", got)
	}
	if !strings.Contains(got, "hello") || !strings.Contains(got, "world") {
		t.Fatalf("unexpected: %q", got)
	}
}

func TestSanitizeForTerminal_StripsBidiOverrides(t *testing.T) {
	in := "safe\u202efaked\u202csafe"
	got := scan.SanitizeForTerminal(in)
	if strings.ContainsRune(got, '\u202e') {
		t.Fatalf("bidi override not stripped: %q", got)
	}
	if got != "safefakedsafe" {
		t.Fatalf("got %q", got)
	}
}

func TestSanitizeForTerminal_StripsControlChars(t *testing.T) {
	in := "ok\x07bad"
	got := scan.SanitizeForTerminal(in)
	if got != "okbad" {
		t.Fatalf("got %q", got)
	}
}
