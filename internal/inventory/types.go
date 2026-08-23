// Package inventory builds a deterministic factual record of what is
// observably present in a binary artifact.
//
// Scan performs only read-only local I/O. No network. No subprocesses.
// Downstream packages must never infer Stripped or StaticLinked — those
// fields are authoritative facts recorded here.
package inventory

import (
	"encoding/json"
	"fmt"
)

// Format identifies the container format of an artifact.
type Format string

const (
	FormatELF     Format = "ELF"
	FormatPE      Format = "PE"
	FormatMachO   Format = "MachO"
	FormatUnknown Format = "Unknown"
)

// DefaultMaxSize is the default maximum artifact size Scan will accept (512 MiB).
const DefaultMaxSize = 512 << 20

// DefaultMaxRoStrings caps how many read-only printable strings are retained.
const DefaultMaxRoStrings = 10000

// DefaultMinRoStringLen is the minimum printable length for RoStrings.
const DefaultMinRoStringLen = 6

// Options configures Scan behaviour.
type Options struct {
	MaxSize        int64 // Zero → DefaultMaxSize
	MaxRoStrings   int   // Zero → DefaultMaxRoStrings
	MinRoStringLen int   // Zero → DefaultMinRoStringLen
}

func (o Options) withDefaults() Options {
	if o.MaxSize <= 0 {
		o.MaxSize = DefaultMaxSize
	}
	if o.MaxRoStrings <= 0 {
		o.MaxRoStrings = DefaultMaxRoStrings
	}
	if o.MinRoStringLen <= 0 {
		o.MinRoStringLen = DefaultMinRoStringLen
	}
	return o
}

// Inventory is a complete factual record of one scanned artifact.
type Inventory struct {
	Path         string    `json:"path"`
	SHA256       string    `json:"sha256"`
	Format       Format    `json:"format"`
	Arch         string    `json:"arch"`
	BuildID      string    `json:"build_id,omitempty"`
	DynSyms      []Symbol  `json:"dyn_syms"`
	SymTab       []Symbol  `json:"symtab"`
	Needed       []string  `json:"needed"`
	RoStrings    []string  `json:"ro_strings"`
	Warnings     []Warning `json:"warnings"`
	Stripped     bool      `json:"stripped"`
	StaticLinked bool      `json:"static_linked"`
}

// Symbol is one symbol-table entry.
type Symbol struct {
	Raw        string `json:"raw"`
	Demangled  string `json:"demangled"`
	Normalized string `json:"normalized"`
	Bind       string `json:"bind"`
	Type       string `json:"type"`
	Version    string `json:"version,omitempty"`
	Defined    bool   `json:"defined"`
}

// Warning records a non-fatal parse anomaly.
type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ErrTooLarge is returned when an artifact exceeds the configured size cap.
type ErrTooLarge struct {
	Path string
	Size int64
	Max  int64
}

func (e *ErrTooLarge) Error() string {
	return fmt.Sprintf("inventory: %s: size %d exceeds cap %d", e.Path, e.Size, e.Max)
}

// Serialize returns a deterministic JSON encoding of inv.
func Serialize(inv *Inventory) ([]byte, error) {
	if inv == nil {
		return nil, fmt.Errorf("inventory: Serialize nil")
	}
	return json.Marshal(inv)
}
