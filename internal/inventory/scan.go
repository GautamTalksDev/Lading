package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// Scan opens path read-only and returns a deterministic Inventory.
func Scan(path string) (*Inventory, error) {
	return ScanWithOptions(path, Options{})
}

// ScanWithOptions is Scan with explicit Options.
func ScanWithOptions(path string, opts Options) (*Inventory, error) {
	opts = opts.withDefaults()

	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inventory: stat %s: %w", path, err)
	}
	if fi.Size() > opts.MaxSize {
		return nil, &ErrTooLarge{Path: path, Size: fi.Size(), Max: opts.MaxSize}
	}

	// #nosec G304 -- path is the caller-supplied artifact path under analysis
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("inventory: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	sum, err := hashReader(f)
	if err != nil {
		return nil, fmt.Errorf("inventory: hash %s: %w", path, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("inventory: seek %s: %w", path, err)
	}

	inv := &Inventory{
		Path:      path,
		SHA256:    sum,
		Format:    FormatUnknown,
		DynSyms:   []Symbol{},
		SymTab:    []Symbol{},
		Needed:    []string{},
		RoStrings: []string{},
		Warnings:  []Warning{},
	}

	format := sniffFormat(f)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("inventory: seek %s: %w", path, err)
	}

	switch format {
	case FormatELF:
		inv.Format = FormatELF
		scanELF(f, inv, opts)
	case FormatPE:
		inv.Format = FormatPE
		scanPE(f, inv, opts)
	case FormatMachO:
		inv.Format = FormatMachO
		scanMachO(f, inv, opts)
	default:
		inv.Format = FormatUnknown
		inv.Warnings = append(inv.Warnings, Warning{
			Code:    "unknown_format",
			Message: "file magic does not match ELF, PE, or Mach-O",
		})
	}

	finalize(inv)
	return inv, nil
}

func hashReader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sniffFormat(r io.ReaderAt) Format {
	var hdr [4]byte
	if _, err := r.ReadAt(hdr[:], 0); err != nil {
		return FormatUnknown
	}
	switch {
	case hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F':
		return FormatELF
	case hdr[0] == 'M' && hdr[1] == 'Z':
		return FormatPE
	case hdr[0] == 0xfe && hdr[1] == 0xed && hdr[2] == 0xfa && (hdr[3] == 0xce || hdr[3] == 0xcf):
		return FormatMachO
	case hdr[0] == 0xce && hdr[1] == 0xfa && hdr[2] == 0xed && hdr[3] == 0xfe:
		return FormatMachO
	case hdr[0] == 0xcf && hdr[1] == 0xfa && hdr[2] == 0xed && hdr[3] == 0xfe:
		return FormatMachO
	case hdr[0] == 0xca && hdr[1] == 0xfe && hdr[2] == 0xba && hdr[3] == 0xbe:
		return FormatMachO
	default:
		return FormatUnknown
	}
}

func finalize(inv *Inventory) {
	sortSymbols(inv.DynSyms)
	sortSymbols(inv.SymTab)
	sort.Strings(inv.Needed)
	sort.Strings(inv.RoStrings)
	if inv.DynSyms == nil {
		inv.DynSyms = []Symbol{}
	}
	if inv.SymTab == nil {
		inv.SymTab = []Symbol{}
	}
	if inv.Needed == nil {
		inv.Needed = []string{}
	}
	if inv.RoStrings == nil {
		inv.RoStrings = []string{}
	}
	if inv.Warnings == nil {
		inv.Warnings = []Warning{}
	}
}

func sortSymbols(syms []Symbol) {
	sort.Slice(syms, func(i, j int) bool {
		if syms[i].Normalized != syms[j].Normalized {
			return syms[i].Normalized < syms[j].Normalized
		}
		return syms[i].Raw < syms[j].Raw
	})
}

func makeSymbol(rawName, bind, typ string, defined bool, versionHint string) Symbol {
	base, verFromName := splitSymbolVersion(rawName)
	version := verFromName
	if version == "" {
		version = versionHint
	}
	dem := Demangle(base)
	return Symbol{
		Raw:        rawName,
		Demangled:  dem,
		Normalized: Normalize(dem),
		Bind:       bind,
		Type:       typ,
		Defined:    defined,
		Version:    version,
	}
}

func splitSymbolVersion(name string) (base, version string) {
	if i := strings.Index(name, "@@"); i >= 0 {
		return name[:i], name[i+2:]
	}
	if i := strings.Index(name, "@"); i >= 0 {
		return name[:i], name[i+1:]
	}
	return name, ""
}
