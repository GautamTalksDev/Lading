package inventory

import (
	"debug/pe"
	"fmt"
	"io"
	"strings"
)

func scanPE(r io.ReaderAt, inv *Inventory, opts Options) {
	f, err := pe.NewFile(r)
	if err != nil {
		inv.Warnings = append(inv.Warnings, Warning{
			Code:    "pe_parse",
			Message: fmt.Sprintf("pe.NewFile: %v", err),
		})
		return
	}
	defer func() { _ = f.Close() }()

	inv.Arch = peArch(f)
	inv.Stripped = len(f.Symbols) == 0

	libs, err := f.ImportedLibraries()
	if err != nil {
		inv.Warnings = append(inv.Warnings, Warning{
			Code:    "pe_imports",
			Message: fmt.Sprintf("ImportedLibraries: %v", err),
		})
	} else {
		inv.Needed = append([]string(nil), libs...)
	}

	imps, err := f.ImportedSymbols()
	if err != nil {
		inv.Warnings = append(inv.Warnings, Warning{
			Code:    "pe_imp_syms",
			Message: fmt.Sprintf("ImportedSymbols: %v", err),
		})
	} else {
		dyn := make([]Symbol, 0, len(imps))
		dlls := map[string]struct{}{}
		for _, name := range imps {
			raw := name
			dll := ""
			if i := strings.LastIndex(name, ":"); i >= 0 {
				raw = name[:i]
				dll = name[i+1:]
			}
			sym := makeSymbol(raw, "GLOBAL", "FUNC", false, "")
			if raw != name {
				sym.Raw = name
			}
			dyn = append(dyn, sym)
			if dll != "" {
				dlls[dll] = struct{}{}
			}
		}
		inv.DynSyms = dyn
		// debug/pe.ImportedLibraries can return empty for some toolchains
		// (notably Go); recover DT-equivalent DLL names from symbol:DLL form.
		if len(inv.Needed) == 0 && len(dlls) > 0 {
			for d := range dlls {
				inv.Needed = append(inv.Needed, d)
			}
		}
	}
	inv.StaticLinked = len(inv.Needed) == 0 && len(inv.DynSyms) == 0

	if len(f.Symbols) > 0 {
		syms := make([]Symbol, 0, len(f.Symbols))
		for _, s := range f.Symbols {
			if s == nil || s.Name == "" {
				continue
			}
			bind := "GLOBAL"
			const imageSymClassStatic = 3 // IMAGE_SYM_CLASS_STATIC (unexported in debug/pe)
			if s.StorageClass == imageSymClassStatic {
				bind = "LOCAL"
			}
			syms = append(syms, makeSymbol(s.Name, bind, "OBJECT", s.SectionNumber > 0, ""))
		}
		inv.SymTab = syms
	}

	inv.RoStrings = extractPERoStrings(f, opts, inv)
}

func peArch(f *pe.File) string {
	return peArchMachine(f.Machine)
}

func peArchMachine(m uint16) string {
	switch m {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "amd64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "386"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	case pe.IMAGE_FILE_MACHINE_ARM, pe.IMAGE_FILE_MACHINE_ARMNT:
		return "arm"
	default:
		return fmt.Sprintf("pe_machine_%d", m)
	}
}

func extractPERoStrings(f *pe.File, opts Options, inv *Inventory) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, sec := range f.Sections {
		name := strings.TrimRight(sec.Name, "\x00")
		if name != ".rdata" && !strings.HasPrefix(name, ".rdata") && name != ".rodata" {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			inv.Warnings = append(inv.Warnings, Warning{
				Code:    "pe_rdata",
				Message: fmt.Sprintf("section %s: %v", name, err),
			})
			continue
		}
		for _, str := range printableStrings(data, opts.MinRoStringLen) {
			if _, ok := seen[str]; ok {
				continue
			}
			seen[str] = struct{}{}
			out = append(out, str)
			if len(out) >= opts.MaxRoStrings {
				inv.Warnings = append(inv.Warnings, Warning{
					Code:    "rostrings_capped",
					Message: fmt.Sprintf("RoStrings capped at %d", opts.MaxRoStrings),
				})
				return out
			}
		}
	}
	return out
}
