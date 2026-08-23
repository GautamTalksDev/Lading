package inventory

import (
	"debug/macho"
	"fmt"
	"io"
)

func scanMachO(r io.ReaderAt, inv *Inventory, opts Options) {
	if fat, err := macho.NewFatFile(r); err == nil {
		defer func() { _ = fat.Close() }()
		if len(fat.Arches) == 0 {
			inv.Warnings = append(inv.Warnings, Warning{
				Code:    "macho_fat_empty",
				Message: "fat Mach-O contains no architectures",
			})
			return
		}
		inv.Warnings = append(inv.Warnings, Warning{
			Code:    "macho_fat",
			Message: fmt.Sprintf("fat Mach-O: inventorying first arch of %d", len(fat.Arches)),
		})
		scanMachOFile(fat.Arches[0].File, inv, opts)
		return
	}

	f, err := macho.NewFile(r)
	if err != nil {
		inv.Warnings = append(inv.Warnings, Warning{
			Code:    "macho_parse",
			Message: fmt.Sprintf("macho.NewFile: %v", err),
		})
		return
	}
	defer func() { _ = f.Close() }()
	scanMachOFile(f, inv, opts)
}

func scanMachOFile(f *macho.File, inv *Inventory, opts Options) {
	inv.Arch = machoArch(f.Cpu)
	inv.Stripped = f.Symtab == nil || len(f.Symtab.Syms) == 0

	libs, err := f.ImportedLibraries()
	if err != nil {
		inv.Warnings = append(inv.Warnings, Warning{
			Code:    "macho_libs",
			Message: fmt.Sprintf("ImportedLibraries: %v", err),
		})
	} else {
		inv.Needed = append([]string(nil), libs...)
	}
	inv.StaticLinked = len(inv.Needed) == 0

	if f.Symtab != nil {
		syms := make([]Symbol, 0, len(f.Symtab.Syms))
		var dyn []Symbol
		for _, s := range f.Symtab.Syms {
			if s.Name == "" {
				continue
			}
			// Mach-O nlist type bits (not exported by debug/macho).
			const (
				nExt  = 0x01
				nType = 0x0e
				nUndf = 0x0
				nSect = 0xe
			)
			bind := "GLOBAL"
			if s.Type&nExt == 0 {
				bind = "LOCAL"
			}
			typ := "NOTYPE"
			ntype := s.Type & nType
			defined := ntype != nUndf
			if ntype == nSect {
				typ = "FUNC"
			}
			sym := makeSymbol(s.Name, bind, typ, defined, "")
			syms = append(syms, sym)
			if !defined {
				dyn = append(dyn, sym)
			}
		}
		inv.SymTab = syms
		inv.DynSyms = dyn
	}

	inv.RoStrings = extractMachORoStrings(f, opts, inv)
}

func machoArch(cpu macho.Cpu) string {
	switch cpu {
	case macho.CpuAmd64:
		return "amd64"
	case macho.Cpu386:
		return "386"
	case macho.CpuArm64:
		return "arm64"
	case macho.CpuArm:
		return "arm"
	default:
		return cpu.String()
	}
}

func extractMachORoStrings(f *macho.File, opts Options, inv *Inventory) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, sec := range f.Sections {
		if sec.Seg != "__TEXT" {
			continue
		}
		// Go emits read-only strings in __rodata; clang uses __cstring / __const.
		switch sec.Name {
		case "__cstring", "__const", "__rodata":
		default:
			continue
		}
		data, err := sec.Data()
		if err != nil {
			inv.Warnings = append(inv.Warnings, Warning{
				Code:    "macho_cstring",
				Message: fmt.Sprintf("%s,%s: %v", sec.Seg, sec.Name, err),
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
