package inventory

import (
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

func scanELF(r io.ReaderAt, inv *Inventory, opts Options) {
	f, err := elf.NewFile(r)
	if err != nil {
		inv.Warnings = append(inv.Warnings, Warning{
			Code:    "elf_parse",
			Message: fmt.Sprintf("elf.NewFile: %v", err),
		})
		return
	}
	defer func() { _ = f.Close() }()

	inv.Arch = elfArch(f.Machine)
	inv.BuildID = elfBuildID(f, inv)
	inv.Stripped = f.Section(".symtab") == nil

	needed, err := f.ImportedLibraries()
	if err != nil {
		inv.Warnings = append(inv.Warnings, Warning{
			Code:    "elf_needed",
			Message: fmt.Sprintf("ImportedLibraries: %v", err),
		})
	} else {
		inv.Needed = append([]string(nil), needed...)
	}

	hasInterp := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			hasInterp = true
			break
		}
	}
	// Explicit fact: static means no PT_INTERP and no DT_NEEDED.
	inv.StaticLinked = !hasInterp && len(inv.Needed) == 0

	versions := readGNUVersions(f, inv)

	if dyn, err := f.DynamicSymbols(); err != nil {
		if err != elf.ErrNoSymbols {
			inv.Warnings = append(inv.Warnings, Warning{
				Code:    "elf_dynsym",
				Message: fmt.Sprintf("DynamicSymbols: %v", err),
			})
		}
	} else {
		inv.DynSyms = convertELFSymbols(dyn, versions)
	}

	if syms, err := f.Symbols(); err != nil {
		if err != elf.ErrNoSymbols {
			inv.Warnings = append(inv.Warnings, Warning{
				Code:    "elf_symtab",
				Message: fmt.Sprintf("Symbols: %v", err),
			})
		}
	} else {
		inv.SymTab = convertELFSymbols(syms, nil)
	}

	inv.RoStrings = extractELFRoStrings(f, opts, inv)
}

func elfArch(m elf.Machine) string {
	switch m {
	case elf.EM_X86_64:
		return "amd64"
	case elf.EM_386:
		return "386"
	case elf.EM_AARCH64:
		return "arm64"
	case elf.EM_ARM:
		return "arm"
	case elf.EM_PPC64:
		return "ppc64"
	case elf.EM_S390:
		return "s390x"
	case elf.EM_RISCV:
		return "riscv"
	default:
		return m.String()
	}
}

func elfBuildID(f *elf.File, inv *Inventory) string {
	sec := f.Section(".note.gnu.build-id")
	if sec == nil {
		return ""
	}
	data, err := sec.Data()
	if err != nil {
		inv.Warnings = append(inv.Warnings, Warning{
			Code:    "elf_buildid",
			Message: fmt.Sprintf(".note.gnu.build-id: %v", err),
		})
		return ""
	}
	return parseGNUBuildID(data)
}

func parseGNUBuildID(data []byte) string {
	if len(data) < 12 {
		return ""
	}
	namesz := binary.LittleEndian.Uint32(data[0:4])
	descsz := binary.LittleEndian.Uint32(data[4:8])
	noteType := binary.LittleEndian.Uint32(data[8:12])
	if noteType != 3 { // NT_GNU_BUILD_ID
		return ""
	}
	nameEnd := 12 + int((namesz+3)&^3)
	descEnd := nameEnd + int(descsz)
	if descEnd > len(data) || descsz == 0 {
		return ""
	}
	return hex.EncodeToString(data[nameEnd:descEnd])
}

func convertELFSymbols(syms []elf.Symbol, versions map[int]string) []Symbol {
	out := make([]Symbol, 0, len(syms))
	for i, s := range syms {
		if s.Name == "" {
			continue
		}
		bind, typ := elfBindType(s.Info)
		hint := ""
		if versions != nil {
			// DynamicSymbols omits the null symbol; versym index is i+1.
			hint = versions[i+1]
		}
		out = append(out, makeSymbol(s.Name, bind, typ, s.Section != elf.SHN_UNDEF, hint))
	}
	return out
}

func elfBindType(info uint8) (bind, typ string) {
	switch elf.ST_BIND(info) {
	case elf.STB_LOCAL:
		bind = "LOCAL"
	case elf.STB_GLOBAL:
		bind = "GLOBAL"
	case elf.STB_WEAK:
		bind = "WEAK"
	default:
		bind = fmt.Sprintf("BIND_%d", int(elf.ST_BIND(info)))
	}
	st := elf.ST_TYPE(info)
	switch st {
	case elf.STT_NOTYPE:
		typ = "NOTYPE"
	case elf.STT_OBJECT:
		typ = "OBJECT"
	case elf.STT_FUNC:
		typ = "FUNC"
	case elf.STT_SECTION:
		typ = "SECTION"
	case elf.STT_FILE:
		typ = "FILE"
	case elf.STT_COMMON:
		typ = "COMMON"
	case elf.STT_TLS:
		typ = "TLS"
	default:
		if st == 10 { // STT_GNU_IFUNC
			typ = "IFUNC"
		} else {
			typ = fmt.Sprintf("TYPE_%d", int(st))
		}
	}
	return bind, typ
}

func readGNUVersions(f *elf.File, inv *Inventory) map[int]string {
	out := map[int]string{}
	versym := f.Section(".gnu.version")
	if versym == nil {
		return out
	}
	data, err := versym.Data()
	if err != nil {
		inv.Warnings = append(inv.Warnings, Warning{
			Code:    "elf_versym",
			Message: fmt.Sprintf(".gnu.version: %v", err),
		})
		return out
	}
	vernames := map[uint16]string{}
	parseVerneed(f, vernames, inv)
	parseVerdef(f, vernames, inv)
	for i := 0; i+1 < len(data); i += 2 {
		idx := binary.LittleEndian.Uint16(data[i : i+2])
		v := idx & 0x7fff
		if v < 2 {
			continue
		}
		if name, ok := vernames[v]; ok {
			out[i/2] = name
		}
	}
	return out
}

func parseVerneed(f *elf.File, vernames map[uint16]string, inv *Inventory) {
	sec := f.Section(".gnu.version_r")
	if sec == nil {
		return
	}
	data, err := sec.Data()
	if err != nil {
		inv.Warnings = append(inv.Warnings, Warning{
			Code:    "elf_verneed",
			Message: fmt.Sprintf(".gnu.version_r: %v", err),
		})
		return
	}
	strdata := sectionData(f, ".dynstr")
	if strdata == nil {
		return
	}
	off := 0
	for off+16 <= len(data) {
		cnt := binary.LittleEndian.Uint16(data[off+2:])
		aux := binary.LittleEndian.Uint32(data[off+8:])
		next := binary.LittleEndian.Uint32(data[off+12:])
		aoff := off + int(aux)
		for i := 0; i < int(cnt) && aoff+16 <= len(data); i++ {
			other := binary.LittleEndian.Uint16(data[aoff+6:])
			nameOff := binary.LittleEndian.Uint32(data[aoff+8:])
			nextAux := binary.LittleEndian.Uint32(data[aoff+12:])
			if int(nameOff) < len(strdata) {
				vernames[other] = cstringAt(strdata, int(nameOff))
			}
			if nextAux == 0 {
				break
			}
			aoff += int(nextAux)
		}
		if next == 0 {
			break
		}
		off += int(next)
	}
}

func parseVerdef(f *elf.File, vernames map[uint16]string, inv *Inventory) {
	sec := f.Section(".gnu.version_d")
	if sec == nil {
		return
	}
	data, err := sec.Data()
	if err != nil {
		inv.Warnings = append(inv.Warnings, Warning{
			Code:    "elf_verdef",
			Message: fmt.Sprintf(".gnu.version_d: %v", err),
		})
		return
	}
	strdata := sectionData(f, ".dynstr")
	if strdata == nil {
		return
	}
	off := 0
	for off+20 <= len(data) {
		ndx := binary.LittleEndian.Uint16(data[off+4:])
		cnt := binary.LittleEndian.Uint16(data[off+6:])
		aux := binary.LittleEndian.Uint32(data[off+12:])
		next := binary.LittleEndian.Uint32(data[off+16:])
		aoff := off + int(aux)
		if cnt > 0 && aoff+8 <= len(data) {
			nameOff := binary.LittleEndian.Uint32(data[aoff:])
			if int(nameOff) < len(strdata) {
				vernames[ndx] = cstringAt(strdata, int(nameOff))
			}
		}
		if next == 0 {
			break
		}
		off += int(next)
	}
}

func sectionData(f *elf.File, name string) []byte {
	sec := f.Section(name)
	if sec == nil {
		return nil
	}
	data, err := sec.Data()
	if err != nil {
		return nil
	}
	return data
}

func cstringAt(b []byte, off int) string {
	if off < 0 || off >= len(b) {
		return ""
	}
	end := off
	for end < len(b) && b[end] != 0 {
		end++
	}
	return string(b[off:end])
}

func extractELFRoStrings(f *elf.File, opts Options, inv *Inventory) []string {
	var sections []*elf.Section
	seenSec := map[*elf.Section]struct{}{}
	add := func(s *elf.Section) {
		if s == nil {
			return
		}
		if _, ok := seenSec[s]; ok {
			return
		}
		seenSec[s] = struct{}{}
		sections = append(sections, s)
	}
	for _, name := range []string{".rodata", ".rodata.str1.1", ".rodata.str1.4", ".rodata.str1.8"} {
		add(f.Section(name))
	}
	for _, s := range f.Sections {
		if s != nil && strings.HasPrefix(s.Name, ".rodata") && s.Type == elf.SHT_PROGBITS {
			add(s)
		}
	}

	var out []string
	seen := map[string]struct{}{}
	for _, s := range sections {
		data, err := s.Data()
		if err != nil {
			inv.Warnings = append(inv.Warnings, Warning{
				Code:    "elf_rodata",
				Message: fmt.Sprintf("section %s: %v", s.Name, err),
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
