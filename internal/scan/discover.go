package scan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gautamtalksdev/lading/internal/inventory"
)

// DiscoverBinaries inventories every ELF/PE/Mach-O file under root.
// When singleFile is set, only that path is scanned.
func DiscoverBinaries(root, singleFile string) ([]*inventory.Inventory, error) {
	if singleFile != "" {
		inv, err := inventory.Scan(singleFile)
		if err != nil {
			return nil, err
		}
		if inv.Format == inventory.FormatUnknown {
			return nil, fmt.Errorf("scan: %q is not a recognized binary", singleFile)
		}
		return []*inventory.Inventory{inv}, nil
	}
	var out []*inventory.Inventory
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !looksLikeBinary(path) {
			return nil
		}
		inv, scanErr := inventory.Scan(path)
		if scanErr != nil {
			var tooLarge inventory.ErrTooLarge
			if ok := errorsAsTooLarge(scanErr, &tooLarge); ok {
				return nil
			}
			return scanErr
		}
		if inv.Format == inventory.FormatUnknown {
			return nil
		}
		out = append(out, inv)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("scan: no binaries found under %q", root)
	}
	sortInventories(out)
	return out, nil
}

func looksLikeBinary(path string) bool {
	f, err := os.Open(path) // #nosec G304
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	var hdr [4]byte
	if _, err := f.Read(hdr[:]); err != nil {
		return false
	}
	switch {
	case hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F':
		return true
	case hdr[0] == 'M' && hdr[1] == 'Z':
		return true
	case hdr[0] == 0xfe && hdr[1] == 0xed && hdr[2] == 0xfa:
		return true
	case hdr[0] == 0xce && hdr[1] == 0xfa && hdr[2] == 0xed && hdr[3] == 0xfe:
		return true
	case hdr[0] == 0xcf && hdr[1] == 0xfa && hdr[2] == 0xed && hdr[3] == 0xfe:
		return true
	case hdr[0] == 0xca && hdr[1] == 0xfe && hdr[2] == 0xba && hdr[3] == 0xbe:
		return true
	default:
		return false
	}
}

func sortInventories(invs []*inventory.Inventory) {
	for i := 0; i < len(invs); i++ {
		for j := i + 1; j < len(invs); j++ {
			if strings.ToLower(invs[j].Path) < strings.ToLower(invs[i].Path) {
				invs[i], invs[j] = invs[j], invs[i]
			}
		}
	}
}

func errorsAsTooLarge(err error, target *inventory.ErrTooLarge) bool {
	var tl *inventory.ErrTooLarge
	if errors.As(err, &tl) {
		*target = *tl
		return true
	}
	return false
}
