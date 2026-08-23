package inventory_test

import (
	"testing"

	"github.com/gautamtalksdev/lading/internal/inventory"
)

func TestPackagePresent(t *testing.T) {
	// Trivial smoke test so CI always has a package under test.
	_ = inventory.Placeholder
}
