//go:build !cgo

package manifestderive

import "fmt"

// EnclosingFunctions requires CGO (tree-sitter). Stub for non-CGO builds.
func EnclosingFunctions(src []byte, lines []int, path, lang string) ([]string, error) {
	return nil, fmt.Errorf("manifestderive: EnclosingFunctions requires CGO (Linux operator builds)")
}
