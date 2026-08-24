package unpack

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
)

func TestWriteRegularFile_RejectsPathOutsideRoot(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outside := filepath.Join(filepath.Dir(root), "escape-outside-root.txt")
	err := writeRegularFile(root, outside, bytes.NewReader([]byte("x")), 1)
	if err == nil {
		t.Fatal("expected rejection for path outside root")
	}
	var pe *PathEscapeError
	if !errors.As(err, &pe) {
		t.Fatalf("want PathEscapeError, got %T: %v", err, err)
	}
	if pe.Path != outside {
		t.Fatalf("Path=%q want %q", pe.Path, outside)
	}
}
