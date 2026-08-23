package unpack_test

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gautamtalksdev/lading/internal/unpack"
)

func TestExtractTar_RejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	writeTarEntry(t, tw, "../escape.txt", tar.TypeReg, []byte("x"))
	_ = tw.Close()

	err := unpack.ExtractTar(&buf, dir)
	assertLimitError(t, err, "escape.txt")
}

func TestExtractTar_RejectsAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	writeTarEntry(t, tw, "/etc/passwd", tar.TypeReg, []byte("x"))
	_ = tw.Close()

	err := unpack.ExtractTar(&buf, dir)
	assertLimitError(t, err, "/etc/passwd")
}

func TestExtractTar_RejectsSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	writeTarEntry(t, tw, "subdir", tar.TypeDir, nil)
	hdr := &tar.Header{
		Name:     "evil-link",
		Typeflag: tar.TypeSymlink,
		Linkname: "../outside",
		Mode:     0o777,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()

	err := unpack.ExtractTar(&buf, dir)
	assertLimitError(t, err, "evil-link")
}

func TestExtractTar_RejectsEntryCount(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := 0; i < unpack.MaxEntryCount+1; i++ {
		writeTarEntry(t, tw, fmt.Sprintf("files/f%d", i), tar.TypeReg, []byte("x"))
	}
	_ = tw.Close()

	err := unpack.ExtractTar(&buf, dir)
	var le *unpack.LimitError
	if !errors.As(err, &le) {
		t.Fatalf("expected LimitError, got %v", err)
	}
	if !strings.Contains(le.Reason, "entry count") {
		t.Fatalf("unexpected reason: %q", le.Reason)
	}
}

func TestExtractTar_RejectsDecompressedSize(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	big := int64(unpack.MaxDecompressedSize + 1)
	hdr := &tar.Header{
		Name:     "huge.bin",
		Typeflag: tar.TypeReg,
		Size:     big,
		Mode:     0o600,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()

	err := unpack.ExtractTar(&buf, dir)
	var le *unpack.LimitError
	if !errors.As(err, &le) {
		t.Fatalf("expected LimitError, got %v", err)
	}
	if !strings.Contains(le.Reason, "decompressed size") {
		t.Fatalf("unexpected reason: %q", le.Reason)
	}
}

func TestExtractTar_AllowsSafeArchive(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	writeTarEntry(t, tw, "bin/app", tar.TypeReg, []byte("hello"))
	_ = tw.Close()

	if err := unpack.ExtractTar(&buf, dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "bin", "app"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("got %q", data)
	}
}

func writeTarEntry(t *testing.T, tw *tar.Writer, name string, typ byte, body []byte) {
	t.Helper()
	hdr := &tar.Header{
		Name:     name,
		Typeflag: typ,
		Mode:     0o600,
		Size:     int64(len(body)),
	}
	if typ == tar.TypeDir {
		hdr.Size = 0
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if len(body) > 0 {
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
}

func assertLimitError(t *testing.T, err error, wantEntry string) {
	t.Helper()
	var le *unpack.LimitError
	if !errors.As(err, &le) {
		t.Fatalf("expected LimitError, got %v", err)
	}
	if wantEntry != "" && le.Entry != wantEntry && !strings.Contains(le.Entry, wantEntry) {
		t.Fatalf("entry %q, want containing %q", le.Entry, wantEntry)
	}
}
