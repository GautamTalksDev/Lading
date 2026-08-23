package unpack

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Kind classifies an artifact path.
type Kind int

const (
	KindDirectory Kind = iota
	KindBinary
	KindTarArchive
	KindOCIImageTar
)

func (k Kind) String() string {
	switch k {
	case KindDirectory:
		return "directory"
	case KindBinary:
		return "binary"
	case KindTarArchive:
		return "tarball"
	case KindOCIImageTar:
		return "oci-image-tar"
	default:
		return "unknown"
	}
}

// Classify determines how artifact should be handled.
func Classify(path string) (Kind, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if fi.IsDir() {
		return KindDirectory, nil
	}
	kind, err := classifyFile(path)
	if err != nil {
		return 0, err
	}
	return kind, nil
}

func classifyFile(path string) (Kind, error) {
	f, err := os.Open(path) // #nosec G304
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	var hdr [512]byte
	n, err := io.ReadFull(f, hdr[:])
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return 0, err
	}
	data := hdr[:n]

	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		return KindTarArchive, nil
	}
	if isTarHeader(data) {
		if _, err := f.Seek(0, io.SeekStart); err == nil && looksLikeOCILayout(path, f) {
			return KindOCIImageTar, nil
		}
		return KindTarArchive, nil
	}
	if sniffBinary(data) {
		return KindBinary, nil
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".tar", ".tgz", ".tar.gz", ".rootfs":
		return KindTarArchive, nil
	}
	return 0, fmt.Errorf("unpack: unrecognized artifact %q (not directory, binary, or archive)", path)
}

func sniffBinary(hdr []byte) bool {
	if len(hdr) < 4 {
		return false
	}
	r := &byteReaderAt{data: hdr}
	switch inventorySniff(r) {
	case "elf", "pe", "macho":
		return true
	default:
		return false
	}
}

func inventorySniff(r io.ReaderAt) string {
	var hdr [4]byte
	if _, err := r.ReadAt(hdr[:], 0); err != nil {
		return "unknown"
	}
	switch {
	case hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F':
		return "elf"
	case hdr[0] == 'M' && hdr[1] == 'Z':
		return "pe"
	case hdr[0] == 0xfe && hdr[1] == 0xed && hdr[2] == 0xfa:
		return "macho"
	case hdr[0] == 0xce && hdr[1] == 0xfa && hdr[2] == 0xed && hdr[3] == 0xfe:
		return "macho"
	case hdr[0] == 0xcf && hdr[1] == 0xfa && hdr[2] == 0xed && hdr[3] == 0xfe:
		return "macho"
	case hdr[0] == 0xca && hdr[1] == 0xfe && hdr[2] == 0xba && hdr[3] == 0xbe:
		return "macho"
	default:
		return "unknown"
	}
}

type byteReaderAt struct {
	data []byte
}

func (b *byteReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b.data)) {
		return 0, io.EOF
	}
	n := copy(p, b.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func isTarHeader(data []byte) bool {
	if len(data) < 262 {
		return false
	}
	return string(data[257:262]) == "ustar"
}

func looksLikeOCILayout(path string, f *os.File) bool {
	name := strings.ToLower(filepath.Base(path))
	if strings.Contains(name, "oci") || strings.Contains(name, "image") {
		return true
	}
	tr := tar.NewReader(f)
	for i := 0; i < 32; i++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false
		}
		base := filepath.Base(h.Name)
		if base == "oci-layout" || base == "manifest.json" || strings.HasSuffix(h.Name, "manifest.json") {
			return true
		}
	}
	return false
}

// OpenArchive returns a reader for plain or gzip-compressed tar bytes.
// ExtractTar wraps the stream with archive/tar; do not pre-wrap here.
func OpenArchive(path string) (io.Reader, func() error, error) {
	f, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, nil, err
	}
	var hdr [2]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if hdr[0] == 0x1f && hdr[1] == 0x8b {
		gz, err := gzip.NewReader(f)
		if err != nil {
			_ = f.Close()
			return nil, nil, err
		}
		return gz, func() error {
			_ = gz.Close()
			return f.Close()
		}, nil
	}
	return f, func() error { return f.Close() }, nil
}
