package unpack

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractTar extracts r into destDir enforcing hard limits.
func ExtractTar(r io.Reader, destDir string) error {
	destDir, err := filepath.Abs(destDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(destDir, 0o750); err != nil {
		return err
	}

	tr := tar.NewReader(r)
	var (
		entries      int
		decompressed int64
	)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("unpack: read tar: %w", err)
		}
		entries++
		if entries > MaxEntryCount {
			return &LimitError{Entry: hdr.Name, Reason: fmt.Sprintf("entry count exceeds %d", MaxEntryCount)}
		}

		cleanName, depth, err := validateEntryName(hdr.Name)
		if err != nil {
			return &LimitError{Entry: hdr.Name, Reason: err.Error()}
		}
		if depth > MaxDepth {
			return &LimitError{Entry: hdr.Name, Reason: fmt.Sprintf("depth exceeds %d", MaxDepth)}
		}

		target := filepath.Join(destDir, cleanName)
		if !pathWithinRoot(destDir, target) {
			return &LimitError{Entry: hdr.Name, Reason: "path escapes extraction root"}
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o750); err != nil {
				return err
			}
		case tar.TypeReg:
			if hdr.Size < 0 {
				return &LimitError{Entry: hdr.Name, Reason: "negative file size"}
			}
			decompressed += hdr.Size
			if decompressed > MaxDecompressedSize {
				return &LimitError{Entry: hdr.Name, Reason: fmt.Sprintf("decompressed size exceeds %d bytes", MaxDecompressedSize)}
			}
			if err := writeRegularFile(target, tr, hdr.Size); err != nil {
				if le, ok := err.(*LimitError); ok {
					le.Entry = hdr.Name
					return le
				}
				return err
			}
		case tar.TypeSymlink:
			if err := validateLinkTarget(destDir, target, hdr.Linkname); err != nil {
				return &LimitError{Entry: hdr.Name, Reason: err.Error()}
			}
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		case tar.TypeLink:
			linkTarget, err := resolveHardLinkPath(destDir, hdr.Linkname)
			if err != nil {
				return &LimitError{Entry: hdr.Name, Reason: "hardlink target: " + err.Error()}
			}
			if err := os.Link(linkTarget, target); err != nil {
				return err
			}
		default:
			return &LimitError{Entry: hdr.Name, Reason: fmt.Sprintf("unsupported type flag %c", hdr.Typeflag)}
		}
	}
	return nil
}

// ExtractFile extracts an on-disk archive into destDir.
func ExtractFile(archivePath, destDir string) error {
	r, closeFn, err := OpenArchive(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = closeFn() }()
	return ExtractTar(r, destDir)
}

func validateEntryName(name string) (clean string, depth int, err error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", 0, fmt.Errorf("empty path")
	}
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "\\") {
		return "", 0, fmt.Errorf("absolute path not allowed")
	}
	if strings.HasPrefix(name, "../") || name == ".." || strings.Contains(name, "/../") {
		return "", 0, fmt.Errorf("path traversal not allowed")
	}
	clean = filepath.Clean(filepath.FromSlash(name))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", 0, fmt.Errorf("path traversal not allowed")
	}
	parts := strings.Split(strings.Trim(clean, string(os.PathSeparator)), string(os.PathSeparator))
	depth = len(parts)
	if parts[len(parts)-1] == "" {
		depth--
	}
	return clean, depth, nil
}

func pathWithinRoot(root, target string) bool {
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func validateLinkTarget(root, linkPath, target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("empty symlink target")
	}
	_, err := resolveLinkPath(root, linkPath, target)
	return err
}

func resolveHardLinkPath(root, target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("empty hardlink target")
	}
	if filepath.IsAbs(target) {
		target = strings.TrimPrefix(filepath.Clean(target), string(os.PathSeparator))
	} else {
		target = filepath.FromSlash(target)
	}
	clean, _, err := validateEntryName(target)
	if err != nil {
		return "", err
	}
	resolved := filepath.Join(root, clean)
	if !pathWithinRoot(root, resolved) {
		return "", fmt.Errorf("hardlink target escapes extraction root")
	}
	return resolved, nil
}

func resolveLinkPath(root, linkPath, target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("empty link target")
	}
	// OCI/container exports often use absolute targets (/bin/busybox) for in-root links.
	if filepath.IsAbs(target) {
		target = strings.TrimPrefix(filepath.Clean(target), string(os.PathSeparator))
	} else {
		target = filepath.FromSlash(target)
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(linkPath), target))
	if !pathWithinRoot(root, resolved) {
		return "", fmt.Errorf("link target escapes extraction root")
	}
	return resolved, nil
}

func writeRegularFile(path string, r io.Reader, size int64) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	written, err := io.CopyN(f, r, size)
	if err == io.EOF && written < size {
		return &LimitError{Reason: fmt.Sprintf("short read: expected %d got %d", size, written)}
	}
	if err != nil && err != io.EOF {
		return err
	}
	if written > size {
		return &LimitError{Reason: "tar stream longer than header size"}
	}
	return nil
}
