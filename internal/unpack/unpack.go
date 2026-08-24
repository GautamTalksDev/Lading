// Package unpack provides sandboxed artifact unpacking.
//
// On Linux, archives and container images extract inside a podman/docker
// sandbox (no network, memory cap, read-only rootfs) with unshare fallback.
// On other platforms only directories and single binaries are accepted.
package unpack

import (
	"fmt"
	"path/filepath"
)

// Options configures unpacking.
type Options struct {
	// ImageRef pulls an OCI image via podman/docker before sandboxed export (Linux only).
	ImageRef string
}

// Result is a scan-ready directory tree.
type Result struct {
	Root        string
	Cleanup     func()
	SingleFile  string // set when artifact is one binary (Root is its directory)
	Description string
}

// Unpack prepares artifact for scanning.
func Unpack(artifact string, opts Options) (Result, error) {
	if opts.ImageRef != "" {
		return unpackImageRef(opts.ImageRef)
	}
	if artifact == "" {
		return Result{}, fmt.Errorf("unpack: artifact path required")
	}
	abs, err := filepath.Abs(artifact)
	if err != nil {
		return Result{}, err
	}
	kind, err := Classify(abs)
	if err != nil {
		return Result{}, err
	}
	switch kind {
	case KindDirectory:
		return Result{
			Root:        abs,
			Cleanup:     func() {},
			Description: "directory",
		}, nil
	case KindBinary:
		return Result{
			Root:        filepath.Dir(abs),
			SingleFile:  abs,
			Cleanup:     func() {},
			Description: "binary",
		}, nil
	case KindTarArchive, KindOCIImageTar:
		return unpackArchive(abs, kind)
	default:
		return Result{}, fmt.Errorf("unpack: unsupported artifact kind %v", kind)
	}
}

// ExtractInput extracts archivePath into outputDir (used by sandbox child).
func ExtractInput(archivePath, outputDir string) error {
	return ExtractFile(archivePath, outputDir)
}
