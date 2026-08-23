//go:build !linux

package unpack

import (
	"fmt"
	"runtime"
)

func unpackArchive(path string, kind Kind) (Result, error) {
	_ = path
	_ = kind
	return Result{}, fmt.Errorf(
		"unpack: on %s, only directories and single binaries are supported; archives and container images require Linux sandboxed unpacking",
		runtime.GOOS,
	)
}

func unpackImageRef(ref string) (Result, error) {
	_ = ref
	return Result{}, fmt.Errorf(
		"unpack: on %s, --image is only supported on Linux with podman or docker",
		runtime.GOOS,
	)
}

func extractSandboxed(archivePath, outDir string) error {
	return ExtractFile(archivePath, outDir)
}
