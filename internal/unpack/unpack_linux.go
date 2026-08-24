//go:build linux

package unpack

import "os"

func unpackArchive(path string, kind Kind) (Result, error) {
	out, err := os.MkdirTemp("", "lading-unpack-*")
	if err != nil {
		return Result{}, err
	}
	cleanup := func() { _ = os.RemoveAll(out) }
	if err := extractSandboxed(path, out); err != nil {
		cleanup()
		return Result{}, err
	}
	desc := kind.String()
	return Result{Root: out, Cleanup: cleanup, Description: desc + " (sandboxed)"}, nil
}
