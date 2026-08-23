//go:build linux

package unpack

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	sandboxMemory = "2g"
	sandboxWall   = 300 * time.Second
	sandboxImage  = "docker.io/library/debian:bookworm-slim"
)

func extractSandboxed(archivePath, outDir string) error {
	if os.Getenv("_LADING_UNPACK_CHILD") == "1" {
		return ExtractFile(archivePath, outDir)
	}
	if rt, err := containerRuntime(); err == nil {
		if err := runPodmanExtract(rt, archivePath, outDir); err == nil {
			return nil
		}
	}
	return runUnshareExtract(archivePath, outDir)
}

func unpackImageRef(ref string) (Result, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return Result{}, fmt.Errorf("unpack: empty image ref")
	}
	rt, err := containerRuntime()
	if err != nil {
		return Result{}, err
	}
	tmpTar, err := os.CreateTemp("", "lading-image-*.tar")
	if err != nil {
		return Result{}, err
	}
	tmpPath := tmpTar.Name()
	_ = tmpTar.Close()

	pull := exec.Command(rt, "pull", ref)
	pull.Stdout = os.Stderr
	pull.Stderr = os.Stderr
	if err := pull.Run(); err != nil {
		_ = os.Remove(tmpPath)
		return Result{}, fmt.Errorf("unpack: pull %q: %w", ref, err)
	}
	create := exec.Command(rt, "create", ref)
	out, err := create.Output()
	if err != nil {
		_ = os.Remove(tmpPath)
		return Result{}, fmt.Errorf("unpack: create container: %w", err)
	}
	cid := strings.TrimSpace(string(out))
	defer func() { _ = exec.Command(rt, "rm", cid).Run() }()

	export := exec.Command(rt, "export", cid, "-o", tmpPath)
	export.Stdout = os.Stderr
	export.Stderr = os.Stderr
	if err := export.Run(); err != nil {
		_ = os.Remove(tmpPath)
		return Result{}, fmt.Errorf("unpack: export image: %w", err)
	}

	outDir, err := os.MkdirTemp("", "lading-unpack-*")
	if err != nil {
		_ = os.Remove(tmpPath)
		return Result{}, err
	}
	cleanup := func() {
		_ = os.RemoveAll(outDir)
		_ = os.Remove(tmpPath)
	}
	if err := extractSandboxed(tmpPath, outDir); err != nil {
		cleanup()
		return Result{}, err
	}
	return Result{
		Root:        outDir,
		Cleanup:     cleanup,
		Description: "oci-image (sandboxed)",
	}, nil
}

func runPodmanExtract(rt, archivePath, outDir string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	absIn, err := filepath.Abs(archivePath)
	if err != nil {
		return err
	}
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return err
	}
	absExe, err := filepath.Abs(exe)
	if err != nil {
		return err
	}

	args := []string{
		"run", "--rm",
		"--network=none",
		"--memory", sandboxMemory,
		"--pids-limit", "512",
		"--security-opt", "no-new-privileges",
		"--read-only",
		"--tmpfs", "/tmp:rw,size=10g,mode=1777",
		"-v", absIn + ":/input:ro",
		"-v", absOut + ":/output:rw",
		"-v", absExe + ":/lading:ro",
		"-e", "_LADING_UNPACK_CHILD=1",
		sandboxImage,
		"/lading", "__unpack-internal",
		"--input", "/input",
		"--output", "/output",
	}
	ctx, cancel := context.WithTimeout(context.Background(), sandboxWall)
	defer cancel()
	cmd := exec.CommandContext(ctx, rt, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("unpack: sandbox timed out after %s", sandboxWall)
		}
		return fmt.Errorf("unpack: sandbox extract: %w", err)
	}
	return nil
}

func runUnshareExtract(archivePath, outDir string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		return fmt.Errorf("unpack: podman/docker or unshare required for sandboxed unpacking")
	}
	ctx, cancel := context.WithTimeout(context.Background(), sandboxWall)
	defer cancel()

	inner := []string{
		exe, "__unpack-internal",
		"--input", archivePath,
		"--output", outDir,
	}
	var cmd *exec.Cmd
	if prlimit, err := exec.LookPath("prlimit"); err == nil {
		args := append([]string{"--as=2147483648", "--", "unshare", "-rn", "--map-root-user"}, inner...)
		cmd = exec.CommandContext(ctx, prlimit, args...)
	} else {
		cmd = exec.CommandContext(ctx, "unshare", append([]string{"-rn", "--map-root-user"}, inner...)...)
	}
	cmd.Env = append(os.Environ(), "_LADING_UNPACK_CHILD=1")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("unpack: sandbox timed out after %s", sandboxWall)
		}
		return fmt.Errorf("unpack: unshare extract: %w", err)
	}
	return nil
}

func containerRuntime() (string, error) {
	for _, rt := range []string{"podman", "docker"} {
		if _, err := exec.LookPath(rt); err == nil {
			return rt, nil
		}
	}
	return "", fmt.Errorf("unpack: podman or docker required for sandboxed unpacking on Linux")
}
