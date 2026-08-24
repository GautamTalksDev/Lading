//go:build linux

package unpack

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	if err := validateImageRef(ref); err != nil {
		return Result{}, err
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

	//nolint:gosec // G204: rt allowlisted to podman/docker in containerRuntime(); ref validated by validateImageRef
	pull := exec.Command(rt, "pull", "--", ref)
	pull.Stdout = os.Stderr
	pull.Stderr = os.Stderr
	if pullErr := pull.Run(); pullErr != nil {
		_ = os.Remove(tmpPath)
		return Result{}, fmt.Errorf("unpack: pull %q: %w", ref, pullErr)
	}
	//nolint:gosec // G204: rt allowlisted to podman/docker in containerRuntime(); ref validated by validateImageRef
	create := exec.Command(rt, "create", "--", ref)
	out, err := create.Output()
	if err != nil {
		_ = os.Remove(tmpPath)
		return Result{}, fmt.Errorf("unpack: create container: %w", err)
	}
	cid := strings.TrimSpace(string(out))
	if cidErr := validateContainerID(cid); cidErr != nil {
		_ = os.Remove(tmpPath)
		return Result{}, cidErr
	}
	//nolint:gosec // G204: rt allowlisted to podman/docker in containerRuntime(); cid validated by validateContainerID
	defer func() { _ = exec.Command(rt, "rm", "--", cid).Run() }()

	//nolint:gosec // G204: rt allowlisted to podman/docker in containerRuntime(); cid validated by validateContainerID; tmpPath is CreateTemp
	export := exec.Command(rt, "export", "-o", tmpPath, "--", cid)
	export.Stdout = os.Stderr
	export.Stderr = os.Stderr
	if exportErr := export.Run(); exportErr != nil {
		_ = os.Remove(tmpPath)
		return Result{}, fmt.Errorf("unpack: export image: %w", exportErr)
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
		// absIn/absOut are Abs of CreateTemp/MkdirTemp paths — cannot begin with '-'.
		"-v", absIn + ":/input:ro",
		"-v", absOut + ":/output:rw",
		"-v", absExe + ":/lading:ro",
		"-e", "_LADING_UNPACK_CHILD=1",
		sandboxImage, // constant
		"/lading", "__unpack-internal",
		"--input", "/input",
		"--output", "/output",
	}
	ctx, cancel := context.WithTimeout(context.Background(), sandboxWall)
	defer cancel()
	//nolint:gosec // G204: rt allowlisted to podman/docker in containerRuntime(); sandboxImage is a const; volume paths are Abs of CreateTemp/MkdirTemp
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
		// archivePath/outDir are CreateTemp/MkdirTemp values in flag-argument position after --input/--output.
		"--input", archivePath,
		"--output", outDir,
	}
	var cmd *exec.Cmd
	if prlimit, err := exec.LookPath("prlimit"); err == nil {
		args := append([]string{"--as=2147483648", "--", "unshare", "-rn", "--map-root-user"}, inner...)
		//nolint:gosec // G204: prlimit from LookPath("prlimit"); unshare args after --; archivePath/outDir are CreateTemp/MkdirTemp in flag-argument position
		cmd = exec.CommandContext(ctx, prlimit, args...)
	} else {
		//nolint:gosec // G204: unshare is a literal; LookPath verified earlier; archivePath/outDir are CreateTemp/MkdirTemp in flag-argument position
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

// InvalidImageRefError is returned when an OCI image reference fails validation.
type InvalidImageRefError struct {
	Ref    string
	Reason string
}

func (e *InvalidImageRefError) Error() string {
	if e.Ref == "" {
		return fmt.Sprintf("unpack: invalid image ref: %s", e.Reason)
	}
	return fmt.Sprintf("unpack: invalid image ref %q: %s", e.Ref, e.Reason)
}

// InvalidContainerIDError is returned when a container ID fails validation.
type InvalidContainerIDError struct {
	ID     string
	Reason string
}

func (e *InvalidContainerIDError) Error() string {
	if e.ID == "" {
		return fmt.Sprintf("unpack: invalid container id: %s", e.Reason)
	}
	return fmt.Sprintf("unpack: invalid container id %q: %s", e.ID, e.Reason)
}

var (
	imageRefAllowed = regexp.MustCompile(`^[a-zA-Z0-9._/:@-]+$`)
	containerIDRe   = regexp.MustCompile(`^[0-9a-f]{12,64}$`)
)

func validateImageRef(ref string) error {
	if ref == "" {
		return &InvalidImageRefError{Reason: "empty"}
	}
	if strings.HasPrefix(ref, "--") {
		return &InvalidImageRefError{Ref: ref, Reason: "must not begin with --"}
	}
	if strings.HasPrefix(ref, "-") {
		return &InvalidImageRefError{Ref: ref, Reason: "must not begin with -"}
	}
	if !imageRefAllowed.MatchString(ref) {
		return &InvalidImageRefError{Ref: ref, Reason: "contains characters outside OCI grammar [a-zA-Z0-9._/:@-]"}
	}
	return nil
}

func validateContainerID(cid string) error {
	if cid == "" {
		return &InvalidContainerIDError{Reason: "empty"}
	}
	if !containerIDRe.MatchString(cid) {
		return &InvalidContainerIDError{ID: cid, Reason: "must be 12-64 lowercase hex characters"}
	}
	return nil
}
