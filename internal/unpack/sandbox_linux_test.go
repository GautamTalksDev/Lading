//go:build linux

package unpack

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateImageRef(t *testing.T) {
	t.Parallel()

	digest64 := strings.Repeat("a", 64)
	tests := []struct {
		name    string
		ref     string
		wantErr bool
	}{
		{name: "leading dash", ref: "-evil", wantErr: true},
		{name: "option injection", ref: "--config=/tmp/x", wantErr: true},
		{name: "empty", ref: "", wantErr: true},
		{name: "illegal char", ref: "alpine;rm", wantErr: true},
		{name: "alpine tag", ref: "alpine:3.20", wantErr: false},
		{name: "digest ref", ref: "ghcr.io/x/y@sha256:" + digest64, wantErr: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateImageRef(tc.ref)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				var ire *InvalidImageRefError
				if !errors.As(err, &ire) {
					t.Fatalf("want InvalidImageRefError, got %T: %v", err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateContainerID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cid     string
		wantErr bool
	}{
		{name: "non hex", cid: "zzzzzzzzzzzz", wantErr: true},
		{name: "too short", cid: "abc123", wantErr: true},
		{name: "uppercase", cid: "ABCDEF123456", wantErr: true},
		{name: "valid 12", cid: "0123456789ab", wantErr: false},
		{name: "valid 64", cid: strings.Repeat("0", 64), wantErr: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateContainerID(tc.cid)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				var ice *InvalidContainerIDError
				if !errors.As(err, &ice) {
					t.Fatalf("want InvalidContainerIDError, got %T: %v", err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
