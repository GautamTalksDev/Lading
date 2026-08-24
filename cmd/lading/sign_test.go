package main

import (
	"errors"
	"testing"
)

func TestValidateSignArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		key     string
		output  string
		wantArg string // empty ⇒ accept
	}{
		{name: "path leading dash", path: "-evil", key: "cosign.key", output: "out.sig", wantArg: "path"},
		{name: "path double dash", path: "--help", key: "cosign.key", output: "out.sig", wantArg: "path"},
		{name: "key leading dash", path: "blob.json", key: "-k", output: "out.sig", wantArg: "key"},
		{name: "output leading dash", path: "blob.json", key: "cosign.key", output: "--output=/tmp/x", wantArg: "output"},
		{name: "ordinary paths", path: "vex.openvex.json", key: "cosign.key", output: "vex.openvex.json.sig", wantArg: ""},
		{name: "empty key ok", path: "blob.json", key: "", output: "blob.json.sig", wantArg: ""},
		{name: "relative path", path: "./out/vex.cdx.json", key: "keys/cosign.key", output: "./out/vex.cdx.json.sig", wantArg: ""},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateSignArgs(tc.path, tc.key, tc.output)
			if tc.wantArg == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			var se *SignArgError
			if !errors.As(err, &se) {
				t.Fatalf("want SignArgError, got %T: %v", err, err)
			}
			if se.Arg != tc.wantArg {
				t.Fatalf("arg=%q want %q", se.Arg, tc.wantArg)
			}
		})
	}
}

func TestSignFile_RejectsLeadingDash(t *testing.T) {
	t.Parallel()
	err := signFile("-x", false, "cosign.key", "")
	var se *SignArgError
	if !errors.As(err, &se) {
		t.Fatalf("want SignArgError, got %v", err)
	}
	if se.Arg != "path" {
		t.Fatalf("arg=%q want path", se.Arg)
	}
}
