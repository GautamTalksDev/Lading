package evidencehtml_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/gautamtalksdev/lading/internal/evidencehtml"
)

func TestRenderDeterministic(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "evidence-pack")
	opts := evidencehtml.Options{
		ArtifactPath: filepath.ToSlash(filepath.Join(root, "artifact")),
		ScanDir:      filepath.ToSlash(filepath.Join(root, "scan")),
		Timestamp:    "2026-08-24T00:00:00Z",
	}

	pack, err := evidencehtml.Load(opts)
	if err != nil {
		t.Fatal(err)
	}

	a := evidencehtml.Render(pack)
	b := evidencehtml.Render(pack)
	if !bytes.Equal(a, b) {
		t.Fatalf("Render not deterministic: %d vs %d bytes", len(a), len(b))
	}

	pack2, err := evidencehtml.Load(opts)
	if err != nil {
		t.Fatal(err)
	}
	c := evidencehtml.Render(pack2)
	if !bytes.Equal(a, c) {
		t.Fatal("Load+Render not deterministic across two loads")
	}
}

func TestSignDetachedDeterministic(t *testing.T) {
	keyPEM, err := os.ReadFile(filepath.Join("..", "..", "testdata", "evidence-pack", "test-sign.key"))
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("deterministic-html-fixture")
	sig1, err := evidencehtml.SignDetached(content, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := evidencehtml.SignDetached(content, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Fatal("SignDetached not deterministic")
	}
}
