package evidencehtml_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
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
	// Fixture key is PKCS#8 Ed25519 PEM ("BEGIN PRIVATE KEY"). It is a real
	// private key and must stay outside the repo (gitignore *.key). Generate
	// an ephemeral key of the same algorithm and encoding for CI.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	keyPath := filepath.Join(t.TempDir(), "test-sign.key")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	keyPEM, err = os.ReadFile(keyPath)
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
