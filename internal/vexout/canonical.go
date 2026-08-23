package vexout

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func marshalCanonical(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	return data, nil
}

func sortedStatements(in DocumentInput) []Statement {
	out := append([]Statement(nil), in.Statements...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].CVE != out[j].CVE {
			return out[i].CVE < out[j].CVE
		}
		if out[i].ComponentPURL != out[j].ComponentPURL {
			return out[i].ComponentPURL < out[j].ComponentPURL
		}
		return out[i].StatementID < out[j].StatementID
	})
	return out
}

func documentSeed(in DocumentInput, format string) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(format))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(in.BundleID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(in.ArtifactSHA256))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(in.Timestamp))
	_, _ = h.Write([]byte{0})
	for _, s := range sortedStatements(in) {
		_, _ = h.Write([]byte(s.CVE))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(s.ComponentPURL))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(string(s.Result.Verdict)))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(string(s.Result.RuleID)))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(string(s.Result.ReasonCode)))
		_, _ = h.Write([]byte{0})
	}
	return h.Sum(nil)
}

func documentID(in DocumentInput, format string) string {
	sum := documentSeed(in, format)
	return fmt.Sprintf("urn:lading:%s:%s", format, hex.EncodeToString(sum[:16]))
}

func deterministicUUID(seed []byte) string {
	h := sha256.Sum256(append([]byte("lading-uuid-v5\x00"), seed...))
	h[6] = (h[6] & 0x0f) | 0x50
	h[8] = (h[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%08x-%04x-%04x-%04x-%012x",
		uint32(h[0])<<24|uint32(h[1])<<16|uint32(h[2])<<8|uint32(h[3]),
		uint16(h[4])<<8|uint16(h[5]),
		uint16(h[6])<<8|uint16(h[7]),
		uint16(h[8])<<8|uint16(h[9]),
		uint64(h[10])<<40|uint64(h[11])<<32|uint64(h[12])<<24|
			uint64(h[13])<<16|uint64(h[14])<<8|uint64(h[15]))
}

func productRef(pinnedPURL string) string {
	sum := sha256.Sum256([]byte("lading-cdx-ref\x00" + pinnedPURL))
	return "lading:" + hex.EncodeToString(sum[:8])
}

func csafProductID(pinnedPURL string) string {
	sum := sha256.Sum256([]byte("lading-csaf-pid\x00" + pinnedPURL))
	return "LADINGPID-" + stringsUpper(hex.EncodeToString(sum[:8]))
}

func stringsUpper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}

func csafTrackingID(in DocumentInput) string {
	sum := documentSeed(in, "csaf")
	return "LADING-VEX-" + stringsUpper(hex.EncodeToString(sum[:8]))
}

func artifactSHA256Hex(in DocumentInput) string {
	return strings.ToLower(strings.TrimSpace(in.ArtifactSHA256))
}
