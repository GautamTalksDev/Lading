package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Slice is Manifest data embedded in an evidence bundle (not loaded from disk).
type Slice struct {
	Version   string    `json:"version"`
	Component Component `json:"component"`
	Entries   []Entry   `json:"entries"`
}

// LoadFromSlice constructs a Manifest from an embedded slice only.
// Verification must use this — never the installed manifest/ tree.
func LoadFromSlice(s Slice) (*Manifest, error) {
	if strings.TrimSpace(s.Version) == "" {
		return nil, fmt.Errorf("manifest: slice version empty")
	}
	comp := s.Component
	if comp.Name == "" {
		return nil, fmt.Errorf("manifest: slice component name empty")
	}
	if err := compileIdentity(&comp); err != nil {
		return nil, err
	}

	semver, contentHash, err := splitVersion(s.Version)
	if err != nil {
		return nil, err
	}

	m := &Manifest{
		semver:      semver,
		contentHash: contentHash,
		byCVE:       map[string][]Entry{},
	}
	m.components = append(m.components, comp)
	for i := range s.Entries {
		e := s.Entries[i]
		e.ComponentName = comp.Name
		key := strings.ToUpper(strings.TrimSpace(e.CVE))
		if key == "" {
			return nil, fmt.Errorf("manifest: slice entry[%d] empty cve", i)
		}
		m.byCVE[key] = append(m.byCVE[key], e)
	}
	return m, nil
}

// SliceFromManifest builds an embeddable slice for one component/CVE pair.
func SliceFromManifest(m *Manifest, componentName, cve string) (Slice, error) {
	if m == nil {
		return Slice{}, fmt.Errorf("manifest: nil")
	}
	cve = strings.ToUpper(strings.TrimSpace(cve))
	var comp *Component
	for _, c := range m.Components() {
		if c.Name == componentName {
			cc := c
			comp = &cc
			break
		}
	}
	if comp == nil {
		return Slice{}, fmt.Errorf("manifest: component %q not found", componentName)
	}
	entries, ok := m.LookupCVE(cve)
	if !ok {
		return Slice{}, fmt.Errorf("manifest: cve %q not found", cve)
	}
	var picked []Entry
	for _, e := range entries {
		if e.ComponentName == componentName {
			picked = append(picked, e)
		}
	}
	if len(picked) == 0 {
		return Slice{}, fmt.Errorf("manifest: no entry for %s on %s", cve, componentName)
	}
	return Slice{
		Version:   m.Version(),
		Component: *comp,
		Entries:   picked,
	}, nil
}

// HashSlice returns a deterministic content hash for a slice document.
func HashSlice(s Slice) (string, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func splitVersion(v string) (semver, hash string, err error) {
	v = strings.TrimSpace(v)
	i := strings.Index(v, "+")
	if i < 0 {
		return v, "slice", nil
	}
	semver = v[:i]
	hash = v[i+1:]
	if semver == "" {
		return "", "", fmt.Errorf("manifest: invalid version %q", v)
	}
	return semver, hash, nil
}

// CanonicalSliceJSON returns deterministic JSON bytes for a slice.
func CanonicalSliceJSON(s Slice) ([]byte, error) {
	type alias Slice
	data, err := json.Marshal(alias(s))
	if err != nil {
		return nil, err
	}
	return data, nil
}
