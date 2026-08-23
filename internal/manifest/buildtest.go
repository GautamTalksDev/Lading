package manifest

import (
	"strings"
)

// BuildForTest constructs an in-memory Manifest for unit tests and fixtures.
// It skips filesystem I/O and uses a fixed content hash suffix "test".
func BuildForTest(version string, comp Component, entries []Entry) (*Manifest, error) {
	compCopy := comp
	if err := compileIdentity(&compCopy); err != nil {
		return nil, err
	}
	m := &Manifest{
		semver:      strings.TrimSpace(version),
		contentHash: "test",
		byCVE:       map[string][]Entry{},
	}
	m.components = append(m.components, compCopy)
	for i := range entries {
		e := entries[i]
		e.ComponentName = compCopy.Name
		key := strings.ToUpper(strings.TrimSpace(e.CVE))
		m.byCVE[key] = append(m.byCVE[key], e)
	}
	return m, nil
}
