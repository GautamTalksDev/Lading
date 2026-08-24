// Package purl implements Package URL canonicalization and graded equivalence.
//
// The decision engine must never receive a bare boolean: Equivalent always
// returns a MatchQuality so Exact digest-pinned identity can be distinguished
// from a fuzzy name-only hit.
package purl

import "fmt"

// MatchQuality grades how two PURLs relate. Ordered from weakest to strongest
// for comparison helpers; never collapse this to a bool at the API boundary.
type MatchQuality int

const (
	// None — no usable identity relationship.
	None MatchQuality = iota
	// NameOnly — package name matches after type-specific normalization;
	// type and/or version disagree.
	NameOnly
	// NameVersionOnly — name and version match; type and/or namespace disagree.
	// Cross-type hits (pkg:generic/openssl vs pkg:deb/debian/openssl) stop here.
	NameVersionOnly
	// TypeNormalized — same type; namespace/name/version agree after
	// type-specific normalization. Qualifiers/subpath may differ, but digests
	// do not conflict.
	TypeNormalized
	// IdentityMapped — distro finding resolved to an upstream component via a
	// definitive identity alias; stronger than type_normalized but not exact.
	IdentityMapped
	// Exact — canonical forms are identical (type, namespace, name, version,
	// sorted qualifiers, subpath).
	Exact
)

func (q MatchQuality) String() string {
	switch q {
	case None:
		return "none"
	case NameOnly:
		return "name_only"
	case NameVersionOnly:
		return "name_version_only"
	case TypeNormalized:
		return "type_normalized"
	case IdentityMapped:
		return "identity_mapped"
	case Exact:
		return "exact"
	default:
		return fmt.Sprintf("MatchQuality(%d)", int(q))
	}
}

// AtLeast reports whether q is at least as strong as min.
func (q MatchQuality) AtLeast(min MatchQuality) bool {
	return q >= min
}

// PURL is a parsed Package URL. Raw is always the unmodified input string.
type PURL struct {
	Raw        string
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string // normalized keys, insertion-independent
	Subpath    string
}

// Canonical returns the purl-spec canonical string form (not Raw).
func (p PURL) Canonical() string {
	return formatCanonical(p)
}

// Empty reports whether p has no type/name (unusable identity).
func (p PURL) Empty() bool {
	return p.Type == "" || p.Name == ""
}
