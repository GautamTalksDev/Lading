package purl

// Equivalent grades the identity relationship between two PURLs.
// It never returns a bare boolean — callers must inspect MatchQuality.
func Equivalent(a, b PURL) MatchQuality {
	if a.Empty() || b.Empty() {
		return None
	}

	// Digest conflict ⇒ no relationship, even if names agree.
	if digestsConflict(a, b) {
		return None
	}

	nameA, nameB := a.Name, b.Name
	verA, verB := a.Version, b.Version
	nsA, nsB := a.Namespace, b.Namespace
	typeA, typeB := a.Type, b.Type

	namesMatch := nameA != "" && nameA == nameB
	versionsMatch := verA != "" && verA == verB
	versionsBothEmpty := verA == "" && verB == ""
	nsMatch := nsA == nsB
	typesMatch := typeA == typeB

	if !namesMatch {
		return None
	}

	// Cross-type: never Exact / TypeNormalized.
	if !typesMatch {
		if versionsMatch {
			return NameVersionOnly
		}
		return NameOnly
	}

	// Same type.
	if a.Canonical() == b.Canonical() {
		return Exact
	}

	if nsMatch && versionsMatch {
		// Type + ns + name + version agree; qualifiers/subpath differ
		// (without digest conflict — checked above).
		return TypeNormalized
	}

	if versionsMatch {
		// Same type and name+version, namespace differs (e.g. missing vs present).
		return NameVersionOnly
	}

	if versionsBothEmpty && nsMatch {
		// Same type/ns/name, no versions — treat as type-normalized identity
		// of an unversioned package, not Exact (canonical may still differ
		// on qualifiers).
		if qualifierEqual(a.Qualifiers, b.Qualifiers) && a.Subpath == b.Subpath {
			return Exact
		}
		return TypeNormalized
	}

	// Unversioned template PURL (manifest component) vs concrete versioned
	// finding — same type/ns/name. Stronger than name_only: the empty side
	// asserts identity without pinning a version.
	if nsMatch && (verA == "" || verB == "") {
		return TypeNormalized
	}

	return NameOnly
}

func digestsConflict(a, b PURL) bool {
	da := identityDigest(a)
	db := identityDigest(b)
	if da == "" || db == "" {
		return false
	}
	return da != db
}

func identityDigest(p PURL) string {
	if p.Qualifiers == nil {
		return ""
	}
	for _, k := range []string{"checksum", "repository_url", "download_url"} {
		if k == "checksum" {
			if v := p.Qualifiers[k]; v != "" {
				return v
			}
		}
	}
	// Prefer explicit checksum only for conflict detection.
	return p.Qualifiers["checksum"]
}

func qualifierEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
