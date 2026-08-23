//go:build ignore

// Harvest enclose golden cases from local clones. Run from repo root:
//
//	go run ./internal/manifestderive/hack/harvest_enclose.go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gautamtalksdev/lading/internal/manifestderive"
)

type caseSpec struct {
	ID     string
	Repo   string
	Commit string
	Note   string
}

type goldenCase struct {
	ID      string   `json:"id"`
	Repo    string   `json:"repo"`
	Commit  string   `json:"commit"`
	Note    string   `json:"note"`
	Symbols []string `json:"symbols"`
	Checked bool     `json:"hand_checked"`
	Files   []string `json:"files"`
}

func main() {
	root := mustAbs(".")
	specs := []caseSpec{
		{"zlib-CVE-2022-37434", "zlib", "eff308af425b67093bab25f80f1ae950166bece1", "CVE-2022-37434 inflate extra field"},
		{"zlib-Z_FIXED", "zlib", "5c44459c3b28a9bd3283aaceab7c615f8020c531", "deflate Z_FIXED crash"},
		{"zlib-inflatePrime", "zlib", "12b345c4309b37ab905e7e702021c1c2d2c095cc", "inflatePrime shift"},
		{"zlib-inftrees", "zlib", "51370f365607fe14a6a7a1a27b3bd29d788f5e5b", "inftrees rare bug"},
		{"zlib-inflateSync", "zlib", "5af7cef45eeef86ddf6ab00b4e363c1eecaf47b6", "inflateSync"},
		{"zlib-gzflush", "zlib", "d98251478246c8ef2f405d76e4ef1678c14d7eda", "gzflush"},
		{"zlib-minizip-hdr", "zlib", "73331a6a0481067628f065ffe87bb1d8f787d10c", "minizip header overflow"},
		{"zlib-miniunz-trav", "zlib", "14a5f8f266c16c87ab6c086fc52b770b27701e01", "miniunz traversal"},
		{"zlib-pending-assert", "zlib", "ee474ff2d11715485a87b123edbdd615ba218b88", "pending buffer assert"},
		{"zlib-inffast-incr", "zlib", "9aaec95e82117c1cb0f9624264c3618fc380cecb", "inffast post-increment"},

		{"expat-CVE-2022-25315", "libexpat", "eb0362808b4f9f1e2345a0cf203b8cc196d776d9", "CVE-2022-25315 storeRawNames"},
		{"expat-CVE-2022-25235", "libexpat", "3f0a0cb644438d4d8e3294cd0b1245d0edb0c6c6", "CVE-2022-25235 encoding"},
		{"expat-CVE-2022-25236", "libexpat", "a2fe525e660badd64b6c557c2b1ec26ddc07f6e4", "CVE-2022-25236 namespace"},
		{"expat-CVE-2022-25314", "libexpat", "efcb347440ade24b9f1054671e6bd05e60b4cafd", "copyString overflow"},
		{"expat-storeAtts", "libexpat", "12dc6d8d3d65f79471a94d8565f6bf1cf245f648", "storeAtts overflow"},
		{"expat-addBinding", "libexpat", "babfc48090977cbf7be24b2c48f6053dca75c164", "addBinding overflow"},
		{"expat-getAttributeId", "libexpat", "2c6c42d33689f6b266a5267b639e03cde17e53c0", "getAttributeId overflow"},
		{"expat-ResumeParser", "libexpat", "d5a654b4881f450827af5b3b7b72370a3bbf9a8f", "XML_ResumeParser"},
		{"expat-dtdCopy-oob", "libexpat", "98599f6dcc2b460410881fe420f5f55d6bec63bf", "dtdCopy OOB"},
		{"expat-build_model", "libexpat", "9b4ce651b26557f16103c3a366c91934ecd439ab", "Prevent stack exhaustion in build_model"},

		{"openssl-CVE-2023-0286", "openssl", "2f7530077e0ef79d98718138716bc51ca0cad658", "CVE-2023-0286 GENERAL_NAME_cmp"},
		{"openssl-CVE-2022-3602", "openssl", "3b421ebc64c7b52f1b9feb3812bdc7781c784332", "CVE-2022-3602 punycode"},
		{"openssl-CVE-2022-3786", "openssl", "680e65b94c916af259bfdc2e25f1ab6e0c7a97d6", "CVE-2022-3786 punycode"},
		{"openssl-BIO-linebuf", "openssl", "475c466ef2fbd8fc1df6fae1c3eed9c813fc8ff6", "BIO_f_linebuffer"},
		{"openssl-ASN1-mbstring", "openssl", "bd17511070fb39a67bfa19682affb765e706a974", "ASN1_mbstring_ncopy"},
		{"openssl-ASN1-trunc", "openssl", "cbe418ae978539cf14a398a207dba834c0e93e83", "ASN1_STRING_set"},
		{"openssl-cms-kek", "openssl", "eecbe330977e8d023aae1ca2d9bdbe983ef3fdc6", "cms kek_unwrap_key"},
		{"openssl-cms-auth", "openssl", "03c1f4d45fb963aee7d5833390c507cd290182bc", "CMS AuthEnvelopedData"},
		{"openssl-PKCS7-UAF", "openssl", "9dfd688ad2290fc5075cacbc9bf0c9a93eefed54", "PKCS7_verify UAF"},
	}

	outRoot := filepath.Join(root, "testdata", "manifestderive", "enclose")
	_ = os.RemoveAll(outRoot)
	must(os.MkdirAll(outRoot, 0o755))

	var goldens []goldenCase
	for _, sp := range specs {
		if strings.Contains(sp.Commit, "resolve") || len(sp.Commit) < 7 {
			continue
		}
		gc, err := harvestOne(root, outRoot, sp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", sp.ID, err)
			continue
		}
		goldens = append(goldens, gc)
		fmt.Printf("OK %s → %v\n", sp.ID, gc.Symbols)
	}
	data, _ := json.MarshalIndent(goldens, "", "  ")
	must(os.WriteFile(filepath.Join(outRoot, "cases.json"), append(data, '\n'), 0o644))
	fmt.Printf("wrote %d cases to %s\n", len(goldens), outRoot)
}

func harvestOne(root, outRoot string, sp caseSpec) (goldenCase, error) {
	repo, err := manifestderive.OpenRepo(filepath.Join(root, ".lading", "repos", sp.Repo))
	if err != nil {
		return goldenCase{}, err
	}
	sha, err := repo.ResolveCommit(sp.Commit)
	if err != nil {
		return goldenCase{}, err
	}
	parent, err := repo.Parent(sha)
	if err != nil {
		return goldenCase{}, err
	}
	patch, err := repo.ShowPatch(sha)
	if err != nil {
		return goldenCase{}, err
	}
	changed, err := manifestderive.ParseUnifiedDiff(patch)
	if err != nil {
		return goldenCase{}, err
	}
	type key struct {
		path string
		side manifestderive.Side
	}
	groups := map[key][]int{}
	for _, cl := range changed {
		ext := strings.ToLower(filepath.Ext(cl.Path))
		switch ext {
		case ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx":
		default:
			continue
		}
		k := key{cl.Path, cl.Side}
		groups[k] = append(groups[k], cl.Line)
	}
	nameSet := map[string]struct{}{}
	caseDir := filepath.Join(outRoot, sp.ID)
	must(os.MkdirAll(caseDir, 0o755))
	var files []string
	fileIdx := 0
	for k, lines := range groups {
		rev := sha
		side := "new"
		if k.side == manifestderive.SideOld {
			rev = parent
			side = "old"
		}
		src, err := repo.Blob(rev, k.path)
		if err != nil {
			continue
		}
		syms, err := manifestderive.EnclosingFunctions(src, uniq(lines), k.path, "")
		if err != nil {
			return goldenCase{}, err
		}
		for _, s := range syms {
			nameSet[s] = struct{}{}
		}
		fname := fmt.Sprintf("%02d_%s_%s", fileIdx, side, filepath.Base(k.path))
		fileIdx++
		linesMeta := uniq(lines)
		must(os.WriteFile(filepath.Join(caseDir, fname), src, 0o644))
		meta := fmt.Sprintf("path=%s\nside=%s\nlines=%s\n", k.path, side, intsCSV(linesMeta))
		must(os.WriteFile(filepath.Join(caseDir, fname+".meta"), []byte(meta), 0o644))
		files = append(files, fname)
	}
	names := mapKeys(nameSet)
	sort.Strings(names)
	return goldenCase{
		ID:      sp.ID,
		Repo:    sp.Repo,
		Commit:  sha,
		Note:    sp.Note,
		Symbols: names,
		Checked: false,
		Files:   files,
	}, nil
}

func uniq(in []int) []int {
	m := map[int]struct{}{}
	var o []int
	for _, v := range in {
		if _, ok := m[v]; ok {
			continue
		}
		m[v] = struct{}{}
		o = append(o, v)
	}
	sort.Ints(o)
	return o
}

func intsCSV(in []int) string {
	parts := make([]string, len(in))
	for i, v := range in {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, ",")
}

func mapKeys(m map[string]struct{}) []string {
	var o []string
	for k := range m {
		o = append(o, k)
	}
	return o
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func mustAbs(p string) string {
	a, err := filepath.Abs(p)
	must(err)
	return a
}
