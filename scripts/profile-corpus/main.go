// Command profile-corpus inventories ELF/PE/Mach-O binaries across ARTIFACTS.yaml
// and emits stripped/static/.dynsym-only counts. Measurement only — does not
// change scan/decision logic. Reuses inventory facts via scan.DiscoverBinaries.
package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/gautamtalksdev/lading/internal/inventory"
	"github.com/gautamtalksdev/lading/internal/scan"
	"github.com/gautamtalksdev/lading/internal/unpack"
	"gopkg.in/yaml.v3"
)

type artifactEntry struct {
	ID     string  `yaml:"id"`
	Class  string  `yaml:"class"`
	Ref    string  `yaml:"ref"`
	URL    string  `yaml:"url"`
	Path   string  `yaml:"path"`
	Status string  `yaml:"status"`
	SHA256 *string `yaml:"sha256"`
}

type catalogDoc struct {
	Artifacts []artifactEntry `yaml:"artifacts"`
}

type row struct {
	ID         string
	Class      string
	Binaries   int
	Stripped   int
	Static     int
	DynsymOnly int
	Note       string
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	root, err := filepath.Abs(root)
	must(err)

	catalogPath := filepath.Join(root, "corpus", "ARTIFACTS.yaml")
	raw, err := os.ReadFile(catalogPath) // #nosec G304
	must(err)
	var doc catalogDoc
	must(yaml.Unmarshal(raw, &doc))

	cache := filepath.Join(root, ".lading", "profile-rootfs")
	must(os.MkdirAll(cache, 0o750))
	outDir := filepath.Join(root, "results")
	must(os.MkdirAll(outDir, 0o750))

	var rows []row
	for _, a := range doc.Artifacts {
		r := profileOne(root, cache, a)
		rows = append(rows, r)
		fmt.Fprintf(os.Stderr, "[profile] %-40s class=%-22s binaries=%5d stripped=%5d (%.0f%%) static=%5d (%.0f%%) dynsym_only=%5d %s\n",
			r.ID, r.Class, r.Binaries, r.Stripped, pct(r.Stripped, r.Binaries), r.Static, pct(r.Static, r.Binaries), r.DynsymOnly, r.Note)
	}

	csvPath := filepath.Join(outDir, "binary-profile.csv")
	must(writeCSV(csvPath, rows))
	fmt.Fprintf(os.Stderr, "[profile] wrote %s\n", csvPath)

	printSummary(rows)
	profileMD := filepath.Join(root, "PROFILE.md")
	must(os.WriteFile(profileMD, []byte(oneSentence(rows)+"\n"), 0o644))
	fmt.Fprintf(os.Stderr, "[profile] wrote %s\n", profileMD)
}

func profileOne(root, cache string, a artifactEntry) row {
	r := row{ID: a.ID, Class: a.Class}
	if a.Status == "missing" {
		r.Note = "status=missing"
		return r
	}
	tree, note, err := prepareTree(root, cache, a)
	if err != nil {
		r.Note = "prepare:" + err.Error()
		return r
	}
	if note != "" {
		r.Note = note
	}
	invs, err := scan.DiscoverBinaries(tree, "")
	if err != nil {
		if strings.Contains(err.Error(), "no binaries found") {
			r.Note = joinNote(r.Note, "no-binaries")
			return r
		}
		r.Note = joinNote(r.Note, "discover:"+err.Error())
		return r
	}
	for _, inv := range invs {
		r.Binaries++
		if inv.Stripped {
			r.Stripped++
		}
		if inv.StaticLinked {
			r.Static++
		}
		if dynsymOnly(inv) {
			r.DynsymOnly++
		}
	}
	return r
}

// dynsymOnly: stripped (no .symtab) but still has dynamic symbols — the
// container-typical "dynsym only" population.
func dynsymOnly(inv *inventory.Inventory) bool {
	return inv.Stripped && len(inv.DynSyms) > 0
}

func prepareTree(root, cache string, a artifactEntry) (string, string, error) {
	dest := filepath.Join(cache, a.ID)
	marker := filepath.Join(dest, ".profile-ready")
	if st, err := os.Stat(marker); err == nil && !st.IsDir() {
		return dest, "cached", nil
	}
	_ = os.RemoveAll(dest)
	if err := os.MkdirAll(dest, 0o750); err != nil {
		return "", "", err
	}

	dl := filepath.Join(root, "corpus", "downloads", a.ID)

	// Prefer existing corpus-scan rootfs when it actually holds binaries.
	// Empty/placeholder rootfs must not block a real image.tar.
	if rf := filepath.Join(dl, "rootfs"); dirNonEmpty(rf) {
		img := filepath.Join(dl, "image.tar")
		imgOK := false
		if fi, err := os.Stat(img); err == nil && fi.Mode().IsRegular() && fi.Size() > 0 {
			imgOK = true
		}
		if hasELFUnder(rf) || !imgOK {
			return rf, "from-rootfs", nil
		}
	}

	// Local path artifact (benchmark / static when stored as path).
	if a.Path != "" {
		p := a.Path
		if !filepath.IsAbs(p) {
			p = filepath.Join(root, p)
		}
		fi, err := os.Stat(p)
		if err == nil && fi.IsDir() {
			return p, "from-path-dir", nil
		}
		if err == nil && !fi.IsDir() {
			return prepareFile(p, dest)
		}
	}

	// OCI docker-archive image.tar
	img := filepath.Join(dl, "image.tar")
	if fi, err := os.Stat(img); err == nil && fi.Mode().IsRegular() && fi.Size() > 0 {
		if err := extractDockerArchive(img, dest); err != nil {
			// Fall back to unpack.ExtractFile (may leave nested layer tars).
			_ = os.RemoveAll(dest)
			_ = os.MkdirAll(dest, 0o750)
			if err2 := unpack.ExtractFile(img, dest); err2 != nil {
				return "", "", fmt.Errorf("docker-archive: %v; extract: %w", err, err2)
			}
			return markReady(dest, "image-tar-flat")
		}
		return markReady(dest, "image-tar-layers")
	}

	// URL / firmware payload in downloads/<id>/
	payload, err := findPayload(dl)
	if err != nil {
		return "", "", err
	}
	return prepareFile(payload, dest)
}

func prepareFile(payload, dest string) (string, string, error) {
	base := strings.ToLower(filepath.Base(payload))
	switch {
	case strings.HasSuffix(base, ".tar.gz"), strings.HasSuffix(base, ".tgz"),
		strings.HasSuffix(base, ".tar.xz"), strings.HasSuffix(base, ".tar"),
		strings.HasSuffix(base, ".zip"):
		if err := extractArchiveShell(payload, dest); err != nil {
			return "", "", err
		}
		// Vendor firmware zips often wrap a .chk / TRX blob — carve squashfs if present.
		_ = carveNestedFirmware(dest)
		return markReady(dest, "archive")
	case strings.HasSuffix(base, ".chk"):
		if err := extractSquashFromBin(payload, dest); err != nil {
			_ = copyFile(payload, filepath.Join(dest, filepath.Base(payload)))
			return markReady(dest, "chk-opaque")
		}
		return markReady(dest, "squashfs-chk")
	case strings.HasSuffix(base, ".img.gz"):
		if err := extractSquashFromGzipImage(payload, dest); err != nil {
			return "", "", err
		}
		return markReady(dest, "squashfs-img-gz")
	case strings.HasSuffix(base, ".bin"):
		if err := extractSquashFromBin(payload, dest); err != nil {
			return "", "", err
		}
		return markReady(dest, "squashfs-bin")
	case strings.HasSuffix(base, ".ext4"):
		if err := extractExt4(payload, dest); err != nil {
			return "", "", err
		}
		return markReady(dest, "ext4")
	case strings.HasSuffix(base, ".wic"):
		if err := extractWIC(payload, dest); err != nil {
			return "", "", err
		}
		return markReady(dest, "wic")
	default:
		// Single binary or opaque blob: place file and also try squashfs carve.
		out := filepath.Join(dest, filepath.Base(payload))
		if err := copyFile(payload, out); err != nil {
			return "", "", err
		}
		_ = extractSquashFromBin(payload, filepath.Join(dest, "_squash"))
		return markReady(dest, "opaque")
	}
}

func carveNestedFirmware(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return err
		}
		name := strings.ToLower(info.Name())
		if !(strings.HasSuffix(name, ".chk") || strings.HasSuffix(name, ".bin") ||
			strings.HasSuffix(name, ".trx") || strings.HasSuffix(name, ".img")) {
			return nil
		}
		sub := filepath.Join(filepath.Dir(path), "_squash_"+info.Name())
		_ = os.MkdirAll(sub, 0o750)
		_ = extractSquashFromBin(path, sub)
		return nil
	})
}

func hasELFUnder(root string) bool {
	found := false
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || found {
			return nil
		}
		f, err := os.Open(path) // #nosec G304
		if err != nil {
			return nil
		}
		var hdr [4]byte
		_, _ = f.Read(hdr[:])
		_ = f.Close()
		if hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F' {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func findPayload(dl string) (string, error) {
	ents, err := os.ReadDir(dl)
	if err != nil {
		return "", fmt.Errorf("downloads missing: %w", err)
	}
	skip := map[string]bool{
		"image.ref": true, "image.tar": true, "download-failure.json": true,
		"provenance.json": true, "rootfs": true,
	}
	var cands []string
	for _, e := range ents {
		if e.IsDir() || skip[e.Name()] || strings.HasSuffix(e.Name(), ".partial") {
			continue
		}
		cands = append(cands, filepath.Join(dl, e.Name()))
	}
	if len(cands) == 0 {
		return "", fmt.Errorf("no payload in %s", dl)
	}
	sort.Slice(cands, func(i, j int) bool {
		si, _ := os.Stat(cands[i])
		sj, _ := os.Stat(cands[j])
		return si.Size() > sj.Size()
	})
	return cands[0], nil
}

func extractDockerArchive(imageTar, dest string) error {
	tmp, err := os.MkdirTemp("", "lading-oci-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if err := exec.Command("tar", "-xf", imageTar, "-C", tmp).Run(); err != nil {
		return fmt.Errorf("tar image.tar: %w", err)
	}
	manPath := filepath.Join(tmp, "manifest.json")
	raw, err := os.ReadFile(manPath) // #nosec G304
	if err != nil {
		return err
	}
	var manifests []struct {
		Layers []string `json:"Layers"`
	}
	if err := json.Unmarshal(raw, &manifests); err != nil {
		return err
	}
	if len(manifests) == 0 {
		return fmt.Errorf("empty manifest.json")
	}
	for _, layer := range manifests[0].Layers {
		lp := filepath.Join(tmp, layer)
		cmd := exec.Command("tar", // #nosec G204
			"--exclude=dev", "--exclude=./dev",
			"--no-same-owner", "--no-same-permissions",
			"-xf", lp, "-C", dest)
		if out, err := cmd.CombinedOutput(); err != nil {
			// Device nodes / hardlinks often fail without root; keep going if files landed.
			if !dirNonEmpty(dest) {
				return fmt.Errorf("layer %s: %w (%s)", layer, err, truncate(string(out), 200))
			}
		}
	}
	return nil
}

func extractArchiveShell(archive, dest string) error {
	base := strings.ToLower(archive)
	switch {
	case strings.HasSuffix(base, ".zip"):
		return run(exec.Command("unzip", "-q", "-o", archive, "-d", dest))
	case strings.HasSuffix(base, ".tar.gz"), strings.HasSuffix(base, ".tgz"):
		return run(exec.Command("tar", "-xzf", archive, "-C", dest))
	case strings.HasSuffix(base, ".tar.xz"):
		return run(exec.Command("tar", "-xJf", archive, "-C", dest))
	case strings.HasSuffix(base, ".tar"):
		return run(exec.Command("tar", "-xf", archive, "-C", dest))
	default:
		return fmt.Errorf("unsupported archive %s", archive)
	}
}

func extractSquashFromBin(bin, dest string) error {
	off, err := findMagic(bin, []byte("hsqs"))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dest, 0o750); err != nil {
		return err
	}
	cmd := exec.Command("unsquashfs", "-ignore-errors", "-no-exit-code", "-f", "-d", dest, "-o", strconv.FormatInt(off, 10), bin) // #nosec G204
	out, err := cmd.CombinedOutput()
	if !dirNonEmpty(dest) {
		return fmt.Errorf("unsquashfs: %w (%s)", err, truncate(string(out), 300))
	}
	return nil
}

func extractSquashFromGzipImage(gzPath, dest string) error {
	tmp, err := os.CreateTemp("", "lading-img-*.img")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	// gunzip with trailing-garbage tolerance (OpenWrt combined images).
	cmd := exec.Command("gunzip", "-c", gzPath)
	cmd.Stdout = tmp
	cmd.Stderr = io.Discard
	_ = cmd.Run() // trailing garbage → non-zero; bytes still written
	_ = tmp.Close()

	off, err := findMagic(tmpName, []byte("hsqs"))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dest, 0o750); err != nil {
		return err
	}
	u := exec.Command("unsquashfs", "-ignore-errors", "-no-exit-code", "-f", "-d", dest, "-o", strconv.FormatInt(off, 10), tmpName) // #nosec G204
	out, err := u.CombinedOutput()
	if !dirNonEmpty(dest) {
		return fmt.Errorf("unsquashfs img: %w (%s)", err, truncate(string(out), 300))
	}
	return nil
}

func extractExt4(img, dest string) error {
	if err := os.MkdirAll(dest, 0o750); err != nil {
		return err
	}
	// debugfs rdump may warn on chown; files still land.
	cmd := exec.Command("debugfs", "-R", "rdump / "+dest, img) // #nosec G204
	out, err := cmd.CombinedOutput()
	if !dirNonEmpty(dest) {
		return fmt.Errorf("debugfs rdump failed: %v (%s)", err, truncate(string(out), 300))
	}
	return nil
}

func extractWIC(wic, dest string) error {
	// GPT partition 2 is typically the Linux rootfs (ext4).
	out, err := exec.Command("sfdisk", "-J", wic).Output()
	if err != nil {
		return fmt.Errorf("sfdisk: %w", err)
	}
	var sf struct {
		PartitionTable struct {
			Partitions []struct {
				Node  string `json:"node"`
				Start int64  `json:"start"`
				Size  int64  `json:"size"`
				Type  string `json:"type"`
			} `json:"partitions"`
		} `json:"partitiontable"`
	}
	if err := json.Unmarshal(out, &sf); err != nil {
		return err
	}
	var start, size int64
	for _, p := range sf.PartitionTable.Partitions {
		t := strings.ToLower(p.Type)
		if strings.Contains(t, "linux") && !strings.Contains(t, "swap") {
			start, size = p.Start, p.Size
			break
		}
	}
	if size == 0 && len(sf.PartitionTable.Partitions) >= 2 {
		p := sf.PartitionTable.Partitions[1]
		start, size = p.Start, p.Size
	}
	if size == 0 {
		return fmt.Errorf("no linux partition in wic")
	}
	part := filepath.Join(dest, "_root.ext4")
	if err := os.MkdirAll(dest, 0o750); err != nil {
		return err
	}
	// dd partition
	bs := int64(512)
	cmd := exec.Command("dd", // #nosec G204
		"if="+wic, "of="+part,
		"bs="+strconv.FormatInt(bs, 10),
		"skip="+strconv.FormatInt(start, 10),
		"count="+strconv.FormatInt(size, 10),
		"status=none")
	if err := run(cmd); err != nil {
		return err
	}
	sub := filepath.Join(dest, "root")
	if err := extractExt4(part, sub); err != nil {
		return err
	}
	_ = os.Remove(part)
	return nil
}

func findMagic(path string, magic []byte) (int64, error) {
	f, err := os.Open(path) // #nosec G304
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	const chunk = 4 << 20
	buf := make([]byte, chunk+len(magic)-1)
	var off int64
	var carry []byte
	for {
		n, err := f.Read(buf[len(carry):])
		data := append(carry, buf[len(carry):len(carry)+n]...)
		if i := indexOf(data, magic); i >= 0 {
			return off + int64(i), nil
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
		if len(data) >= len(magic)-1 {
			carry = append([]byte(nil), data[len(data)-(len(magic)-1):]...)
		}
		off += int64(len(data) - len(carry))
	}
	return 0, fmt.Errorf("magic %q not found in %s", magic, filepath.Base(path))
}

func indexOf(data, magic []byte) int {
	for i := 0; i+len(magic) <= len(data); i++ {
		ok := true
		for j := range magic {
			if data[i+j] != magic[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

func markReady(dest, note string) (string, string, error) {
	if err := os.WriteFile(filepath.Join(dest, ".profile-ready"), []byte(note+"\n"), 0o644); err != nil {
		return "", "", err
	}
	return dest, note, nil
}

func writeCSV(path string, rows []row) error {
	f, err := os.Create(path) // #nosec G304
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	w := csv.NewWriter(f)
	_ = w.Write([]string{
		"artifact_id", "class", "binaries", "stripped", "stripped_pct",
		"static_linked", "static_pct", "dynsym_only", "dynsym_only_pct", "note",
	})
	for _, r := range rows {
		_ = w.Write([]string{
			r.ID, r.Class,
			itoa(r.Binaries), itoa(r.Stripped), fmt.Sprintf("%.1f", pct(r.Stripped, r.Binaries)),
			itoa(r.Static), fmt.Sprintf("%.1f", pct(r.Static, r.Binaries)),
			itoa(r.DynsymOnly), fmt.Sprintf("%.1f", pct(r.DynsymOnly, r.Binaries)),
			r.Note,
		})
	}
	w.Flush()
	return w.Error()
}

func printSummary(rows []row) {
	type agg struct {
		n, bin, stripped, static, dyn int
	}
	by := map[string]*agg{}
	order := []string{}
	for _, r := range rows {
		a := by[r.Class]
		if a == nil {
			a = &agg{}
			by[r.Class] = a
			order = append(order, r.Class)
		}
		a.n++
		a.bin += r.Binaries
		a.stripped += r.Stripped
		a.static += r.Static
		a.dyn += r.DynsymOnly
	}
	sort.Strings(order)

	fmt.Println()
	fmt.Printf("%-22s %8s %10s %12s %10s %12s %10s\n",
		"class", "artifacts", "binaries", "stripped", "strip%", "static", "static%")
	fmt.Println(strings.Repeat("-", 90))
	for _, c := range order {
		a := by[c]
		fmt.Printf("%-22s %8d %10d %12d %9.1f%% %12d %9.1f%%\n",
			c, a.n, a.bin, a.stripped, pct(a.stripped, a.bin), a.static, pct(a.static, a.bin))
	}
	fw, okF := by["firmware"]
	sc, okS := by["substitute-container"]
	fmt.Println()
	safe := func(c string) *agg {
		if a := by[c]; a != nil {
			return a
		}
		return &agg{}
	}
	if okF && okS && fw.bin > 0 {
		fmt.Printf("firmware vs substitute-container: stripped %.1f%% vs %.1f%%; static %.1f%% vs %.1f%%\n",
			pct(fw.stripped, fw.bin), pct(sc.stripped, sc.bin),
			pct(fw.static, fw.bin), pct(sc.static, sc.bin))
	}
	// Container stratum = oci-base + oci-app + substitute-container
	cBin := safe("oci-base").bin + safe("oci-app").bin + safe("substitute-container").bin
	cStrip := safe("oci-base").stripped + safe("oci-app").stripped + safe("substitute-container").stripped
	cStat := safe("oci-base").static + safe("oci-app").static + safe("substitute-container").static
	if okF && fw.bin > 0 && cBin > 0 {
		fmt.Printf("firmware vs container(oci+subst): stripped %.1f%% vs %.1f%%; static %.1f%% vs %.1f%%\n",
			pct(fw.stripped, fw.bin), pct(cStrip, cBin),
			pct(fw.static, fw.bin), pct(cStat, cBin))
	}
}

func oneSentence(rows []row) string {
	sum := func(classes ...string) (bin, stripped, static int) {
		want := map[string]bool{}
		for _, c := range classes {
			want[c] = true
		}
		for _, r := range rows {
			if want[r.Class] {
				bin += r.Binaries
				stripped += r.Stripped
				static += r.Static
			}
		}
		return
	}
	fb, fs, fst := sum("firmware")
	cb, cs, cst := sum("oci-base", "oci-app", "substitute-container")
	if fb == 0 {
		return "Firmware stratum yielded no inventoryable binaries in this profile run, so stripped/static comparison to the container stratum is not yet measurable."
	}
	if cb == 0 {
		return "Container stratum yielded no inventoryable binaries in this profile run, so firmware-vs-container comparison is not yet measurable."
	}
	fStrip, cStrip := pct(fs, fb), pct(cs, cb)
	fStat, cStat := pct(fst, fb), pct(cst, cb)
	stripDelta := fStrip - cStrip
	statDelta := fStat - cStat
	const material = 15.0 // percentage points

	switch {
	case abs(stripDelta) < material && abs(statDelta) < material:
		return fmt.Sprintf(
			"No: the firmware stratum is not materially different from the container stratum on stripped/static profile (firmware stripped %.0f%% / static %.0f%% vs containers stripped %.0f%% / static %.0f%%), so D01 evidence will likely stay thin and KT-1 should return the honest number without adjusting the kill test.",
			fStrip, fStat, cStrip, cStat)
	case stripDelta <= -material || (statDelta >= material && fStrip+10 < cStrip):
		return fmt.Sprintf(
			"Yes: the firmware stratum is materially less stripped and/or more static than the container stratum (firmware stripped %.0f%% / static %.0f%% vs containers stripped %.0f%% / static %.0f%%), so the symbol-evidence thesis is well-placed.",
			fStrip, fStat, cStrip, cStat)
	case stripDelta >= material:
		return fmt.Sprintf(
			"No: the firmware stratum is at least as stripped as the container stratum (firmware stripped %.0f%% / static %.0f%% vs containers stripped %.0f%% / static %.0f%%), so D01 evidence will be thin — do not adjust the kill test; proceed to measurement and let KT-1 return the honest number.",
			fStrip, fStat, cStrip, cStat)
	default:
		return fmt.Sprintf(
			"Mixed: firmware stripped %.0f%% / static %.0f%% vs containers stripped %.0f%% / static %.0f%% — not a clear static/unstripped advantage; treat D01 evidence as likely thin and proceed without adjusting the kill test.",
			fStrip, fStat, cStrip, cStat)
	}
}

func pct(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return 100 * float64(n) / float64(d)
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func itoa(n int) string { return strconv.Itoa(n) }

func dirNonEmpty(p string) bool {
	ents, err := os.ReadDir(p)
	return err == nil && len(ents) > 0
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	in, err := os.Open(src) // #nosec G304
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	_, err = io.Copy(out, in)
	return err
}

func run(cmd *exec.Cmd) error {
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %w (%s)", cmd.Args, err, truncate(string(out), 200))
	}
	return nil
}

func joinNote(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + ";" + b
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
