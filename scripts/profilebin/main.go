package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gautamtalksdev/lading/internal/scan"
	"github.com/gautamtalksdev/lading/internal/unpack"
)

func main() {
	in := os.Args[1]
	out := os.Args[2]
	_ = os.RemoveAll(out)
	_ = os.MkdirAll(out, 0o750)
	if err := unpack.ExtractFile(in, out); err != nil {
		fmt.Println("extract err", err)
		return
	}
	n := 0
	_ = filepath.Walk(out, func(p string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			n++
			if n <= 15 {
				fmt.Println(" file", p)
			}
		}
		return nil
	})
	fmt.Println("files", n)
	invs, err := scan.DiscoverBinaries(out, "")
	fmt.Println("discover", len(invs), err)
}
