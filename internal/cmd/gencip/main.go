// SPDX-License-Identifier: MIT

// Command gencip regenerates protocols/enip/catalog.go — the EtherNet/IP
// vendor and device-type name tables — from the CIP catalogue of the
// sibling module github.com/otfabric/go-ethernetip.
//
// go-otfp is a zero-dependency library, so go-ethernetip is not imported;
// the generator reads its catalogue source directly. Point it at a local
// checkout with -src, or let it find the module in the Go cache.
//
// Usage:
//
//	go run ./internal/cmd/gencip [-src ../go-ethernetip] [-out protocols/enip/catalog.go]
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func main() {
	src := flag.String("src", "", "path to a go-ethernetip checkout (default: locate via go list)")
	out := flag.String("out", "protocols/enip/catalog.go", "output file")
	flag.Parse()
	if err := run(*src, *out); err != nil {
		fmt.Fprintln(os.Stderr, "gencip:", err)
		os.Exit(1)
	}
}

func run(src, out string) error {
	if src == "" {
		var err error
		if src, err = locate(); err != nil {
			return err
		}
	}
	catalog, err := os.ReadFile(filepath.Join(src, "cip", "catalog_gen.go"))
	if err != nil {
		return err
	}
	codes, _ := os.ReadFile(filepath.Join(src, "cip", "codes.go"))
	devs := deviceTypes(string(catalog))
	vendors := vendorEntries(string(catalog) + string(codes))
	if len(devs) == 0 || len(vendors) == 0 {
		return fmt.Errorf("found %d device types and %d vendors; catalogue layout changed", len(devs), len(vendors))
	}
	code, err := format.Source(render(devs, vendors))
	if err != nil {
		return err
	}
	return os.WriteFile(out, code, 0o644)
}

func locate() (string, error) {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/otfabric/go-ethernetip")
	cmd.Env = append(os.Environ(), "GOWORK=off")
	b, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go list go-ethernetip: %w (pass -src)", err)
	}
	return strings.TrimSpace(string(b)), nil
}

type pair struct {
	id   int
	name string
}

func deviceTypes(src string) []pair {
	ids := map[string]int{}
	for _, m := range regexp.MustCompile(`DeviceType(\w+) DeviceType = (0x[0-9A-Fa-f]+)`).FindAllStringSubmatch(src, -1) {
		v, _ := strconv.ParseInt(m[2], 0, 32)
		ids[m[1]] = int(v)
	}
	seen := map[int]bool{}
	var out []pair
	for _, m := range regexp.MustCompile(`DeviceType(\w+):\s*"([^"]+)"`).FindAllStringSubmatch(src, -1) {
		if id, ok := ids[m[1]]; ok && !seen[id] {
			seen[id] = true
			out = append(out, pair{id, m[2]})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

func vendorEntries(src string) []pair {
	i := strings.Index(src, "vendors = [...]vendorEntry{")
	if i < 0 {
		return nil
	}
	block := src[i:]
	block = block[:strings.Index(block, "\n}")]
	var out []pair
	for _, m := range regexp.MustCompile(`\{(\d+), "([^"]*)"\}`).FindAllStringSubmatch(block, -1) {
		id, _ := strconv.Atoi(m[1])
		out = append(out, pair{id, m[2]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

func render(devs, vendors []pair) []byte {
	var b bytes.Buffer
	b.WriteString(`// SPDX-License-Identifier: MIT

package enip

// This file is generated from go-ethernetip's CIP catalogue by
// internal/cmd/gencip. Do not edit by hand; run ` + "`go generate ./...`" + `.

import "sort"

//go:generate go run ../../internal/cmd/gencip

// deviceTypeName returns the ODVA device-type name, or a hex fallback.
func deviceTypeName(t uint16) string {
	if n, ok := deviceTypeNames[t]; ok {
		return n
	}
	return "device type 0x" + hex2(t)
}

// vendorName returns the ODVA vendor name, or "" when unknown.
func vendorName(id uint16) string {
	i := sort.Search(len(vendors), func(i int) bool { return vendors[i].id >= id })
	if i < len(vendors) && vendors[i].id == id {
		return vendors[i].name
	}
	return ""
}

func hex2(v uint16) string {
	const d = "0123456789abcdef"
	return string([]byte{d[v>>12&0xf], d[v>>8&0xf], d[v>>4&0xf], d[v&0xf]})
}

var deviceTypeNames = map[uint16]string{
`)
	for _, d := range devs {
		fmt.Fprintf(&b, "\t0x%04X: %q,\n", d.id, d.name)
	}
	b.WriteString("}\n\ntype vendorEntry struct {\n\tid   uint16\n\tname string\n}\n\n// vendors is the ODVA public vendor-ID list, sorted by ID.\nvar vendors = [...]vendorEntry{\n")
	for _, v := range vendors {
		fmt.Fprintf(&b, "\t{%d, %q},\n", v.id, v.name)
	}
	b.WriteString("}\n")
	return b.Bytes()
}
