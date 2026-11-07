// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
)

// buildInfo is what `otprobe version` reports: the values injected at build
// time (main.version, main.tag, main.commit, main.buildDate), completed
// from the Go build information for a `go build` or `go install`.
type buildInfo struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Tag       string    `json:"tag"`
	Commit    string    `json:"commit"`
	Built     string    `json:"built"`
	Libraries []library `json:"libraries"`
	Go        string    `json:"go"`
	Platform  string    `json:"platform"`
}

// library is an OT Fabric Go library the binary is built on.
type library struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// toolName is the name the version output starts with.
const toolName = "otprobe"

// ownModules are left out of the libraries: this repository's library,
// which the version already describes.
var ownModules = map[string]bool{"github.com/otfabric/go-otfp": true}

// pseudoVersion matches a Go pseudo-version (vX.Y.Z-yyyymmddhhmmss-abcdefabcdef).
var pseudoVersion = regexp.MustCompile(`\d{14}-[0-9a-f]{12}(\+.*)?$`)

// currentBuildInfo resolves the build information of this binary.
func currentBuildInfo() buildInfo {
	bi, _ := debug.ReadBuildInfo()
	return resolveBuildInfo(version, tag, commit, buildDate, bi)
}

// resolveBuildInfo fills each field from the injected value, else from the
// Go build information bi (which may be nil), else "dev" or "unknown".
func resolveBuildInfo(version, tag, commit, built string, bi *debug.BuildInfo) buildInfo {
	info := buildInfo{
		Name: toolName, Version: strings.TrimPrefix(version, "v"), Tag: tag, Commit: commit, Built: built,
		Libraries: libraries(bi), Go: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}
	if info.Version == "" || info.Version == "dev" {
		info.Version = "dev"
		// A `go install …@vX.Y.Z` records the module version; a local build
		// records (devel), a pseudo-version or a +dirty version: dev.
		if bi != nil && realVersion(bi.Main.Version) {
			info.Version = strings.TrimPrefix(bi.Main.Version, "v")
		}
	}
	if info.Commit == "" || info.Commit == "unknown" {
		info.Commit = "unknown"
		if bi != nil {
			var rev, modified string
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision":
					rev = s.Value
				case "vcs.modified":
					modified = s.Value
				}
			}
			if rev != "" {
				info.Commit = rev
				if modified == "true" {
					info.Commit += "-dirty"
				}
			}
		}
	}
	if info.Built == "" {
		info.Built = "unknown"
	}
	return info
}

// realVersion reports whether a module version from the build information
// is a release version.
func realVersion(v string) bool {
	return v != "" && v != "(devel)" && !strings.Contains(v, "+") && !pseudoVersion.MatchString(v)
}

// libraries lists the github.com/otfabric/go-* modules among the
// dependencies (their replacements where replaced), sorted by name; never nil.
func libraries(bi *debug.BuildInfo) []library {
	libs := []library{}
	if bi == nil {
		return libs
	}
	for _, d := range bi.Deps {
		m := d
		if d.Replace != nil {
			m = d.Replace
		}
		if !strings.HasPrefix(d.Path, "github.com/otfabric/go-") || d.Path == bi.Main.Path || ownModules[d.Path] {
			continue
		}
		name := d.Path[strings.LastIndex(d.Path, "/")+1:]
		if strings.HasPrefix(m.Path, "github.com/otfabric/go-") {
			name = m.Path[strings.LastIndex(m.Path, "/")+1:]
		}
		libs = append(libs, library{Name: name, Version: strings.TrimPrefix(m.Version, "v")})
	}
	sort.Slice(libs, func(i, j int) bool { return libs[i].Name < libs[j].Name })
	return libs
}

// Text is the one-line text form:
//
//	otprobe 0.5.0 (tag v0.5.0, commit <sha>, built <date>, go-x 1.2.3, go1.26.3, linux/amd64)
func (b buildInfo) Text() string {
	var s strings.Builder
	fmt.Fprintf(&s, "%s %s (", b.Name, b.Version)
	if b.Tag != "" {
		fmt.Fprintf(&s, "tag %s, ", b.Tag)
	}
	fmt.Fprintf(&s, "commit %s, built %s, ", b.Commit, b.Built)
	for _, l := range b.Libraries {
		fmt.Fprintf(&s, "%s %s, ", l.Name, l.Version)
	}
	fmt.Fprintf(&s, "%s, %s)", b.Go, b.Platform)
	return s.String()
}

// JSON is the one-line JSON form, keys in a fixed order.
func (b buildInfo) JSON() string {
	if b.Libraries == nil {
		b.Libraries = []library{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(b) // strings and a slice of strings always encode
	return strings.TrimSuffix(buf.String(), "\n")
}
