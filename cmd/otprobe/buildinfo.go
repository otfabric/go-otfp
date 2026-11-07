// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// buildInfo is what `otprobe version` reports: the values injected at build
// time (main.version, main.tag, main.commit, main.buildDate), completed
// from the Go build information for a `go build` or `go install`.
type buildInfo struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Tag      string `json:"tag"`
	Commit   string `json:"commit"`
	Built    string `json:"built"`
	Go       string `json:"go"`
	Platform string `json:"platform"`
}

// currentBuildInfo resolves the build information of this binary.
func currentBuildInfo() buildInfo {
	bi, _ := debug.ReadBuildInfo()
	return resolveBuildInfo("otprobe", version, tag, commit, buildDate, bi)
}

// resolveBuildInfo fills each field from the injected value, else from the
// Go build information bi (which may be nil), else "dev" or "unknown".
func resolveBuildInfo(name, version, tag, commit, built string, bi *debug.BuildInfo) buildInfo {
	info := buildInfo{
		Name: name, Version: strings.TrimPrefix(version, "v"), Tag: tag, Commit: commit, Built: built,
		Go: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}
	if info.Version == "" || info.Version == "dev" {
		info.Version = "dev"
		// A `go install …@vX.Y.Z` records the module version; a local build
		// records (devel) or, from a modified tree, a +dirty pseudo-version.
		if bi != nil && bi.Main.Version != "" && bi.Main.Version != "(devel)" && !strings.HasSuffix(bi.Main.Version, "+dirty") {
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

// Text is the one-line text form:
//
//	otprobe 0.5.0 (tag v0.5.0, commit <sha>, built <date>, go1.26.3, linux/amd64)
func (b buildInfo) Text() string {
	tagPart := ""
	if b.Tag != "" {
		tagPart = "tag " + b.Tag + ", "
	}
	return fmt.Sprintf("%s %s (%scommit %s, built %s, %s, %s)", b.Name, b.Version, tagPart, b.Commit, b.Built, b.Go, b.Platform)
}

// JSON is the one-line JSON form, keys in a fixed order.
func (b buildInfo) JSON() string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(b) // a struct of strings always encodes
	return strings.TrimSuffix(buf.String(), "\n")
}
