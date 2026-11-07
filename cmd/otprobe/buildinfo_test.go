// SPDX-License-Identifier: MIT

package main

import (
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const sha = "1802d0f9afe8642d1e278120b76fcdfac967cb9e"

var goPlatform = runtime.Version() + ", " + runtime.GOOS + "/" + runtime.GOARCH

func TestBuildInfoText(t *testing.T) {
	cases := []struct {
		name string
		info buildInfo
		want string
	}{
		{"release", resolveBuildInfo("otprobe", "0.5.0", "v0.5.0", sha, "2026-11-05T15:41:49Z", nil),
			"otprobe 0.5.0 (tag v0.5.0, commit " + sha + ", built 2026-11-05T15:41:49Z, " + goPlatform + ")"},
		{"leading v stripped", resolveBuildInfo("otprobe", "v0.5.0", "v0.5.0", sha, "2026-11-05T15:41:49Z", nil),
			"otprobe 0.5.0 (tag v0.5.0, commit " + sha + ", built 2026-11-05T15:41:49Z, " + goPlatform + ")"},
		{"no tag", resolveBuildInfo("otprobe", "0.5.0-3-gabc", "", sha, "2026-11-05T15:41:49Z", nil),
			"otprobe 0.5.0-3-gabc (commit " + sha + ", built 2026-11-05T15:41:49Z, " + goPlatform + ")"},
		{"nothing injected", resolveBuildInfo("otprobe", "dev", "", "unknown", "unknown", nil),
			"otprobe dev (commit unknown, built unknown, " + goPlatform + ")"},
		{"empty injected", resolveBuildInfo("otprobe", "", "", "", "", nil),
			"otprobe dev (commit unknown, built unknown, " + goPlatform + ")"},
	}
	for _, c := range cases {
		if got := c.info.Text(); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
}

func TestBuildInfoFromGo(t *testing.T) {
	dirty := &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: []debug.BuildSetting{
		{Key: "vcs.revision", Value: sha}, {Key: "vcs.modified", Value: "true"}}}
	if got, want := resolveBuildInfo("otprobe", "dev", "", "unknown", "unknown", dirty).Text(),
		"otprobe dev (commit "+sha+"-dirty, built unknown, "+goPlatform+")"; got != want {
		t.Errorf("go build:\n got %s\nwant %s", got, want)
	}
	dirtyPseudo := &debug.BuildInfo{Main: debug.Module{Version: "v0.4.1-0.20261107101010-1802d0f9afe8+dirty"}}
	if got := resolveBuildInfo("otprobe", "dev", "", "", "", dirtyPseudo).Version; got != "dev" {
		t.Errorf("+dirty pseudo-version: %q, want dev", got)
	}
	installed := &debug.BuildInfo{Main: debug.Module{Version: "v0.5.0"}, Settings: []debug.BuildSetting{
		{Key: "vcs.revision", Value: sha}, {Key: "vcs.modified", Value: "false"}}}
	info := resolveBuildInfo("otprobe", "dev", "", "unknown", "unknown", installed)
	if info.Version != "0.5.0" || info.Commit != sha {
		t.Errorf("go install @v0.5.0: %+v", info)
	}
	// Injected values win over the Go build information.
	if info := resolveBuildInfo("otprobe", "0.6.0", "v0.6.0", "abc", "2026-11-05T15:41:49Z", installed); info.Version != "0.6.0" || info.Commit != "abc" {
		t.Errorf("injected: %+v", info)
	}
}

func TestBuildInfoJSON(t *testing.T) {
	got := resolveBuildInfo("otprobe", "0.5.0", "v0.5.0", sha, "2026-11-05T15:41:49Z", nil).JSON()
	want := `{"name":"otprobe","version":"0.5.0","tag":"v0.5.0","commit":"` + sha + `","built":"2026-11-05T15:41:49Z","go":"` +
		runtime.Version() + `","platform":"` + runtime.GOOS + "/" + runtime.GOARCH + `"}`
	if got != want {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
	got = resolveBuildInfo("otprobe", "", "", "", "", nil).JSON()
	if !strings.HasPrefix(got, `{"name":"otprobe","version":"dev","tag":"","commit":"unknown","built":"unknown","go":"`) {
		t.Errorf("dev: %s", got)
	}
}

// TestEveryFlagCompletes fails when a flag that takes a value has no
// completion function: enums complete their values, free values complete
// nothing (no file names).
func TestEveryFlagCompletes(t *testing.T) {
	root := &cobra.Command{Use: "otprobe"}
	root.AddCommand(detectCommand(nil, nil), listCommand(nil), versionCommand(nil), completionCommand(root, nil))
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if f.NoOptDefVal != "" || f.Name == "help" {
				return // a boolean
			}
			if _, ok := c.GetFlagCompletionFunc(f.Name); !ok {
				t.Errorf("%s --%s has no completion function", c.CommandPath(), f.Name)
			}
		})
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)
}
