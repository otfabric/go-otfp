// SPDX-License-Identifier: MIT

package canopen

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

func TestChaos(t *testing.T) {
	server := func(t testing.TB, cfg chaos.Config) core.Target { return chaos.TCP(t, cfg, canopennode().handle) }
	t.Run("passive", chaos.Suite{FP: NewWithConfig(Config{Node: 32}), TCP: server}.Run)
	t.Run("read-only", chaos.Suite{
		FP: NewWithConfig(Config{Node: 32}), TCP: server,
		Options: core.Options{MaxIntrusiveness: core.ReadOnly},
		// info version and seven SDO uploads, each of which a stalled
		// gateway can hold for a timeout.
		Exchanges: 9,
	}.Run)
}

var (
	infoVersion = regexp.MustCompile(`^\[[0-9]+\] info version$`)
	sdoUpload   = regexp.MustCompile(`^\[[0-9]+\] ([0-9]{1,3} )?r 0x[0-9A-F]{4} [0-9]{1,3} (u32|vs)$`)
)

// The safety contract: "info version", and SDO uploads ("r") of the
// identity objects only when read-only probes are allowed. Never a
// download (w/write), set, start, stop, preop, reset, or any lss_ command.
func TestSafetyContract(t *testing.T) {
	for _, node := range []int{0, 32} {
		for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
			for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
				rec := &chaos.Recorder{}
				target := testsrv.TCP(t, rec.Wrap(canopennode().handle))
				if _, err := NewWithConfig(Config{Node: node}).Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: level}); err != nil {
					t.Fatal(err)
				}
				var lines []string
				for _, req := range rec.Requests() {
					for _, l := range strings.Split(string(req), "\n") {
						if l = strings.TrimRight(l, "\r"); l != "" {
							lines = append(lines, l)
						}
					}
				}
				if len(lines) == 0 {
					t.Fatal("nothing sent")
				}
				reads := 0
				for _, l := range lines {
					switch {
					case infoVersion.MatchString(l):
					case sdoUpload.MatchString(l):
						reads++
					default:
						t.Fatalf("node %d %s/%s: sent %q", node, mode, level, l)
					}
				}
				if reads > 0 && (level < core.ReadOnly || mode == core.ModeDetect) {
					t.Fatalf("node %d %s/%s: %d SDO uploads", node, mode, level, reads)
				}
			}
		}
	}
}

// Error paths of the number parsers.
func TestParseNumberEdges(t *testing.T) {
	for _, s := range []string{"0x123456789", "0xZZ", "0x"} {
		if _, ok := parseNumber(s); ok {
			t.Fatalf("%q parsed", s)
		}
	}
	if v, ok := parseNumber("0xFF"); !ok || v != 0xFF {
		t.Fatal("0xFF")
	}
}
