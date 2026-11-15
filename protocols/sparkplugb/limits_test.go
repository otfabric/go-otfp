// SPDX-License-Identifier: MIT

package sparkplugb

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
	"github.com/otfabric/go-otfp/protocols/mqtt"
)

// The limits of SECURITY.md for Sparkplug B: an MQTT packet of at most
// MaxPacket octets is read, a larger one is not read; at most
// DefaultMaxMessages messages are read in one window, and each list of the
// identity holds at most maxIDs entries.
func TestLimits(t *testing.T) {
	suback := pkt(0x90, []byte{0, 1, 0, 0, 0, 0})
	unsuback := pkt(0xB0, []byte{0, 2})
	// publishOf is a PUBLISH on a node topic whose fixed header declares a
	// packet of total octets, with a payload that is not a Sparkplug B one.
	publishOf := func(total int) []byte {
		const topic = "spBv1.0/g/NBIRTH/e"
		b := mqtt.AppendVarint([]byte{mqtt.TypePublish << 4}, total-4) // a three-octet length
		b = append(b, str(topic)...)
		return append(b, make([]byte, total-len(b))...)
	}
	var many []byte
	for i := range DefaultMaxMessages + 44 {
		many = append(many, pub(fmt.Sprintf("spBv1.0/g%d/NDATA/e", i), birth(0), false)...)
	}
	fp := &Fingerprinter{Window: 300 * time.Millisecond}
	session := func(after []byte) [][]byte {
		return [][]byte{accept(mqtt.Level311), append(append([]byte(nil), suback...), after...), unsuback}
	}
	confidence := func(want core.Confidence, evidence string) func(*testing.T, core.Result, error) {
		return func(t *testing.T, r core.Result, err error) {
			t.Helper()
			if err != nil || r.Confidence != want || !hasEvidence(r, evidence) {
				t.Errorf("%v (err %v), evidence %q; want confidence %.2f and %q", r, err, r.Evidence, want, evidence)
			}
		}
	}
	fuzzkit.Limits(t, fp,
		fuzzkit.Limit{Name: "a packet of MaxPacket octets", Replies: session(publishOf(MaxPacket)),
			Budget: 64<<10 + 8*MaxPacket, Want: confidence(core.ConfidenceMedium, "not a Sparkplug B payload")},
		fuzzkit.Limit{Name: "a declared packet of MaxPacket+1", Replies: session(publishOf(MaxPacket + 1)),
			Budget: 256 << 10, Want: confidence(core.ConfidenceMedium, "larger than")},
		fuzzkit.Limit{Name: "DefaultMaxMessages+44 messages", Mode: core.ModeIdentify, Replies: session(many),
			Budget: 64<<10 + uint64(16*len(many)),
			Want: func(t *testing.T, r core.Result, err error) {
				t.Helper()
				if err != nil || !r.Matched || r.Identity == nil {
					t.Fatalf("%v (err %v)", r, err)
				}
				if got := r.Identity.Attributes["messages"]; got != strconv.Itoa(DefaultMaxMessages) {
					t.Errorf("%s messages read, want %d", got, DefaultMaxMessages)
				}
				want := fmt.Sprintf("(+%d more)", DefaultMaxMessages-maxIDs)
				if got := r.Identity.Attributes["groups"]; len(got) < len(want) || got[len(got)-len(want):] != want {
					t.Errorf("groups %q, want %d listed and %s", got, maxIDs, want)
				}
			}},
	)
}
