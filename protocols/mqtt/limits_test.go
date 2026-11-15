// SPDX-License-Identifier: MIT

package mqtt

import (
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// publishOf returns a PUBLISH whose fixed header declares a packet of total
// octets and that carries have octets in all.
func publishOf(total, have int) []byte {
	head := AppendVarint([]byte{TypePublish << 4}, total-4) // 1 + a three-octet length + the rest
	b := make([]byte, have)
	copy(b, head)
	copy(b[len(head):], []byte{0, 1, 't'})
	return b
}

// The limits of SECURITY.md for MQTT: a packet of at most DefaultMaxPacket
// octets is read; a larger declared packet is not read, and its size is not
// allocated.
func TestLimits(t *testing.T) {
	confidence := func(want core.Confidence) func(*testing.T, core.Result, error) {
		return func(t *testing.T, r core.Result, err error) {
			t.Helper()
			if err != nil || r.Confidence != want {
				t.Errorf("confidence %.2f (err %v), want %.2f: %v", r.Confidence, err, want, r)
			}
		}
	}
	largest := append([]byte{TypePublish << 4}, 0xFF, 0xFF, 0xFF, 0x7F) // remaining length 268435455
	fuzzkit.Limits(t, New(),
		fuzzkit.Limit{Name: "a packet of DefaultMaxPacket octets", Replies: [][]byte{publishOf(DefaultMaxPacket, DefaultMaxPacket)},
			Budget: 8 * DefaultMaxPacket, Want: confidence(core.ConfidenceLow)}, // a PUBLISH before CONNACK: a hint
		fuzzkit.Limit{Name: "a declared packet of DefaultMaxPacket+1", Replies: [][]byte{publishOf(DefaultMaxPacket+1, DefaultMaxPacket+1)},
			Budget: 128 << 10, Want: confidence(0)},
		fuzzkit.Limit{Name: "the largest remaining length", Replies: [][]byte{append(largest, make([]byte, 64<<10)...)},
			Budget: 128 << 10, Want: confidence(0)},
		fuzzkit.Limit{Name: "a remaining length of five octets", Replies: [][]byte{{TypePublish << 4, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0, 0}},
			Budget: 128 << 10, Want: confidence(0)},
	)
}
