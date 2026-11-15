// SPDX-License-Identifier: MIT

package dnp3

import (
	"bytes"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// The limits of SECURITY.md for DNP3: a frame is at most maxFrame octets
// (LENGTH is one octet); detection reads at most maxFrames frames that are
// not the link status, identify at most 32 frames within identifyBudget
// timeouts.
func TestLimits(t *testing.T) {
	other := Frame(ctrlDIR|ctrlPRM|fcUnconfirmedData, 1, 20, bytes.Repeat([]byte{0xAA}, maxFrameData)) // another station's frame, the largest
	if len(other) != maxFrame {
		t.Fatalf("the largest frame has %d octets, want %d", len(other), maxFrame)
	}
	status := Frame(fcLinkStatus, 1, 10, nil)
	fragment := Frame(ctrlPRM|fcUnconfirmedData, 1, 10, append([]byte{0x00}, bytes.Repeat([]byte{0xBB}, maxFrameData-1)...)) // neither FIR nor FIN
	// What a probe allocates without reading a frame, and a few times the
	// frames it may read.
	budget := func(frames int) uint64 { return 64<<10 + uint64(frames)*8*maxFrame }
	fuzzkit.Limits(t, New(),
		fuzzkit.Limit{Name: "maxFrames frames of maxFrame octets, then the link status",
			Replies: [][]byte{append(bytes.Repeat(other, maxFrames-1), status...)}, Budget: budget(maxFrames),
			Want: func(t *testing.T, r core.Result, err error) {
				t.Helper()
				if err != nil || r.Confidence != core.ConfidenceCertain {
					t.Errorf("%v (err %v), want the link status found within maxFrames frames", r, err)
				}
			}},
		fuzzkit.Limit{Name: "maxFrames+1 frames before the link status",
			Replies: [][]byte{append(bytes.Repeat(other, maxFrames), status...)}, Budget: budget(maxFrames),
			Want: func(t *testing.T, r core.Result, err error) {
				t.Helper()
				if err != nil || r.Confidence >= core.ConfidenceCertain {
					t.Errorf("%v (err %v), want reading stopped before the link status", r, err)
				}
			}},
		fuzzkit.Limit{Name: "identify: 64 fragments without an end", Mode: core.ModeIdentify,
			Replies: [][]byte{status, bytes.Repeat(fragment, 64)}, Budget: budget(32),
			Want: func(t *testing.T, r core.Result, err error) {
				t.Helper()
				if err != nil || !r.Matched {
					t.Errorf("%v (err %v), want the outstation matched", r, err)
				}
			}},
	)
}
