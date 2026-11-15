// SPDX-License-Identifier: MIT

package iec104

import (
	"bytes"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// The limits of SECURITY.md for IEC 104: an APDU is at most 255 octets (a
// length octet of 253); detection reads at most maxFrames APDUs before the
// TESTFR confirmation. The bounds of the StartDT exchange are in
// TestListeningWindowIsBounded and TestIdentityListsAreBounded.
func TestLimits(t *testing.T) {
	apdu := func(length byte, have int) []byte {
		b := make([]byte, have)
		b[0], b[1] = startByte, length
		return b
	}
	sFrame := []byte{startByte, 0x04, 0x01, 0x00, 0x00, 0x00}
	const budget = 64<<10 + 8*maxFrames*maxAPDU
	fuzzkit.Limits(t, New(),
		fuzzkit.Limit{Name: "an APDU of 255 octets", Replies: [][]byte{apdu(253, 255)}, Budget: budget},
		fuzzkit.Limit{Name: "a length octet of 254", Replies: [][]byte{apdu(254, 4096)}, Budget: budget,
			Want: func(t *testing.T, r core.Result, err error) {
				t.Helper()
				if err != nil || r.Matched {
					t.Errorf("%v (err %v), want no match", r, err)
				}
			}},
		fuzzkit.Limit{Name: "maxFrames-1 APDUs, then the confirmation",
			Replies: [][]byte{append(bytes.Repeat(sFrame, maxFrames-1), U(uTestCon)...)}, Budget: budget,
			Want: func(t *testing.T, r core.Result, err error) {
				t.Helper()
				if err != nil || r.Confidence != core.ConfidenceCertain {
					t.Errorf("%v (err %v), want the confirmation found", r, err)
				}
			}},
		fuzzkit.Limit{Name: "maxFrames APDUs before the confirmation",
			Replies: [][]byte{append(bytes.Repeat(sFrame, maxFrames), U(uTestCon)...)}, Budget: budget,
			Want: func(t *testing.T, r core.Result, err error) {
				t.Helper()
				if err != nil || r.Confidence >= core.ConfidenceCertain {
					t.Errorf("%v (err %v), want reading stopped before the confirmation", r, err)
				}
			}},
	)
}
