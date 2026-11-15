// SPDX-License-Identifier: MIT

package mms

import (
	"encoding/binary"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// tpkt returns a TPKT frame whose header declares length octets and that
// carries have octets in all.
func tpkt(length uint16, have int) []byte {
	b := make([]byte, have)
	b[0] = 0x03
	binary.BigEndian.PutUint16(b[2:], length)
	return b
}

// The limits of SECURITY.md for MMS: at most maxFrame octets of one TPKT
// frame are read, whatever length its header declares.
func TestLimits(t *testing.T) {
	notMatched := func(t *testing.T, r core.Result, err error) {
		t.Helper()
		if err != nil || r.Matched {
			t.Errorf("%v (err %v), want no match", r, err)
		}
	}
	fuzzkit.Limits(t, New(),
		fuzzkit.Limit{Name: "a frame of maxFrame octets", Replies: [][]byte{tpkt(maxFrame, maxFrame)},
			Budget: 64<<10 + 8*maxFrame, Want: notMatched},
		fuzzkit.Limit{Name: "a declared length of maxFrame+1", Replies: [][]byte{tpkt(maxFrame+1, maxFrame+1)},
			Budget: 64<<10 + 8*maxFrame, Want: notMatched},
		fuzzkit.Limit{Name: "the largest declared length", Replies: [][]byte{tpkt(0xFFFF, 0xFFFF)},
			Budget: 64<<10 + 8*maxFrame, Want: notMatched},
		fuzzkit.Limit{Name: "the largest declared length after the connection confirm", Mode: core.ModeIdentify,
			Replies: [][]byte{goMMSConfirm, tpkt(0xFFFF, 0xFFFF)},
			Budget:  64<<10 + 8*maxFrame, Want: notMatched},
	)
}
