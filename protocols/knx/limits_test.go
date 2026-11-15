// SPDX-License-Identifier: MIT

package knx

import (
	"encoding/binary"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// The limits of SECURITY.md for KNXnet/IP: a frame of at most maxFrame
// octets is read over TCP, and one datagram of at most maxFrame octets over
// UDP; a larger declared length is not a KNXnet/IP frame.
func TestLimits(t *testing.T) {
	frame := func(length uint16, have int) []byte {
		b := make([]byte, have)
		b[0], b[1] = headerLen, version10
		binary.BigEndian.PutUint16(b[2:], 0x0204) // DESCRIPTION_RESPONSE
		binary.BigEndian.PutUint16(b[4:], length)
		return b
	}
	notMatched := func(t *testing.T, r core.Result, err error) {
		t.Helper()
		if err != nil || r.Matched {
			t.Errorf("%v (err %v), want no match", r, err)
		}
	}
	fuzzkit.Limits(t, NewTCP(),
		fuzzkit.Limit{Name: "tcp: a frame of maxFrame octets", Replies: [][]byte{frame(maxFrame, maxFrame)},
			Budget: 64<<10 + 8*maxFrame, Want: notMatched},
		fuzzkit.Limit{Name: "tcp: a declared length of maxFrame+1", Replies: [][]byte{frame(maxFrame+1, maxFrame+1)},
			Budget: 64<<10 + 8*maxFrame, Want: notMatched},
		fuzzkit.Limit{Name: "tcp: the largest declared length", Replies: [][]byte{frame(0xFFFF, 0xFFFF)},
			Budget: 64<<10 + 8*maxFrame, Want: notMatched},
	)
	fuzzkit.Limits(t, New(),
		fuzzkit.Limit{Name: "udp: a datagram of maxFrame octets", Replies: [][]byte{frame(maxFrame, maxFrame)},
			Budget: 64<<10 + 8*maxFrame, Want: notMatched},
		fuzzkit.Limit{Name: "udp: a datagram larger than maxFrame", Replies: [][]byte{frame(8192, 8192)},
			Budget: 64<<10 + 8*maxFrame, Want: notMatched},
	)
}
