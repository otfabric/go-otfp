// SPDX-License-Identifier: MIT

package enip

import (
	"encoding/binary"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// The limits of SECURITY.md for EtherNet/IP: an encapsulation message of at
// most maxFrame octets is read over TCP; a larger declared length is not an
// encapsulation message.
func TestLimits(t *testing.T) {
	message := func(length uint16, have int) []byte {
		b := make([]byte, have)
		binary.LittleEndian.PutUint16(b[0:], cmdListIdentity)
		binary.LittleEndian.PutUint16(b[2:], length)
		return b
	}
	notMatched := func(t *testing.T, r core.Result, err error) {
		t.Helper()
		if err != nil || r.Matched {
			t.Errorf("%v (err %v), want no match", r, err)
		}
	}
	fuzzkit.Limits(t, New(),
		fuzzkit.Limit{Name: "a message of maxFrame octets", Replies: [][]byte{message(maxFrame-headerLen, maxFrame)},
			Budget: 8 * maxFrame},
		fuzzkit.Limit{Name: "a declared length of maxFrame-headerLen+1", Replies: [][]byte{message(maxFrame-headerLen+1, maxFrame+1)},
			Budget: 128 << 10, Want: notMatched},
		fuzzkit.Limit{Name: "the largest declared length", Replies: [][]byte{message(0xFFFF, 0xFFFF+headerLen)},
			Budget: 128 << 10, Want: notMatched},
	)
}
