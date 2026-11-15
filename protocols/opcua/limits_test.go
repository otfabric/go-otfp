// SPDX-License-Identifier: MIT

package opcua

import (
	"encoding/binary"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// sized returns a UACP message of the given type whose header declares
// size octets and that carries have octets in all.
func sized(typ string, size uint32, have int) []byte {
	b := make([]byte, have)
	copy(b, typ)
	b[3] = chunkF
	binary.LittleEndian.PutUint32(b[4:], size)
	return b
}

// The limits of SECURITY.md for OPC UA: a message of at most maxFrame
// octets is read; a larger declared size is not a UACP message, and its
// size is not allocated. GetEndpoints holds at most maxEndpoints
// descriptions; a larger count is refused before anything is decoded.
func TestLimits(t *testing.T) {
	matched := func(want bool) func(*testing.T, core.Result, error) {
		return func(t *testing.T, r core.Result, err error) {
			t.Helper()
			if err != nil || r.Matched != want {
				t.Errorf("matched %v (err %v), want %v: %v", r.Matched, err, want, r)
			}
		}
	}
	endpoints := func(n uint32, descriptions int) []byte {
		var eps [][]byte
		for range descriptions {
			eps = append(eps, endpointDescription("urn:a", "urn:p", "n", "urn:policy#None"))
		}
		reply := endpointsReply(eps...)
		// The count sits after the 16-octet security header, the service
		// node identifier and the response header.
		at := 8 + 16 + 4 + len(responseHeader(0))
		binary.LittleEndian.PutUint32(reply[at:], n)
		return reply
	}
	identity := func(want bool) func(*testing.T, core.Result, error) {
		return func(t *testing.T, r core.Result, err error) {
			t.Helper()
			if got := r.Identity != nil; err != nil || !r.Matched || got != want {
				t.Errorf("identity %v (err %v), want %v: %v", got, err, want, r)
			}
		}
	}
	fuzzkit.Limits(t, New(),
		fuzzkit.Limit{Name: "a message of maxFrame octets", Replies: [][]byte{sized(msgACK, maxFrame, maxFrame)},
			Budget: 8 * maxFrame, Want: matched(true)},
		fuzzkit.Limit{Name: "a declared size of maxFrame+1", Replies: [][]byte{sized(msgACK, maxFrame+1, 64<<10)},
			Budget: 256 << 10, Want: matched(false)},
		fuzzkit.Limit{Name: "a declared size of 2^31", Replies: [][]byte{sized(msgACK, 1<<31, 64<<10)},
			Budget: 256 << 10, Want: matched(false)},
		fuzzkit.Limit{Name: "a declared size of 2^32-1", Replies: [][]byte{sized(msgACK, 1<<32-1, 64<<10)},
			Budget: 256 << 10, Want: matched(false)},
		fuzzkit.Limit{Name: "maxEndpoints endpoint descriptions", Mode: core.ModeIdentify,
			Replies: [][]byte{ackFrame, opnReply, endpoints(maxEndpoints, maxEndpoints)},
			Budget:  1 << 20, Want: identity(true)},
		fuzzkit.Limit{Name: "a count of maxEndpoints+1", Mode: core.ModeIdentify,
			Replies: [][]byte{ackFrame, opnReply, endpoints(maxEndpoints+1, maxEndpoints)},
			Budget:  1 << 20, Want: identity(false)},
		fuzzkit.Limit{Name: "a count of 2^31-1", Mode: core.ModeIdentify,
			Replies: [][]byte{ackFrame, opnReply, endpoints(1<<31-1, 1)},
			Budget:  256 << 10, Want: identity(false)},
	)
}
