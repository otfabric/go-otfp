// SPDX-License-Identifier: MIT

package profinet

import (
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// The limits of SECURITY.md for PROFINET: one datagram of at most maxUDP
// octets is read per answer, whatever the peer sends.
func TestLimits(t *testing.T) {
	datagram := func(n int) []byte {
		b := make([]byte, n)
		b[0], b[1], b[4] = rpcVersion, typeResponse, drepLittle
		return b
	}
	// A reply to another activity is discarded and the probe waits out its
	// timeout: no match, with the timeout as the error.
	notMatched := func(t *testing.T, r core.Result, err error) {
		t.Helper()
		if r.Matched {
			t.Errorf("%v (err %v), want no match", r, err)
		}
	}
	const budget = 64<<10 + 4*maxUDP
	const timeout = 100 * time.Millisecond
	fuzzkit.Limits(t, New(),
		fuzzkit.Limit{Name: "a datagram of maxUDP octets", Replies: [][]byte{datagram(maxUDP)}, Budget: budget, Want: notMatched, Timeout: timeout},
		fuzzkit.Limit{Name: "a datagram of maxUDP+1 octets", Replies: [][]byte{datagram(maxUDP + 1)}, Budget: budget, Want: notMatched, Timeout: timeout},
		fuzzkit.Limit{Name: "a datagram of 8192 octets", Replies: [][]byte{datagram(8192)}, Budget: budget, Want: notMatched, Timeout: timeout},
	)
}
