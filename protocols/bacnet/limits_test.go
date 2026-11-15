// SPDX-License-Identifier: MIT

package bacnet

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// The limits of SECURITY.md for BACnet/IP: one datagram of at most maxUDP
// octets is read per answer; a larger one is cut by the read and is not a
// BVLC frame, since its length no longer matches.
func TestLimits(t *testing.T) {
	frame := func(n int) []byte {
		b := make([]byte, n)
		b[0], b[1] = bvlcType, bvlcUnicastNPDU
		binary.BigEndian.PutUint16(b[2:], uint16(n))
		b[4], b[5], b[6] = npduVersion, 0x00, apduSimpleACK
		b[7], b[8] = 1, svcReadProperty
		return b
	}
	const budget = 64<<10 + 4*maxUDP
	const timeout = 100 * time.Millisecond
	fuzzkit.Limits(t, New(),
		fuzzkit.Limit{Name: "a datagram of maxUDP octets", Replies: [][]byte{frame(maxUDP)}, Budget: budget, Timeout: timeout,
			Want: func(t *testing.T, r core.Result, err error) {
				t.Helper()
				if err != nil || r.Confidence != core.ConfidenceHigh {
					t.Errorf("%v (err %v), want the SimpleACK judged", r, err)
				}
			}},
		fuzzkit.Limit{Name: "a datagram of maxUDP+1 octets", Replies: [][]byte{frame(maxUDP + 1), frame(maxUDP + 1)}, Budget: budget, Timeout: timeout,
			Want: func(t *testing.T, r core.Result, err error) {
				t.Helper()
				if err != nil || r.Matched {
					t.Errorf("%v (err %v), want no match", r, err)
				}
			}},
		fuzzkit.Limit{Name: "a datagram of 8192 octets", Replies: [][]byte{frame(8192), frame(8192)}, Budget: budget, Timeout: timeout},
	)
}
