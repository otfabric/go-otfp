// SPDX-License-Identifier: MIT

package ieee2030

import (
	"bytes"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// The limits of SECURITY.md for IEEE 2030.5: the server's flight is read
// for at most maxRecords records and maxHandshake octets of handshake
// messages, each record read being at most maxFlight octets; a flight
// beyond that is not a TLS hello flight.
func TestLimits(t *testing.T) {
	small := record(recHandshake, hsMsg(4, nil)) // a message the probe skips
	// A handshake message that announces the largest length, carried in
	// records of 16 KiB.
	announced := append([]byte{hsCertificate, 0xFF, 0xFF, 0xFF}, make([]byte, 16<<10-4)...)
	huge := record(recHandshake, announced)
	for range 2 * maxHandshake / (16 << 10) {
		huge = append(huge, record(recHandshake, make([]byte, 16<<10))...)
	}
	notMatched := func(t *testing.T, r core.Result, err error) {
		t.Helper()
		if err != nil || r.Matched {
			t.Errorf("%v (err %v), want no match", r, err)
		}
	}
	fuzzkit.Limits(t, New(),
		fuzzkit.Limit{Name: "maxRecords+1 records", Replies: [][]byte{bytes.Repeat(small, maxRecords+1)},
			Budget: uint64(64<<10 + 8*(maxRecords+1)*len(small) + 2*maxFlight), Want: notMatched},
		fuzzkit.Limit{Name: "ten times maxRecords records", Replies: [][]byte{bytes.Repeat(small, 10*maxRecords)},
			Budget: uint64(64<<10 + 8*(maxRecords+1)*len(small) + 2*maxFlight), Want: notMatched},
		fuzzkit.Limit{Name: "a handshake message of 2^24-1 octets", Replies: [][]byte{huge},
			Budget: 64<<10 + 8*(maxHandshake+maxFlight), Want: notMatched},
		fuzzkit.Limit{Name: "a record of the largest length", Replies: [][]byte{record(recHandshake, make([]byte, 0xFFFF))},
			Budget: 64<<10 + 8*maxFlight, Want: notMatched},
	)
}
