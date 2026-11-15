// SPDX-License-Identifier: MIT

package modbus

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
	"github.com/otfabric/go-otfp/internal/mbap"
)

// The limits of SECURITY.md for Modbus: an ADU is at most mbap.MaxADU
// octets, and a larger declared length is not an ADU; Read Device
// Identification is followed for at most maxPages responses, however long
// the device says that more follows.
func TestLimits(t *testing.T) {
	adu := func(length uint16, have int) []byte {
		b := make([]byte, have)
		binary.BigEndian.PutUint16(b, probeTID)
		binary.BigEndian.PutUint16(b[4:], length)
		b[6], b[7] = 1, mbap.FCEncapsulated
		return b
	}
	// page is a Read Device Identification response with one object of 200
	// octets and "more follows".
	page := func(object byte) []byte {
		pdu := []byte{mbap.FCEncapsulated, mbap.MEIReadDeviceID, readRegular, 0x82, 0xFF, object + 1, 1, object, 200}
		return mbap.Request(probeTID, 1, append(pdu, bytes.Repeat([]byte{'x'}, 200)...)...)
	}
	var pages [][]byte
	for i := range 2 * maxPages {
		pages = append(pages, page(byte(0x80+i)))
	}
	notMatched := func(t *testing.T, r core.Result, err error) {
		t.Helper()
		if err != nil || r.Matched {
			t.Errorf("%v (err %v), want no match", r, err)
		}
	}
	const base = 64 << 10 // what a probe allocates without reading a frame
	fuzzkit.Limits(t, New(),
		fuzzkit.Limit{Name: "an ADU of MaxADU octets", Replies: [][]byte{adu(mbap.MaxADU-6, mbap.MaxADU)}, Budget: base + 8*mbap.MaxADU},
		fuzzkit.Limit{Name: "a declared length of MaxADU-6+1", Replies: [][]byte{adu(mbap.MaxADU-6+1, mbap.MaxADU+1)},
			Budget: base + 8*mbap.MaxADU, Want: notMatched},
		fuzzkit.Limit{Name: "the largest declared length", Replies: [][]byte{adu(0xFFFF, 0xFFFF)},
			Budget: base + 8*mbap.MaxADU, Want: notMatched},
		fuzzkit.Limit{Name: "more follows on every page", Mode: core.ModeIdentify, Replies: pages,
			Budget: base + maxPages*16*mbap.MaxADU,
			Want: func(t *testing.T, r core.Result, err error) {
				t.Helper()
				want := fmt.Sprintf("device identification: %d objects", maxPages)
				if err != nil || !r.Matched || r.Evidence[len(r.Evidence)-1] != want {
					t.Errorf("%v (err %v), evidence %q; want %q", r, err, r.Evidence, want)
				}
			}},
	)
}
