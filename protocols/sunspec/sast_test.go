// SPDX-License-Identifier: MIT

package sunspec

import (
	"context"
	"encoding/binary"
	"sync/atomic"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/mbap"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// With the marker in the last two registers (base 0xFFFE), the common
// model address 0x10000 used to wrap to 0, and identify read and reported
// whatever the device holds at register 0.
func TestMarkerAtTopOfRegisterSpace(t *testing.T) {
	m := map[uint16]uint16{0xFFFE: marker0, 0xFFFF: marker1, 0: commonModel, 1: 66}
	for i, v := range regsOf("Wrong vendor", 16) {
		m[uint16(2+i)] = v
	}
	var readZero atomic.Bool
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) {
		tid := binary.BigEndian.Uint16(req)
		addr := binary.BigEndian.Uint16(req[8:])
		qty := binary.BigEndian.Uint16(req[10:])
		if addr == 0 {
			readZero.Store(true)
		}
		pdu := []byte{req[7], byte(2 * qty)}
		for i := range qty {
			v, ok := m[addr+i]
			if !ok {
				return mbap.Request(tid, req[6], req[7]|0x80, 0x02), false
			}
			pdu = binary.BigEndian.AppendUint16(pdu, v)
		}
		return mbap.Request(tid, req[6], pdu...), false
	})
	f := NewWithConfig(Config{Bases: []uint16{0xFFFE}})
	r, err := f.Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify, MaxIntrusiveness: core.ReadOnly})
	if err != nil || !r.Matched {
		t.Fatalf("%v %v", r, err)
	}
	if readZero.Load() || (r.Identity != nil && r.Identity.Vendor != "") {
		t.Fatalf("read register 0: identity %+v", r.Identity)
	}
}
