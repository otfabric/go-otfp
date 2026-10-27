// SPDX-License-Identifier: MIT

package sunspec

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/mbap"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

func regsOf(s string, n int) []uint16 {
	b := make([]byte, 2*n)
	copy(b, s)
	out := make([]uint16, n)
	for i := range out {
		out[i] = binary.BigEndian.Uint16(b[2*i:])
	}
	return out
}

// device serves a SunSpec map at base through function fc: marker, common
// model, an inverter model 101 of length 50, end model.
func device(base uint16, fc byte) testsrv.Handler {
	m := map[uint32]uint16{}
	put := func(a uint32, v ...uint16) {
		for i, x := range v {
			m[a+uint32(i)] = x
		}
	}
	a := uint32(base)
	put(a, marker0, marker1, 1, 66)
	put(a+4, regsOf("OT Fabric", 16)...)
	put(a+20, regsOf("Inverter 5000", 16)...)
	put(a+36, regsOf("opt", 8)...)
	put(a+44, regsOf("3.1.4", 8)...)
	put(a+52, regsOf("SN-0042", 16)...)
	put(a+68, 1, 0x8000)
	put(a+70, 101, 50)
	put(a+122, endModel, 0)
	return func(req []byte) ([]byte, bool) {
		tid := binary.BigEndian.Uint16(req)
		if req[7] != fc {
			return mbap.Request(tid, req[6], req[7]|0x80, 0x01), false
		}
		addr := binary.BigEndian.Uint16(req[8:])
		qty := binary.BigEndian.Uint16(req[10:])
		pdu := []byte{fc, byte(2 * qty)}
		for i := uint32(0); i < uint32(qty); i++ {
			v, ok := m[uint32(addr)+i]
			if !ok {
				return mbap.Request(tid, req[6], fc|0x80, 0x02), false
			}
			pdu = binary.BigEndian.AppendUint16(pdu, v)
		}
		return mbap.Request(tid, req[6], pdu...), false
	}
}

func TestDetectIdentify(t *testing.T) {
	target := testsrv.TCP(t, device(40000, 0x03))
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v %v", r, err)
	}
	id := r.Identity
	if id.Vendor != "OT Fabric" || id.Model != "Inverter 5000" || id.Version != "3.1.4" || id.Serial != "SN-0042" ||
		id.Attributes["options"] != "opt" || id.Attributes["deviceAddress"] != "1" || id.Attributes["models"] != "1,101,end" {
		t.Fatalf("identity %+v", id)
	}
	if r.Fingerprint.Signature != "base=40000;fc=0x03;models=1,101,end" {
		t.Fatalf("signature %q", r.Fingerprint.Signature)
	}
}

func TestOtherBaseAndInputRegisters(t *testing.T) {
	target := testsrv.TCP(t, device(50000, 0x04))
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || !r.Matched || r.Variant != "base 50000" || r.Fingerprint.Metadata["baseAddress"] != "50000" {
		t.Fatalf("%v %v", r, err)
	}
}

func TestPlainModbusIsNotSunSpec(t *testing.T) {
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) {
		return mbap.Request(binary.BigEndian.Uint16(req), req[6], req[7], 4, 0, 0, 0, 0), false
	})
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || r.Matched || len(r.Evidence) == 0 {
		t.Fatalf("%v %v", r, err)
	}
	if New().Info().Refines != core.ProtocolModbus {
		t.Fatal("refines")
	}
}

func TestNotModbus(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script([]byte("HTTP/1.0 400\r\n\r\n")))
	target.Timeout = 300 * time.Millisecond
	r, _ := New().Detect(context.Background(), target, core.Options{})
	if r.Matched {
		t.Fatalf("%v", r)
	}
	r, err := New().Detect(context.Background(), testsrv.Closed(t), core.Options{})
	if err == nil || r.Matched {
		t.Fatalf("closed: %v %v", r, err)
	}
}

func FuzzCommon(f *testing.F) {
	f.Add([]byte("OT Fabric"))
	f.Fuzz(func(t *testing.T, b []byte) {
		regs := make([]uint16, len(b)/2)
		for i := range regs {
			regs[i] = binary.BigEndian.Uint16(b[2*i:])
		}
		_ = Common(regs)
	})
}
