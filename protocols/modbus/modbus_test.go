// SPDX-License-Identifier: MIT

package modbus

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/mbap"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// device answers like a Modbus server with the given identification
// objects, split into pages of perPage objects.
func device(objs [][2]string, perPage int, supportFC43 bool) testsrv.Handler {
	return func(req []byte) ([]byte, bool) {
		if len(req) < 8 {
			return nil, true
		}
		tid := uint16(req[0])<<8 | uint16(req[1])
		unit, fc := req[6], req[7]
		switch {
		case fc == mbap.FCEncapsulated && supportFC43:
			start := int(req[10])
			end := min(start+perPage, len(objs))
			more, next := byte(0), byte(0)
			if end < len(objs) {
				more, next = 0xFF, byte(end)
			}
			pdu := []byte{fc, 0x0E, req[9], 0x82, more, next, byte(end - start)}
			for i := start; i < end; i++ {
				pdu = append(pdu, byte(i), byte(len(objs[i][1])))
				pdu = append(pdu, objs[i][1]...)
			}
			return mbap.Request(tid, unit, pdu...), false
		case fc == mbap.FCReadHoldingRegisters:
			return mbap.Request(tid, unit, fc, 2, 0x12, 0x34), false
		case fc == mbap.FCEncapsulated:
			return nil, true // close, like NModbus
		}
		return mbap.Request(tid, unit, fc|0x80, 0x01), false
	}
}

var objects = [][2]string{
	{"0", "otfabric"}, {"1", "MBI-BASELINE"}, {"2", "1.0"}, {"3", "https://otfabric.io"},
	{"4", "Interop Server"}, {"5", "IS-1"}, {"6", "baseline"},
}

func TestDetectIdentify(t *testing.T) {
	target := testsrv.TCP(t, device(objects, 3, true))
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify, Trace: true})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Matched || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("result %v", r)
	}
	id := r.Identity
	if id == nil || id.Vendor != "otfabric" || id.Product != "Interop Server" || id.Model != "IS-1" ||
		id.Version != "1.0" || id.Attributes["productCode"] != "MBI-BASELINE" ||
		id.Attributes["userApplicationName"] != "baseline" || id.Attributes["vendorUrl"] != "https://otfabric.io" {
		t.Fatalf("identity %+v", id)
	}
	if len(r.Exchanges) != 3 {
		t.Fatalf("%d exchanges, want 3 pages", len(r.Exchanges))
	}
	if r.Fingerprint == nil || r.Fingerprint.Signature != "fc=0x2b;resp=normal;unit=1;conf=0x82" {
		t.Fatalf("fingerprint %v", r.Fingerprint)
	}
}

func TestDetectModeNoIdentity(t *testing.T) {
	target := testsrv.TCP(t, device(objects, 10, true))
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || !r.Matched {
		t.Fatalf("%v %v", r, err)
	}
	// Basic category still yields what came back.
	if r.Identity == nil || r.Identity.Vendor != "otfabric" {
		t.Fatalf("identity %+v", r.Identity)
	}
}

func TestDetectException(t *testing.T) {
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) {
		return mbap.Request(uint16(req[0])<<8|uint16(req[1]), req[6], req[7]|0x80, 0x01), false
	})
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v %v", r, err)
	}
	if r.Identity != nil {
		t.Fatalf("identity from an exception: %+v", r.Identity)
	}
}

func TestRegularFallsBackToBasic(t *testing.T) {
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) {
		tid := uint16(req[0])<<8 | uint16(req[1])
		if req[9] == readRegular {
			return mbap.Request(tid, req[6], 0xAB, 0x03), false
		}
		return mbap.Request(tid, req[6], 0x2B, 0x0E, 0x01, 0x01, 0, 0, 1, 0, 4, 'A', 'c', 'm', 'e'), false
	})
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
	if err != nil || r.Identity == nil || r.Identity.Vendor != "Acme" {
		t.Fatalf("%v %v", r, err)
	}
}

func TestClosesOnFC43(t *testing.T) {
	target := testsrv.TCP(t, device(nil, 1, false))
	// Passive only: the close is all we learn.
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || r.Matched {
		t.Fatalf("passive: %v %v", r, err)
	}
	r, err = New().Detect(context.Background(), target, core.Options{MaxIntrusiveness: core.ReadOnly, Trace: true})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("read-only: %v %v", r, err)
	}
	if len(r.Exchanges) != 2 {
		t.Fatalf("%d exchanges", len(r.Exchanges))
	}
}

func TestNotModbus(t *testing.T) {
	cases := map[string][]byte{
		"http":      []byte("HTTP/1.1 400 Bad Request\r\n\r\n"),
		"wrong pid": {0x4F, 0x54, 0x00, 0x01, 0x00, 0x03, 0x01, 0x2B, 0x00},
		"wrong tid": mbap.Request(0x1111, 1, 0x2B, 0x0E, 0x01, 0x01, 0, 0, 0),
		"wrong fc":  mbap.Request(probeTID, 1, 0x03, 0x02, 0, 0),
		"bad exc":   mbap.Request(probeTID, 1, 0xAB, 0x55),
	}
	for name, resp := range cases {
		t.Run(name, func(t *testing.T) {
			target := testsrv.TCP(t, testsrv.Script(resp))
			r, err := New().Detect(context.Background(), target, core.Options{})
			if err != nil || r.Matched {
				t.Fatalf("%v %v", r, err)
			}
		})
	}
}

func TestTimeoutAndRefused(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script())
	target.Timeout = 200 * time.Millisecond
	_, err := New().Detect(context.Background(), target, core.Options{})
	var te *core.TimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("silent: %v", err)
	}
	_, err = New().Detect(context.Background(), testsrv.Closed(t), core.Options{})
	var ce *core.ConnectionError
	if !errors.As(err, &ce) || !ce.Refused() {
		t.Fatalf("closed: %v", err)
	}
}

func TestUnitConfig(t *testing.T) {
	if NewWithConfig(Config{UnitIDSet: true}).unit != 0 || New().unit != 1 || NewWithConfig(Config{UnitID: 7}).unit != 7 {
		t.Fatal("unit selection")
	}
	if New().Info().Protocol != core.ProtocolModbus {
		t.Fatal("info")
	}
}

func FuzzParseDeviceID(f *testing.F) {
	f.Add([]byte{0x0E, 0x01, 0x01, 0, 0, 1, 0, 4, 'A', 'c', 'm', 'e'})
	f.Add([]byte{0x0E, 0x01, 0x01, 0xFF, 3, 9, 0, 200})
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := parseDeviceID(b)
		if err == nil {
			fillIdentity(&core.Identity{}, d.objects)
		}
	})
}
