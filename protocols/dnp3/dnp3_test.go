// SPDX-License-Identifier: MIT

package dnp3

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

func TestCRCVector(t *testing.T) {
	want, _ := hex.DecodeString("056405c001000004e921")
	got := Frame(0xC0, 1, 0x400, nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("frame % x, want % x", got, want)
	}
	// The probe from master 1 to outstation 10 (dnp3ctl's discover).
	if got := hex.EncodeToString(Frame(0xC9, 10, 1, nil)); got != "056405c90a000100feda" {
		t.Fatalf("link status request %s", got)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte{0xAA}, 40)
	f := Frame(0x44, 1, 1024, data)
	if len(f) != FrameLen(f[2]) {
		t.Fatalf("len %d, FrameLen %d", len(f), FrameLen(f[2]))
	}
	h, err := ParseHeader(f)
	if err != nil || !bytes.Equal(h.Data, data) || h.Src != 1024 || h.Dst != 1 {
		t.Fatalf("%+v %v", h, err)
	}
	f[len(f)-1] ^= 1
	if _, err := ParseHeader(f); err == nil {
		t.Fatal("corrupt block CRC accepted")
	}
}

// outstation answers like the interop fixture: address 1024, master 1 only,
// self address not supported.
func outstation(addr uint16, attrs bool) testsrv.Handler {
	return func(req []byte) ([]byte, bool) {
		var out []byte
		for len(req) >= headerLen {
			n := FrameLen(req[2])
			if n < 0 || n > len(req) {
				break
			}
			h, err := ParseHeader(req[:n])
			req = req[n:]
			if err != nil || h.Dst != addr || h.Src != 1 {
				continue
			}
			switch h.Ctrl & 0x0F {
			case fcRequestLinkStatus:
				out = append(out, Frame(fcLinkStatus, h.Src, addr, nil)...)
			case fcUnconfirmedData:
				if !attrs {
					continue
				}
				obj := []byte{0x00, 252, 0x00, 0, 0, 1, 4, 'A', 'c', 'm', 'e',
					0x00, 250, 0x00, 0, 0, 1, 6, 'R', 'T', 'U', '-', '5', '0',
					0x00, 242, 0x00, 0, 0, 1, 5, '2', '.', '1', '.', '0',
					0x00, 248, 0x00, 0, 0, 1, 3, 'S', 'N', '1',
					0x00, 241, 0x00, 0, 0, 2, 2, 0x00, 0x08}
				apdu := append([]byte{0xC0, 0x81, 0x00, 0x00}, obj...)
				// Two transport segments to exercise reassembly.
				out = append(out, Frame(0x44, h.Src, addr, append([]byte{0x40}, apdu[:20]...))...)
				out = append(out, Frame(0x44, h.Src, addr, append([]byte{0x81}, apdu[20:]...))...)
			}
		}
		return out, false
	}
}

func TestDetectAndIdentify(t *testing.T) {
	target := testsrv.TCP(t, outstation(1024, true))
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify, Trace: true})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v %v", r, err)
	}
	if r.Fingerprint.Metadata["outstation"] != "1024" || r.Fingerprint.Metadata["master"] != "1" {
		t.Fatalf("metadata %v", r.Fingerprint.Metadata)
	}
	id := r.Identity
	if id.Vendor != "Acme" || id.Product != "RTU-50" || id.Version != "2.1.0" || id.Serial != "SN1" ||
		id.Attributes["g0v241"] != "2048" || id.Attributes["outstationAddress"] != "1024" {
		t.Fatalf("identity %+v", id)
	}
}

func TestSelfAddress(t *testing.T) {
	target := testsrv.TCP(t, outstation(selfAddress, false))
	r, err := NewWithConfig(Config{Outstations: []uint16{77}}).Detect(context.Background(), target, core.Options{})
	if err != nil || !r.Matched {
		t.Fatalf("%v %v", r, err)
	}
}

func TestSilentOutstation(t *testing.T) {
	target := testsrv.TCP(t, outstation(4242, false)) // not a candidate
	target.Timeout = 200 * time.Millisecond
	r, err := New().Detect(context.Background(), target, core.Options{})
	var te *core.TimeoutError
	if r.Matched || !errors.As(err, &te) {
		t.Fatalf("%v %v", r, err)
	}
}

func TestNotDNP3(t *testing.T) {
	for name, resp := range map[string][]byte{
		"modbus":  {0, 1, 0, 0, 0, 3, 1, 0x83, 1},
		"bad crc": {0x05, 0x64, 0x05, 0x0B, 0x01, 0x00, 0x0A, 0x00, 0x00, 0x00},
	} {
		t.Run(name, func(t *testing.T) {
			target := testsrv.TCP(t, testsrv.Script(resp))
			target.Timeout = 300 * time.Millisecond
			r, _ := New().Detect(context.Background(), target, core.Options{})
			if r.Matched {
				t.Fatalf("%v", r)
			}
		})
	}
}

// A frame with valid CRCs that is not a link status is still DNP3, but
// less certain.
func TestOtherFrames(t *testing.T) {
	for name, resp := range map[string][]byte{
		"primary":   Frame(0xC4, 1, 10, []byte{0xC0}),
		"other fun": Frame(0x00, 1, 10, nil),
	} {
		t.Run(name, func(t *testing.T) {
			target := testsrv.TCP(t, testsrv.Script(resp))
			target.Timeout = 300 * time.Millisecond
			r, _ := New().Detect(context.Background(), target, core.Options{})
			if !r.Matched || r.Confidence != core.ConfidenceMedium {
				t.Fatalf("%v", r)
			}
		})
	}
}

func TestParseAttributesErrors(t *testing.T) {
	for _, b := range [][]byte{nil, {0xC0, 0x01, 0, 0}, {0xC0, 0x81, 0, 0}, {0xC0, 0x81, 0, 0, 0, 252, 0, 2, 1}} {
		if _, err := ParseAttributes(b); err == nil {
			t.Fatalf("% x accepted", b)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(Frame(0x0B, 1, 10, nil))
	f.Add(Frame(0x44, 1, 10, []byte{0xC0, 0xC0, 0x81, 0, 0, 0, 252, 0, 0, 0, 1, 1, 'A'}))
	f.Fuzz(func(t *testing.T, b []byte) {
		if h, err := ParseHeader(b); err == nil && len(h.Data) > 0 {
			_, _ = ParseAttributes(h.Data[1:])
		}
		_ = Framer(b)
	})
}

// A reply that starts with the DNP3 start octets but is malformed (another
// protocol whose bytes happen to begin 05 64) ends the read at once instead
// of waiting for more frames until the timeout.
func TestMalformedFrameStopsReading(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script([]byte{0x05, 0x64, 0x00, 0x00, 0x00, 0x0a, 0x01, 0x2b, 0x0e, 0x01, 0x82}))
	target.Timeout = 3 * time.Second
	start := time.Now()
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || r.Matched {
		t.Fatalf("%v %v", r, err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %v", d)
	}
}
