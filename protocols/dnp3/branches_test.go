// SPDX-License-Identifier: MIT

package dnp3

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

func attr(v byte, s string) []byte {
	return append([]byte{0x00, v, 0x00, 0, 0, 1, byte(len(s))}, s...)
}

func TestAllAttributes(t *testing.T) {
	var obj []byte
	for v, s := range map[byte]string{247: "PLC-7", 243: "hw2", 245: "Hall 1", 246: "uid", 244: "OTF", 249: "L2", 230: "x"} {
		obj = append(obj, attr(v, s)...)
	}
	attrs, err := ParseAttributes(append([]byte{0xC0, 0x81, 0, 0}, obj...))
	if err != nil || len(attrs) != 7 {
		t.Fatalf("%v %v", attrs, err)
	}
	// Through identify: every mapping.
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) {
		h, err := ParseHeader(req[:FrameLen(req[2])])
		if err != nil {
			return nil, false
		}
		if h.Ctrl&0x0F == fcRequestLinkStatus {
			return Frame(fcNotSupported, 1, 10, nil), false // "not supported" still answers
		}
		return Frame(0x44, 1, 10, append([]byte{0xC0, 0xC0, 0x81, 0, 0}, obj...)), false
	})
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
	if err != nil || !r.Matched || r.Variant != "link status not supported" {
		t.Fatalf("%v %v", r, err)
	}
	id := r.Identity
	if id.Name != "PLC-7" || id.Attributes["hardwareVersion"] != "hw2" || id.Attributes["location"] != "Hall 1" ||
		id.Attributes["userId"] != "uid" || id.Attributes["owner"] != "OTF" || id.Attributes["subsetAndConformance"] != "L2" || id.Attributes["g0v230"] != "x" {
		t.Fatalf("%+v", id)
	}
}

func TestQualifiersAndErrors(t *testing.T) {
	// Qualifier 0x01 (two-octet range).
	q1 := append([]byte{0xC0, 0x81, 0, 0, 0x00, 252, 0x01, 0, 0, 0, 0}, 1, 2, 'A', 'B')
	if a, err := ParseAttributes(q1); err != nil || a[252] != "AB" {
		t.Fatalf("%v %v", a, err)
	}
	// A qualifier not decoded keeps what came before.
	mixed := append(append([]byte{0xC0, 0x81, 0, 0}, attr(252, "X")...), 0x00, 250, 0x17, 1)
	if a, err := ParseAttributes(mixed); err != nil || a[252] != "X" {
		t.Fatalf("%v %v", a, err)
	}
	// A group other than 0 ends the list.
	if a, _ := ParseAttributes(append(append([]byte{0xC0, 0x81, 0, 0}, attr(252, "Y")...), 0x01, 0x02, 0x00, 0, 0)); a[252] != "Y" {
		t.Fatal("non-attribute group")
	}
	for _, b := range [][]byte{
		{0xC0, 0x81, 0, 0, 0x00, 252, 0x01, 0, 0},            // short 16-bit range
		{0xC0, 0x81, 0, 0, 0x00, 252, 0x01, 5, 0, 1, 0},      // stop < start
		{0xC0, 0x81, 0, 0, 0x00, 252, 0x00, 0, 0, 1},         // attribute header truncated
		{0xC0, 0x81, 0, 0, 0x00, 252, 0x00, 0, 0, 1, 5, 'a'}, // value truncated
		{0xC0, 0x81, 0, 0, 0x00, 252, 0x00, 0, 0, 9, 1, 'a'}, // unknown type: no string
	} {
		if _, err := ParseAttributes(b); err == nil {
			t.Errorf("% x accepted", b)
		}
	}
	if attrString(5, []byte{1}) != "" {
		t.Fatal("octet-string attributes are not rendered")
	}
	if _, err := ParseHeader([]byte{0x05, 0x65, 5, 0, 0, 0, 0, 0, 0, 0}); err == nil {
		t.Fatal("start octets")
	}
	f := Frame(0x0B, 1, 10, nil)
	if _, err := ParseHeader(append(f, 0)); err == nil {
		t.Fatal("length mismatch")
	}
	if Framer([]byte{0x05}) != 0 || Framer([]byte{0x05, 0x64}) != 0 || FrameLen(2) != -1 {
		t.Fatal("framer edges")
	}
}

// A device answers the attribute read with a malformed response; another
// station's primary frame arrives first in a burst.
func TestIdentifyAndBurstEdges(t *testing.T) {
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) {
		h, err := ParseHeader(req[:FrameLen(req[2])])
		if err != nil {
			return nil, false
		}
		if h.Ctrl&0x0F == fcRequestLinkStatus {
			// Another station's primary frame first, then the reply.
			return append(Frame(0xC4, 1, 20, []byte{0xC0}), Frame(fcLinkStatus, 1, 10, nil)...), false
		}
		return Frame(0x44, 1, 10, []byte{0xC0, 0xC0, 0x01}), false
	})
	target.Timeout = 300 * time.Millisecond
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
	if err != nil || !r.Matched || r.Identity.Attributes["outstationAddress"] != "10" {
		t.Fatalf("%v %v", r, err)
	}
	if _, err := New().Detect(context.Background(), testsrv.Closed(t), core.Options{}); err == nil {
		t.Fatal("closed port")
	}
	// The self address configured explicitly is not probed twice.
	if f := NewWithConfig(Config{Outstations: []uint16{selfAddress, 7}, Master: 3}); f.master != 3 || len(f.outstations) != 2 {
		t.Fatal("config")
	}
}
