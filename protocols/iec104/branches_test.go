// SPDX-License-Identifier: MIT

package iec104

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

func TestApciEdges(t *testing.T) {
	if Framer([]byte{0x68}) != 0 || Framer([]byte{0x68, 2}) != -1 || Framer([]byte{0x68, 254}) != -1 {
		t.Fatal("framer")
	}
	for _, b := range [][]byte{
		{0x68, 0x04, 0x00, 0x00, 0x01, 0x00},       // I-format, odd receive octet
		{0x68, 0x04, 0x01, 0x01, 0x00, 0x00},       // S-format, non-zero second octet
		{0x68, 0x06, 0x01, 0x00, 0x00, 0x00, 1, 2}, // S-format with an ASDU
	} {
		if _, err := Parse(b); err == nil {
			t.Errorf("% x accepted", b)
		}
	}
	if joinInts([]int{1, 2, 3}) != "1,2,3" {
		t.Fatal("joinInts")
	}
}

func TestDetectEdges(t *testing.T) {
	// A malformed APDU with the start octet: a hint.
	bad := testsrv.TCP(t, testsrv.Script([]byte{0x68, 0x04, 0x47, 0, 0, 0}))
	if r, err := New().Detect(context.Background(), bad, core.Options{}); err != nil || r.Matched || r.Confidence != core.ConfidenceLow {
		t.Fatalf("%v %v", r, err)
	}
	// An S-frame first, then the confirmation.
	sFirst := testsrv.TCP(t, testsrv.Script(append([]byte{0x68, 0x04, 0x01, 0x00, 0x02, 0x00}, U(uTestCon)...)))
	if r, err := New().Detect(context.Background(), sFirst, core.Options{}); err != nil || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v %v", r, err)
	}
	if _, err := New().Detect(context.Background(), testsrv.Closed(t), core.Options{}); err == nil {
		t.Fatal("closed")
	}
}

func TestIdentifyEdges(t *testing.T) {
	f := &Fingerprinter{Window: 200 * time.Millisecond}
	cases := map[string]testsrv.Handler{
		// STARTDT never confirmed (the station keeps silent).
		"no startdt con": testsrv.Script(U(uTestCon)),
		// STARTDT refused by closing.
		"startdt closed": func(req []byte) ([]byte, bool) {
			if req[2] == uTestAct {
				return U(uTestCon), false
			}
			return nil, true
		},
		// The station tests the link during the window and sends a
		// non-ASDU I-frame.
		"testfr in window": func(req []byte) ([]byte, bool) {
			switch req[2] {
			case uTestAct:
				return U(uTestCon), false
			case uStartAct:
				return append(append(U(uStartCon), U(uTestAct)...), 0x68, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00), false
			}
			return nil, false
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			target := testsrv.TCP(t, h)
			target.Timeout = 300 * time.Millisecond
			r, err := f.Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
			if err != nil || !r.Matched {
				t.Fatalf("%v %v", r, err)
			}
		})
	}
	// The default window is one second, capped by the timeout.
	target := testsrv.TCP(t, testsrv.Script(U(uTestCon), U(uStartCon)))
	target.Timeout = 150 * time.Millisecond
	start := time.Now()
	_, _ = New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
	if time.Since(start) > 900*time.Millisecond {
		t.Fatalf("window not capped by the timeout: %v", time.Since(start))
	}
	if _, _, ok := asduHeader([]byte{0, 1, 2, 3, 4, 5}); ok {
		t.Fatal("type 0 is not an ASDU")
	}
}
