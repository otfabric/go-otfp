// SPDX-License-Identifier: MIT

package iec104

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// station answers like a controlled station with common address ca that
// sends an end of initialisation after STARTDT.
func station(ca uint16, speakFirst bool) testsrv.Handler {
	first := speakFirst
	return func(req []byte) ([]byte, bool) {
		var out []byte
		if first {
			first = false
			out = append(out, U(uTestAct)...)
		}
		for len(req) >= 6 {
			n := int(req[1]) + 2
			if n > len(req) {
				break
			}
			a, err := Parse(req[:n])
			req = req[n:]
			if err != nil || a.Format != 'U' {
				continue
			}
			switch a.U {
			case uTestAct:
				out = append(out, U(uTestCon)...)
			case uStartAct:
				out = append(out, U(uStartCon)...)
				// M_EI_NA_1, COT 4 (initialised), CA, IOA 0, COI 0.
				out = append(out, startByte, 0x0E, 0x00, 0x00, 0x00, 0x00,
					70, 0x01, 0x04, 0x00, byte(ca), byte(ca>>8), 0, 0, 0, 0)
			case uStopAct:
				out = append(out, U(uStopCon)...)
			}
		}
		return out, false
	}
}

func TestDetect(t *testing.T) {
	target := testsrv.TCP(t, station(1, false))
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain || r.Fingerprint.Signature != "testfr=con" {
		t.Fatalf("%v %v", r, err)
	}
}

func TestStationSpeaksFirst(t *testing.T) {
	target := testsrv.TCP(t, station(1, true))
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v %v", r, err)
	}
}

func TestIdentify(t *testing.T) {
	target := testsrv.TCP(t, station(4711, false))
	f := &Fingerprinter{Window: 300 * time.Millisecond}
	r, err := f.Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify, Trace: true})
	if err != nil || !r.Matched {
		t.Fatalf("%v %v", r, err)
	}
	if r.Identity == nil || r.Identity.Attributes["commonAddress"] != "4711" || r.Identity.Attributes["asduTypes"] != "70" {
		t.Fatalf("identity %+v", r.Identity)
	}
	if r.Fingerprint.Signature != "testfr=con;startdt=con" {
		t.Fatalf("signature %q", r.Fingerprint.Signature)
	}
}

func TestEchoIsNotIEC104(t *testing.T) {
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) { return req, false })
	target.Timeout = 300 * time.Millisecond
	r, _ := New().Detect(context.Background(), target, core.Options{})
	if r.Confidence == core.ConfidenceCertain {
		t.Fatalf("echo matched: %v", r)
	}
}

func TestNotIEC104(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script([]byte("SSH-2.0-OpenSSH_9.6\r\n")))
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || r.Matched || r.Confidence != 0 {
		t.Fatalf("%v %v", r, err)
	}
	silent := testsrv.TCP(t, testsrv.Script())
	silent.Timeout = 200 * time.Millisecond
	_, err = New().Detect(context.Background(), silent, core.Options{})
	var te *core.TimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("silent: %v", err)
	}
}

func TestParse(t *testing.T) {
	good := [][]byte{U(uTestCon), {0x68, 0x04, 0x01, 0x00, 0x02, 0x00}, {0x68, 0x06, 0x02, 0x00, 0x00, 0x00, 0x01, 0x02}}
	for _, b := range good {
		if _, err := Parse(b); err != nil {
			t.Fatalf("% x: %v", b, err)
		}
	}
	bad := [][]byte{{0x68, 0x04, 0x47, 0, 0, 0}, {0x68, 0x05, 0x83, 0, 0, 0}, {0x68, 0x04, 0x83, 0, 1, 0}, {0x69, 4, 0x83, 0, 0, 0}}
	for _, b := range bad {
		if _, err := Parse(b); err == nil {
			t.Fatalf("% x accepted", b)
		}
	}
	if a, _ := Parse([]byte{0x68, 0x04, 0x06, 0x01, 0x00, 0x00}); a.SendSeq != 0x83 {
		t.Fatalf("send sequence %d", a.SendSeq)
	}
	if !bytes.Equal(U(uStartAct), []byte{0x68, 4, 7, 0, 0, 0}) {
		t.Fatal("STARTDT act")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(U(uTestCon))
	f.Add([]byte{0x68, 0x0E, 0, 0, 0, 0, 70, 1, 4, 0, 1, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if a, err := Parse(b); err == nil {
			_, _, _ = asduHeader(a.ASDU)
		}
		if len(b) > 0 {
			_ = Framer(b)
		}
	})
}
