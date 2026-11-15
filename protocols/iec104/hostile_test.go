// SPDX-License-Identifier: MIT

package iec104

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

func TestChaos(t *testing.T) {
	chaos.Suite{
		FP:  New(),
		TCP: func(t testing.TB, cfg chaos.Config) core.Target { return chaos.TCP(t, cfg, station(7, false)) },
	}.Run(t)
}

// The same under the StartDT option, which adds the exchange of identify
// mode.
func TestChaosWithStartDT(t *testing.T) {
	chaos.Suite{
		FP:      &Fingerprinter{Window: 100 * time.Millisecond, StartDT: true},
		TCP:     func(t testing.TB, cfg chaos.Config) core.Target { return chaos.TCP(t, cfg, station(7, false)) },
		Options: core.Options{MaxIntrusiveness: core.ReadOnly},
	}.Run(t)
}

// apdus splits recorded request chunks into APDUs.
func apdus(t *testing.T, rec *chaos.Recorder) [][]byte {
	t.Helper()
	var out [][]byte
	for _, chunk := range rec.Requests() {
		for len(chunk) > 0 {
			n := Framer(chunk)
			if n <= 0 || n > len(chunk) {
				t.Fatalf("not an APDU: % x", chunk)
			}
			out = append(out, chunk[:n])
			chunk = chunk[n:]
		}
	}
	return out
}

// The safety contract. By default, at every intrusiveness level and in both
// modes, the fingerprinter sends TESTFR act and nothing else: no STARTDT,
// no acknowledgement, no STOPDT. With the StartDT option, which needs
// read-only probes allowed, identify mode adds STARTDT act, one S-format
// acknowledgement, TESTFR con to a test of the link, and STOPDT act;
// detect mode stays as it is. Never an I-format APDU: no command (C_*,
// type identifiers 45..69), no interrogation (100), no clock sync.
func TestSafetyContract(t *testing.T) {
	type sent struct{ testAct, testCon, start, stop, s, other int }
	run := func(t *testing.T, f *Fingerprinter, opts core.Options, speakFirst bool) sent {
		t.Helper()
		rec := &chaos.Recorder{}
		target := testsrv.TCP(t, rec.Wrap(station(3, speakFirst)))
		if _, err := f.Detect(context.Background(), target, opts); err != nil {
			t.Fatal(err)
		}
		var n sent
		for _, b := range apdus(t, rec) {
			a, err := Parse(b)
			if err != nil {
				t.Fatalf("sent a malformed APDU % x: %v", b, err)
			}
			switch {
			case a.Format == 'I':
				t.Fatalf("sent an I-format APDU (type %d)", b[6])
			case a.Format == 'S':
				n.s++
			case a.U == uTestAct:
				n.testAct++
			case a.U == uTestCon:
				n.testCon++
			case a.U == uStartAct:
				n.start++
			case a.U == uStopAct:
				n.stop++
			default:
				n.other++
			}
		}
		return n
	}
	for _, speakFirst := range []bool{false, true} {
		for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
			for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
				opts := core.Options{Mode: mode, MaxIntrusiveness: level}
				if got, want := run(t, New(), opts, speakFirst), (sent{testAct: 1}); got != want {
					t.Errorf("default, %s/%s, station speaks first %v: sent %+v, want TESTFR act only", mode, level, speakFirst, got)
				}
				if level < core.ReadOnly {
					continue // the StartDT option is refused: TestStartDTIsRefusedUnderAPassiveScan
				}
				got := run(t, &Fingerprinter{Window: 100 * time.Millisecond, StartDT: true}, opts, speakFirst)
				want := sent{testAct: 1}
				if mode == core.ModeIdentify {
					want = sent{testAct: 1, start: 1, stop: 1, s: 1}
				}
				if got != want {
					t.Errorf("StartDT, %s/%s, station speaks first %v: sent %+v, want %+v", mode, level, speakFirst, got, want)
				}
			}
		}
	}
}

// Regression: the exported Framer indexed b[0] of an empty slice and
// panicked; it now asks for more bytes.
func TestFramerEmpty(t *testing.T) {
	if n := Framer(nil); n != 0 {
		t.Fatalf("Framer(nil) = %d", n)
	}
	if n := Framer([]byte{}); n != 0 {
		t.Fatalf("Framer(empty) = %d", n)
	}
}
