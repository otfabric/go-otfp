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
		FP:  &Fingerprinter{Window: 100 * time.Millisecond},
		TCP: func(t testing.TB, cfg chaos.Config) core.Target { return chaos.TCP(t, cfg, station(7, false)) },
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

// The safety contract: U-format TESTFR act/con, STARTDT act and STOPDT act,
// and S-format acknowledgements. Never an I-format APDU: no command
// (C_*, type identifiers 45..69), no interrogation (100), no clock sync.
func TestSafetyContract(t *testing.T) {
	for _, speakFirst := range []bool{false, true} {
		for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
			for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
				rec := &chaos.Recorder{}
				target := testsrv.TCP(t, rec.Wrap(station(3, speakFirst)))
				f := &Fingerprinter{Window: 100 * time.Millisecond}
				if _, err := f.Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: level}); err != nil {
					t.Fatal(err)
				}
				sent := apdus(t, rec)
				if len(sent) == 0 {
					t.Fatal("nothing sent")
				}
				starts := 0
				for _, b := range sent {
					a, err := Parse(b)
					if err != nil {
						t.Fatalf("sent a malformed APDU % x: %v", b, err)
					}
					switch a.Format {
					case 'I':
						t.Fatalf("%s/%s: sent an I-format APDU (type %d)", mode, level, b[6])
					case 'U':
						switch a.U {
						case uTestAct, uTestCon, uStopAct:
						case uStartAct:
							starts++
						default:
							t.Fatalf("%s/%s: sent U-format 0x%02x", mode, level, a.U)
						}
					}
				}
				if mode == core.ModeDetect && starts > 0 {
					t.Fatalf("detect mode started data transfer")
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
