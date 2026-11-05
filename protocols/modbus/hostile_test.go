// SPDX-License-Identifier: MIT

package modbus

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/mbap"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

func TestChaos(t *testing.T) {
	t.Run("fc43", chaos.Suite{
		FP:  New(),
		TCP: func(t testing.TB, cfg chaos.Config) core.Target { return chaos.TCP(t, cfg, device(objects, 3, true)) },
	}.Run)
	t.Run("fc03-fallback", chaos.Suite{
		FP:      New(),
		Options: core.Options{MaxIntrusiveness: core.ReadOnly},
		TCP:     func(t testing.TB, cfg chaos.Config) core.Target { return chaos.TCP(t, cfg, device(objects, 3, false)) },
	}.Run)
}

// requests splits the recorded stream chunks into MBAP ADUs.
func requests(t *testing.T, rec *chaos.Recorder) []mbap.Response {
	t.Helper()
	var out []mbap.Response
	for _, chunk := range rec.Requests() {
		for len(chunk) > 0 {
			n := mbap.Framer(chunk)
			if n <= 0 || n > len(chunk) {
				t.Fatalf("not an MBAP request: % x", chunk)
			}
			r, err := mbap.Parse(chunk[:n])
			if err != nil {
				t.Fatalf("request % x: %v", chunk[:n], err)
			}
			out = append(out, r)
			chunk = chunk[n:]
		}
	}
	return out
}

// The safety contract: Read Device Identification (FC 43 / MEI 14, read
// codes basic and regular), and one holding register by FC 03 only when
// read-only probes are allowed. Never a write (05, 06, 0F, 10, 16, 17), a
// diagnostic (08) or any other function.
func TestSafetyContract(t *testing.T) {
	for _, fc43 := range []bool{true, false} {
		for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
			for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
				rec := &chaos.Recorder{}
				target := testsrv.TCP(t, rec.Wrap(device(objects, 2, fc43)))
				if _, err := New().Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: level}); err != nil {
					t.Fatal(err)
				}
				reqs := requests(t, rec)
				if len(reqs) == 0 {
					t.Fatal("nothing sent")
				}
				for _, r := range reqs {
					d := r.Data
					switch r.FC {
					case mbap.FCEncapsulated:
						if len(d) != 3 || d[0] != mbap.MEIReadDeviceID || (d[1] != readBasic && d[1] != readRegular) {
							t.Fatalf("FC 43 request % x is not Read Device Identification", d)
						}
					case mbap.FCReadHoldingRegisters:
						if level < core.ReadOnly {
							t.Fatalf("%s/%s: FC 03 sent although only passive probes are allowed", mode, level)
						}
						if len(d) != 4 || binary.BigEndian.Uint16(d[2:]) != 1 {
							t.Fatalf("FC 03 request % x reads more than one register", d)
						}
					default:
						t.Fatalf("%s/%s: function code 0x%02x sent", mode, level, r.FC)
					}
				}
			}
		}
	}
}

// echo returns every request unchanged, as an echo service (TCP 7) or a
// debugging loopback does.
func echo(req []byte) ([]byte, bool) { return req, false }

// An echo of the request carries the probe's own transaction identifier,
// protocol identifier and function code, but it is not a Modbus reply: a
// normal FC 43 response has at least six data octets, an FC 03 response a
// byte count that matches its registers.
func TestEchoIsNotModbus(t *testing.T) {
	for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
		for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
			r, err := New().Detect(context.Background(), testsrv.TCP(t, echo), core.Options{Mode: mode, MaxIntrusiveness: level})
			if err != nil || r.Matched {
				t.Fatalf("%s/%s: an echo service matched as Modbus: %v %v", mode, level, r, err)
			}
		}
	}
	// FC 03 echo, reached when FC 43 closes the connection.
	closeFC43 := func(req []byte) ([]byte, bool) {
		if len(req) > 7 && req[7] == mbap.FCEncapsulated {
			return nil, true
		}
		return req, false
	}
	r, err := New().Detect(context.Background(), testsrv.TCP(t, closeFC43), core.Options{MaxIntrusiveness: core.ReadOnly})
	if err != nil || r.Matched {
		t.Fatalf("an FC 03 echo matched as Modbus: %v %v", r, err)
	}
}
