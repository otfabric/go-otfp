// SPDX-License-Identifier: MIT

package profinet

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// spoof is the device's reply under another activity UUID: a reply to
// another client's request, which must be discarded.
func spoof(req []byte, i int) []byte {
	out := append([]byte(nil), unhex(im0Response)...)
	if len(req) >= 56 {
		copy(out[40:56], req[40:56])
	}
	out[40] ^= byte((1 + i%200) & 0xFF)
	return out
}

func TestChaos(t *testing.T) {
	t.Run("junk", chaos.Suite{
		FP: New(),
		UDP: func(t testing.TB, cfg chaos.UDPConfig) core.Target {
			return chaos.UDP(t, cfg, echoActivity(unhex(im0Response)))
		},
	}.Run)
	t.Run("spoofed-activity", chaos.Suite{
		FP: New(),
		UDP: func(t testing.TB, cfg chaos.UDPConfig) core.Target {
			cfg.Spoof = spoof
			return chaos.UDP(t, cfg, echoActivity(unhex(im0Response)))
		},
		Seeds: 1,
	}.Run)
}

// The safety contract: one connectionless DCE/RPC v4 request, opnum 5
// (ReadImplicit) on the PNIO device interface, with a single
// IODReadReqHeader for the I&M0 record. Never Connect (0), Release (1),
// Read with an AR (2), Write (3) or Control (4).
func TestSafetyContract(t *testing.T) {
	for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
		for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
			rec := &chaos.Recorder{}
			target := testsrv.UDP(t, rec.Wrap(echoActivity(unhex(im0Response))))
			r, err := New().Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: level})
			if err != nil || !r.Matched {
				t.Fatalf("%s: %v %v", mode, r, err)
			}
			reqs := rec.Requests()
			if len(reqs) == 0 {
				t.Fatal("nothing sent")
			}
			for _, dg := range reqs {
				h, body, err := parseHeader(dg)
				if err != nil || h.typ != typeRequest {
					t.Fatalf("not a DCE/RPC v4 request: % x (%v)", dg, err)
				}
				if h.opnum != opReadImplicit {
					t.Fatalf("%s: opnum %d sent", mode, h.opnum)
				}
				if [16]byte(dg[24:40]) != [16]byte(encodeUUIDLE(deviceInterface)) {
					t.Fatalf("interface % x is not the PNIO device interface", dg[24:40])
				}
				blocks := body[ndrHeaderLen:]
				if len(blocks) < 38 || binary.BigEndian.Uint16(blocks) != 0x0009 ||
					binary.BigEndian.Uint16(blocks[34:]) != indexIM0 || int(binary.BigEndian.Uint16(blocks[2:]))+4 != len(blocks) {
					t.Fatalf("not one IODReadReqHeader for I&M0: % x", blocks)
				}
			}
		}
	}
}

// An echo of the ReadImplicit request carries our activity UUID, but it is
// a request (type 0), which only the probing side sends.
func TestEchoIsNotPROFINET(t *testing.T) {
	target := testsrv.UDP(t, func(req []byte) ([]byte, bool) { return req, false })
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
	if err != nil || r.Matched || r.Confidence != core.ConfidenceLow {
		t.Fatalf("%v %v", r, err)
	}
}
