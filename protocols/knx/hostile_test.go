// SPDX-License-Identifier: MIT

package knx

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// spoof is routing traffic (a ROUTING_INDICATION), as a KNX router
// multicasts: never an answer to a request.
func spoof([]byte, int) []byte { return frame(0x0530, []byte{0x29, 0x00, 0xBC, 0xE0}) }

func TestChaos(t *testing.T) {
	t.Run("udp", chaos.Suite{
		FP: New(),
		UDP: func(t testing.TB, cfg chaos.UDPConfig) core.Target {
			return chaos.UDP(t, cfg, server(hostUDP, unhex(knxdResp)))
		},
	}.Run)
	t.Run("udp-routing-flood", chaos.Suite{
		FP: New(),
		UDP: func(t testing.TB, cfg chaos.UDPConfig) core.Target {
			cfg.Spoof = spoof
			return chaos.UDP(t, cfg, server(hostUDP, unhex(knxdResp)))
		},
		Seeds: 1,
	}.Run)
	t.Run("tcp", chaos.Suite{
		FP: NewTCP(),
		TCP: func(t testing.TB, cfg chaos.Config) core.Target {
			return chaos.TCP(t, cfg, server(hostTCP, unhex(calimeroResp)))
		},
	}.Run)
}

// The safety contract: DESCRIPTION_REQUEST (0x0203) with a control HPAI
// only. Never SEARCH (none is needed), CONNECT_REQUEST (0x0205), a
// tunnelling (0x042x), device-management (0x031x) or routing (0x05xx)
// frame, or any KNX IP Secure service (0x095x).
func TestSafetyContract(t *testing.T) {
	type tc struct {
		fp   *Fingerprinter
		host byte
		resp string
	}
	for _, c := range []tc{{New(), hostUDP, knxdResp}, {NewTCP(), hostTCP, calimeroResp}} {
		for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
			for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
				rec := &chaos.Recorder{}
				var target core.Target
				if c.fp.network == core.UDP {
					target = testsrv.UDP(t, rec.Wrap(server(c.host, unhex(c.resp))))
				} else {
					target = testsrv.TCP(t, rec.Wrap(server(c.host, unhex(c.resp))))
				}
				r, err := c.fp.Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: level})
				if err != nil || !r.Matched {
					t.Fatalf("%s %s: %v %v", c.fp.network, mode, r, err)
				}
				for _, req := range rec.Requests() {
					svc, ok := header(req)
					if !ok {
						t.Fatalf("not a KNXnet/IP frame: % x", req)
					}
					if svc != svcDescReq {
						t.Fatalf("%s %s: service 0x%04x sent", c.fp.network, mode, svc)
					}
					if len(req) != headerLen+hpaiLen || req[6] != hpaiLen || req[7] != c.host {
						t.Fatalf("DESCRIPTION_REQUEST % x without the expected HPAI", req)
					}
					if binary.BigEndian.Uint16(req[4:]) != headerLen+hpaiLen {
						t.Fatalf("total length % x", req[4:6])
					}
				}
			}
		}
	}
}
