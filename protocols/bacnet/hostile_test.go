// SPDX-License-Identifier: MIT

package bacnet

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// spoof answers a ReadProperty with the device's ComplexACK under another
// invoke ID: a late or forged answer that must be discarded.
func spoof(req []byte, i int) []byte {
	resp, _ := device()(req)
	if len(resp) < 8 || len(req) < 9 {
		return []byte{0x81, 0x0a, 0x00, 0x04}
	}
	resp = append([]byte(nil), resp...)
	resp[7] = req[8] + byte((1+i%100)&0xFF)
	return resp
}

func TestChaos(t *testing.T) {
	t.Run("junk", chaos.Suite{
		FP:  New(),
		UDP: func(t testing.TB, cfg chaos.UDPConfig) core.Target { return chaos.UDP(t, cfg, device()) },
	}.Run)
	t.Run("spoofed-invoke", chaos.Suite{
		FP: New(),
		UDP: func(t testing.TB, cfg chaos.UDPConfig) core.Target {
			cfg.Spoof = spoof
			return chaos.UDP(t, cfg, device())
		},
		Seeds: 1,
	}.Run)
}

// iAmOnly answers Who-Is only, which forces the Who-Is fallback.
func iAmOnly(req []byte) ([]byte, bool) {
	if len(req) > 7 && req[6] == apduUnconfirmedReq {
		return bvlc(bvlcUnicastNPDU, []byte{npduVersion, 0x00, apduUnconfirmedReq, 0x00,
			0xC4, 0x02, 0x00, 0x04, 0xD2, 0x22, 0x05, 0xC4, 0x91, 0x03, 0x21, 0x0F}), false
	}
	return nil, false
}

// The safety contract: confirmed ReadProperty (service 12) of the device
// object and the unconfirmed Who-Is (service 8), nothing else: never
// WriteProperty, ReinitializeDevice, DeviceCommunicationControl or any
// other service.
func TestSafetyContract(t *testing.T) {
	for name, h := range map[string]testsrv.Handler{"device": device(), "who-is only": iAmOnly} {
		for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
			for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
				rec := &chaos.Recorder{}
				target := testsrv.UDP(t, rec.Wrap(h))
				target.Timeout = 300 * time.Millisecond
				r, err := New().Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: level})
				if err != nil || !r.Matched {
					t.Fatalf("%s %s: %v %v", name, mode, r, err)
				}
				reads := 0
				for _, dg := range rec.Requests() {
					if len(dg) < 8 || dg[0] != bvlcType || dg[1] != bvlcUnicastNPDU || dg[4] != npduVersion || dg[5]&0xA8 != 0 {
						t.Fatalf("%s: not a unicast BACnet/IP request without addresses: % x", name, dg)
					}
					a := dg[6:]
					switch {
					case a[0] == apduConfirmedReq && len(a) >= 4 && a[3] == svcReadProperty:
						if len(a) < 9 || a[4] != 0x0C || binary.BigEndian.Uint32(a[5:9])>>22 != objectDevice {
							t.Fatalf("%s: ReadProperty of a non-device object: % x", name, a)
						}
						reads++
					case a[0] == apduUnconfirmedReq && len(a) == 2 && a[1] == svcWhoIs:
					default:
						t.Fatalf("%s %s: APDU % x is neither ReadProperty nor Who-Is", name, mode, a)
					}
				}
				if mode == core.ModeDetect && reads > 2 { // the probe and its retransmission
					t.Fatalf("%s: detect sent %d ReadProperty requests", name, reads)
				}
			}
		}
	}
}
