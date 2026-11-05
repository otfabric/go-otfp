// SPDX-License-Identifier: MIT

package s7

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/iso"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// plc is a stateless S7-300 speaker: it confirms every COTP CR, answers
// Setup Communication and the SZL reads 0x0011 and 0x001C, and closes on
// anything else.
func plc() testsrv.Handler {
	m11 := szlResponse(szlModuleID, 28,
		rec0011(1, "6ES7 315-2EH14-0AB0", 0, 0, 0, 0, 0, 0),
		rec0011(7, "", 0, 0, 'V', 3, 2, 8))
	m1c := szlResponse(szlComponentID, 34,
		rec001c(1, "Line 3 PLC"), rec001c(4, "Original Siemens Equipment"), rec001c(5, "S C-X4U421302009"))
	return func(req []byte) ([]byte, bool) {
		if iso.TPDUType(req) == iso.TPDUConnectRequest {
			return snap7Confirm, false
		}
		p, ok := iso.Payload(req)
		if !ok || len(p) < 10 || p[0] != protoS7 {
			return nil, true
		}
		switch p[1] {
		case rosctrJob:
			return snap7SetupAck, false
		case rosctrUserData:
			if len(p) >= 24 {
				switch binary.BigEndian.Uint16(p[22:]) {
				case szlModuleID:
					return m11, false
				case szlComponentID:
					return m1c, false
				}
			}
		}
		return nil, true
	}
}

func TestChaos(t *testing.T) {
	chaos.Suite{
		FP:  New(),
		TCP: func(t testing.TB, cfg chaos.Config) core.Target { return chaos.TCP(t, cfg, plc()) },
		// Three called TSAPs, each of which a stalled peer can hold for a
		// timeout, then setup and two SZL reads.
		Exchanges: 8,
	}.Run(t)
}

// s7PDUs splits recorded request chunks into TPKT frames and returns the
// COTP CR count and the S7 PDUs of the data TPDUs.
func s7PDUs(t *testing.T, rec *chaos.Recorder) (crs int, pdus [][]byte) {
	t.Helper()
	for _, chunk := range rec.Requests() {
		for len(chunk) > 0 {
			n := iso.Framer(chunk)
			if n <= 0 || n > len(chunk) {
				t.Fatalf("not a TPKT frame: % x", chunk)
			}
			frame := chunk[:n]
			chunk = chunk[n:]
			switch iso.TPDUType(frame) {
			case iso.TPDUConnectRequest:
				crs++
			case iso.TPDUData:
				p, _ := iso.Payload(frame)
				pdus = append(pdus, p)
			default:
				t.Fatalf("TPDU % x is neither a CR nor data", frame)
			}
		}
	}
	return crs, pdus
}

// The safety contract: COTP CR, S7 Setup Communication, and in identify
// mode the SZL reads of userdata group 4 (CPU functions) subfunction 1.
// Never a read or write of variables (0x04/0x05), a block upload or
// download (0x1A..0x1F), PLC control (0x28) or stop (0x29), and no
// userdata other than SZL reads.
func TestSafetyContract(t *testing.T) {
	for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
		for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
			rec := &chaos.Recorder{}
			target := testsrv.TCP(t, rec.Wrap(plc()))
			r, err := New().Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: level})
			if err != nil || !r.Matched {
				t.Fatalf("%s/%s: %v %v", mode, level, r, err)
			}
			crs, pdus := s7PDUs(t, rec)
			if crs == 0 || len(pdus) == 0 {
				t.Fatalf("%s/%s: %d CRs, %d PDUs", mode, level, crs, len(pdus))
			}
			szl := 0
			for _, p := range pdus {
				if len(p) < 10 || p[0] != protoS7 {
					t.Fatalf("not an S7 PDU: % x", p)
				}
				plen := int(binary.BigEndian.Uint16(p[6:]))
				if 10+plen > len(p) || plen < 1 {
					t.Fatalf("S7 parameters overrun: % x", p)
				}
				params := p[10 : 10+plen]
				switch p[1] {
				case rosctrJob:
					if params[0] != fnSetupComm {
						t.Fatalf("%s/%s: S7 job function 0x%02x sent", mode, level, params[0])
					}
				case rosctrUserData:
					// params: 00 01 12, length, method 0x11, type/group
					// 0x44 (request, CPU functions), subfunction 0x01 (read SZL).
					if len(params) < 7 || params[4] != 0x11 || params[5] != 0x44 || params[6] != 0x01 {
						t.Fatalf("%s/%s: userdata % x is not an SZL read", mode, level, params)
					}
					szl++
				default:
					t.Fatalf("%s/%s: ROSCTR 0x%02x sent", mode, level, p[1])
				}
			}
			if mode == core.ModeDetect && szl != 0 {
				t.Fatalf("detect mode read %d SZLs", szl)
			}
			if mode == core.ModeIdentify && szl != 2 {
				t.Fatalf("identify mode read %d SZLs, want 2", szl)
			}
		}
	}
}
