// SPDX-License-Identifier: MIT

package enip

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// spoof is the device's ListIdentity reply under another sender context:
// the answer to another request, which must be discarded.
func spoof(req []byte, i int) []byte {
	resp, _ := opener()(req)
	if len(resp) < headerLen {
		return []byte{0x63, 0}
	}
	resp[12] ^= byte((1 + i%200) & 0xFF)
	return resp
}

func TestChaos(t *testing.T) {
	t.Run("tcp", chaos.Suite{
		FP:  New(),
		TCP: func(t testing.TB, cfg chaos.Config) core.Target { return chaos.TCP(t, cfg, opener()) },
	}.Run)
	t.Run("udp", chaos.Suite{
		FP:  NewUDP(),
		UDP: func(t testing.TB, cfg chaos.UDPConfig) core.Target { return chaos.UDP(t, cfg, opener()) },
	}.Run)
	t.Run("udp-spoofed-context", chaos.Suite{
		FP: NewUDP(),
		UDP: func(t testing.TB, cfg chaos.UDPConfig) core.Target {
			cfg.Spoof = spoof
			return chaos.UDP(t, cfg, opener())
		},
		Seeds: 1,
	}.Run)
}

// The safety contract: ListIdentity (0x0063), and RegisterSession (0x0065,
// protocol version 1, no options) over TCP in identify mode only. No
// SendRRData/SendUnitData (0x006F/0x0070), so no CIP service at all: no
// Set_Attribute, Reset or any other object request.
func TestSafetyContract(t *testing.T) {
	for _, fp := range []*Fingerprinter{New(), NewUDP()} {
		for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
			for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
				rec := &chaos.Recorder{}
				var target core.Target
				if fp.network == core.UDP {
					target = testsrv.UDP(t, rec.Wrap(opener()))
				} else {
					target = testsrv.TCP(t, rec.Wrap(opener()))
				}
				r, err := fp.Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: level})
				if err != nil || !r.Matched {
					t.Fatalf("%s %s: %v %v", fp.network, mode, r, err)
				}
				registered := 0
				for _, chunk := range rec.Requests() {
					for len(chunk) > 0 {
						n := framer(chunk)
						if n <= 0 || n > len(chunk) {
							t.Fatalf("not an encapsulation: % x", chunk)
						}
						h, data, err := parseEncap(chunk[:n])
						if err != nil {
							t.Fatal(err)
						}
						switch h.command {
						case cmdListIdentity:
							if len(data) != 0 {
								t.Fatalf("ListIdentity with data % x", data)
							}
						case cmdRegisterSession:
							if fp.network != core.TCP || mode != core.ModeIdentify {
								t.Fatalf("%s %s: RegisterSession sent", fp.network, mode)
							}
							if len(data) != 4 || binary.LittleEndian.Uint16(data) != 1 || binary.LittleEndian.Uint16(data[2:]) != 0 {
								t.Fatalf("RegisterSession data % x", data)
							}
							registered++
						default:
							t.Fatalf("%s %s: encapsulation command 0x%04x sent", fp.network, mode, h.command)
						}
						chunk = chunk[n:]
					}
				}
				if registered > 1 {
					t.Fatalf("%d sessions registered", registered)
				}
			}
		}
	}
}

// A reply that does not echo the sender context is EtherNet/IP, but not
// certain: FINGERPRINTS.md makes the echoed context part of a certain match.
func TestContextNotEchoedIsNotCertain(t *testing.T) {
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) {
		resp, closeConn := opener()(req)
		if len(resp) >= headerLen {
			resp[12] ^= 0xFF
		}
		return resp, closeConn
	})
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceHigh {
		t.Fatalf("%v %v", r, err)
	}
}

// An echo of ListIdentity (24 octets, length 0, the probe's own context
// and a zero status) is not a target: it carries no CPF item count.
func TestEchoIsNotENIP(t *testing.T) {
	echo := func(req []byte) ([]byte, bool) { return req, false }
	for _, fp := range []*Fingerprinter{New(), NewUDP()} {
		var target core.Target
		if fp.network == core.UDP {
			target = testsrv.UDP(t, echo)
		} else {
			target = testsrv.TCP(t, echo)
		}
		r, err := fp.Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
		if err != nil || r.Matched || r.Confidence != core.ConfidenceLow {
			t.Fatalf("%s: %v %v", fp.network, r, err)
		}
	}
}
