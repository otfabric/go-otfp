// SPDX-License-Identifier: MIT

package e2e_test

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
	"github.com/otfabric/go-otfp/internal/testsrv"
	"github.com/otfabric/go-otfp/internal/wire"
	"github.com/otfabric/go-otfp/protocols/bacnet"
	"github.com/otfabric/go-otfp/protocols/enip"
	"github.com/otfabric/go-otfp/protocols/knx"
	"github.com/otfabric/go-otfp/protocols/profinet"
)

const udpTimeout = 400 * time.Millisecond

// udpSpeakers are minimal correct responders of the UDP protocols, keyed
// by their fingerprinter.
func udpSpeakers() map[string]struct {
	fp core.Fingerprinter
	h  testsrv.Handler
} {
	type sp = struct {
		fp core.Fingerprinter
		h  testsrv.Handler
	}
	return map[string]sp{
		"bacnet": {bacnet.New(), func(req []byte) ([]byte, bool) {
			// A ComplexACK of ReadProperty(Object_Identifier) for device 1234,
			// under the request's invoke ID; nothing else is answered.
			if len(req) < 10 || req[0] != 0x81 || req[6] != 0x00 || req[9] != 12 {
				return nil, false
			}
			apdu := []byte{0x30, req[8], 12, 0x0C, 0x02, 0x00, 0x04, 0xD2, 0x19, 75, 0x3E, 0xC4, 0x02, 0x00, 0x04, 0xD2, 0x3F}
			out := append([]byte{0x81, 0x0A, 0, 0, 0x01, 0x00}, apdu...)
			binary.BigEndian.PutUint16(out[2:], wire.Len16(len(out)))
			return out, false
		}},
		"profinet": {profinet.New(), func(req []byte) ([]byte, bool) {
			// A DCE/RPC v4 response echoing the activity, with an empty
			// NDR result (PNIO status 0, no blocks).
			if len(req) < 80 || req[0] != 4 || req[1] != 0 {
				return nil, false
			}
			out := append([]byte(nil), req[:80]...)
			out[1] = 2
			binary.LittleEndian.PutUint16(out[74:], 20)
			return append(out, make([]byte, 20)...), false
		}},
		"enip": {enip.NewUDP(), speakers()[core.ProtocolENIP]},
		"knx": {knx.New(), func(req []byte) ([]byte, bool) {
			if len(req) != 14 || binary.BigEndian.Uint16(req[2:]) != 0x0203 {
				return nil, false
			}
			dev := make([]byte, 0x36)
			dev[0], dev[1], dev[2] = 0x36, 0x01, 0x20 // DEVICE_INFO, medium IP
			copy(dev[24:], "e2e-knx")
			svc := []byte{0x04, 0x02, 0x02, 0x01} // SUPP_SVC_FAMILIES: core v1
			out := append([]byte{0x06, 0x10, 0x02, 0x04, 0, 0}, append(dev, svc...)...)
			binary.BigEndian.PutUint16(out[4:], wire.Len16(len(out)))
			return out, false
		}},
	}
}

// udpServer answers h's replies, first sending before(req) from its own
// address and fromOther(req) from another socket (another source port).
func udpServer(t *testing.T, h testsrv.Handler, before, fromOther func(req []byte) [][]byte) core.Target {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	other, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = pc.Close(); _ = other.Close(); wg.Wait() })
	wg.Go(func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := append([]byte(nil), buf[:n]...)
			resp, _ := h(req)
			if resp == nil {
				continue
			}
			if fromOther != nil {
				for _, dg := range fromOther(req) {
					_, _ = other.WriteTo(dg, from)
				}
			}
			if before != nil {
				for _, dg := range before(req) {
					_, _ = pc.WriteTo(dg, from)
				}
			}
			_, _ = pc.WriteTo(resp, from)
		}
	})
	return chaos.Target(t, pc.LocalAddr(), core.UDP)
}

// burst returns n copies of dg: bounded, since a loopback socket buffer
// under -race on a loaded runner overflows long before 500 datagrams.
func burst(n int, dg []byte) func([]byte) [][]byte {
	return func([]byte) [][]byte {
		out := make([][]byte, n)
		for i := range out {
			out[i] = dg
		}
		return out
	}
}

// Every UDP fingerprinter finds the real answer behind spoofed, foreign,
// empty and oversized datagrams and behind a flood from another port, and
// fails promptly with a typed error on an ICMP port unreachable or an
// answer from the wrong port.
func TestUDPHostile(t *testing.T) {
	foreignAnswers := map[string][]byte{ // another protocol's answer
		"bacnet":   []byte("\x06\x10\x02\x04\x00\x06"),
		"profinet": {0x81, 0x0b, 0x00, 0x04},
		"enip":     {0x81, 0x0b, 0x00, 0x04},
		"knx":      {0x81, 0x0b, 0x00, 0x04},
	}
	for name, sp := range udpSpeakers() {
		p := sp.fp.Info().Protocol
		mustMatch := map[string]core.Target{
			"clean":           udpServer(t, sp.h, nil, nil),
			"garbage-flood":   udpServer(t, sp.h, burst(chaos.FloodSize, []byte("\xde\xad\xbe\xef garbage")), nil),
			"foreign-flood":   udpServer(t, sp.h, burst(chaos.FloodSize, foreignAnswers[name]), nil),
			"empty":           udpServer(t, sp.h, burst(2, nil), nil),
			"oversized":       chaos.UDP(t, chaos.UDPConfig{Fault: chaos.Oversize}, sp.h),
			"wrong-port-fld":  udpServer(t, sp.h, nil, burst(chaos.FloodSize, []byte("spoofed source"))),
			"dropped-once":    chaos.UDP(t, chaos.UDPConfig{Fault: chaos.Drop}, sp.h),
			"late-and-dup":    chaos.UDP(t, chaos.UDPConfig{Fault: chaos.UDPDuplicate}, sp.h),
			"flood-then-real": chaos.UDP(t, chaos.UDPConfig{Fault: chaos.Flood, Seed: 9}, sp.h),
		}
		for scenario, target := range mustMatch {
			t.Run(name+"/"+scenario, func(t *testing.T) {
				t.Parallel()
				target.Timeout = udpTimeout
				r, err := sp.fp.Detect(context.Background(), target, core.Options{MaxIntrusiveness: core.ReadOnly})
				fuzzkit.Check(t, p, r, err)
				if err != nil || !r.Matched {
					t.Fatalf("the real answer was missed: %v (%v)", r, err)
				}
			})
		}
		t.Run(name+"/port-unreachable", func(t *testing.T) {
			t.Parallel()
			target := chaos.ClosedUDP(t)
			target.Timeout = udpTimeout
			start := time.Now()
			r, err := sp.fp.Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
			fuzzkit.Check(t, p, r, err)
			var ce *core.ConnectionError
			if r.Matched || !errors.As(err, &ce) || !ce.Refused() {
				t.Fatalf("want a refused ConnectionError: %v (%v)", r, err)
			}
			if d := time.Since(start); d > 2*udpTimeout {
				t.Fatalf("an ICMP port unreachable took %v", d)
			}
		})
		t.Run(name+"/answer-from-other-port", func(t *testing.T) {
			t.Parallel()
			target := chaos.UDP(t, chaos.UDPConfig{Fault: chaos.OtherPort}, sp.h)
			target.Timeout = udpTimeout
			r, err := sp.fp.Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
			fuzzkit.Check(t, p, r, err)
			var te *core.TimeoutError
			if r.Matched || !errors.As(err, &te) {
				t.Fatalf("an answer from another port must not be read: %v (%v)", r, err)
			}
		})
		t.Run(name+"/foreign-service", func(t *testing.T) {
			t.Parallel()
			// A service of another protocol only: a NoMatch, not an error,
			// within the retransmission windows.
			target := testsrv.UDP(t, func([]byte) ([]byte, bool) { return foreignAnswers[name], false })
			target.Timeout = udpTimeout
			start := time.Now()
			r, err := sp.fp.Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
			fuzzkit.Check(t, p, r, err)
			if err != nil || r.Matched {
				t.Fatalf("%v (%v)", r, err)
			}
			if d := time.Since(start); d > 4*udpTimeout {
				t.Fatalf("took %v", d)
			}
		})
	}
}
