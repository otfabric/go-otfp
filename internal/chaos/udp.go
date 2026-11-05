// SPDX-License-Identifier: MIT

package chaos

import (
	"net"
	"sync"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// UDPFault is a fault of a UDP endpoint.
type UDPFault uint8

// UDP faults. Those up to Oversize still deliver the right answer: a
// fingerprinter must match its own protocol through them.
const (
	// UDPClean answers every request once.
	UDPClean UDPFault = iota
	// Drop drops every other answer (the first, third ...): one
	// retransmission recovers each.
	Drop
	// UDPDuplicate sends every answer twice.
	UDPDuplicate
	// Reorder holds an answer back and sends it after the answer to the
	// next request (a late answer).
	Reorder
	// Flood sends a bounded burst of spoofed datagrams, from the
	// endpoint's own address, before every answer.
	Flood
	// Empty sends a zero-length datagram before every answer.
	Empty
	// Oversize sends a datagram of the largest size the loopback accepts
	// (up to 65507 octets) before every answer.
	Oversize
	// UDPTruncate cuts every answer at a random point.
	UDPTruncate
	// UDPBitFlip flips one random bit of every answer.
	UDPBitFlip
	// OtherPort answers from a different socket, so the answer comes
	// from another source port.
	OtherPort
)

// UDPFaults lists every UDP fault.
var UDPFaults = []UDPFault{UDPClean, Drop, UDPDuplicate, Reorder, Flood, Empty, Oversize, UDPTruncate, UDPBitFlip, OtherPort}

var udpFaultNames = [...]string{"clean", "drop", "duplicate", "reorder", "flood", "empty", "oversize", "truncate", "bit-flip", "other-port"}

// String returns the fault's name.
func (f UDPFault) String() string {
	if int(f) < len(udpFaultNames) {
		return udpFaultNames[f]
	}
	return "fault?"
}

// Complete reports whether the right answer still reaches the client.
func (f UDPFault) Complete() bool { return f <= Oversize }

// FloodSize is the number of spoofed datagrams of one Flood burst. A
// loopback socket buffer holds far more, even under -race on a loaded CI
// runner (a 500-datagram burst does not).
const FloodSize = 24

// UDPConfig selects a UDP fault.
type UDPConfig struct {
	Fault UDPFault
	Seed  uint64
	// Spoof, when set, makes the Flood datagrams: the i-th spoofed
	// datagram before the answer to req (for example a plausible frame of
	// the protocol with the wrong correlation identifier). The default is
	// random octets.
	Spoof func(req []byte, i int) []byte
}

// UDP serves h on loopback UDP behind cfg's fault until the test ends.
func UDP(t testing.TB, cfg UDPConfig, h testsrv.Handler) core.Target {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var other net.PacketConn
	if cfg.Fault == OtherPort {
		if other, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = pc.Close()
		if other != nil {
			_ = other.Close()
		}
		wg.Wait()
	})
	rng := NewRand(cfg.Seed)
	wg.Go(func() {
		var held []byte
		answers := 0
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
			answers++
			send := func(b []byte) { _, _ = pc.WriteTo(b, from) }
			switch cfg.Fault {
			case Drop:
				if answers%2 == 1 {
					continue
				}
				send(resp)
			case UDPDuplicate:
				send(resp)
				send(resp)
			case Reorder:
				if held == nil {
					held = resp
					continue
				}
				send(resp)
				send(held)
				held = nil
			case Flood:
				for i := range FloodSize {
					if cfg.Spoof != nil {
						send(cfg.Spoof(req, i))
						continue
					}
					junk := make([]byte, 1+rng.Intn(64))
					for j := range junk {
						junk[j] = byte(rng.Uint64() & 0xFF)
					}
					send(junk)
				}
				send(resp)
			case Empty:
				send(nil)
				send(resp)
			case Oversize:
				sendLargest(pc, from)
				send(resp)
			case UDPTruncate:
				send(resp[:rng.Intn(len(resp))])
			case UDPBitFlip:
				out := append([]byte(nil), resp...)
				if len(out) > 0 {
					bit := rng.Intn(8 * len(out))
					out[bit/8] ^= 1 << (bit % 8)
				}
				send(out)
			case OtherPort:
				_, _ = other.WriteTo(resp, from)
			default:
				send(resp)
			}
		}
	})
	return Target(t, pc.LocalAddr(), core.UDP)
}

// sendLargest sends the largest datagram the loopback accepts, starting at
// the IPv4 maximum of 65507 octets (macOS limits loopback datagrams to its
// net.inet.udp.maxdgram, 9216 by default).
func sendLargest(pc net.PacketConn, to net.Addr) {
	big := make([]byte, 65507)
	for i := range big {
		big[i] = 0xA5
	}
	for _, n := range []int{65507, 32768, 16384, 9216, 8192} {
		if _, err := pc.WriteTo(big[:n], to); err == nil {
			return
		}
	}
}

// ClosedUDP returns a UDP target on which nothing listens: a connected
// socket reading from it gets ECONNREFUSED (the ICMP port unreachable).
func ClosedUDP(t testing.TB) core.Target {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := pc.LocalAddr()
	_ = pc.Close()
	return Target(t, a, core.UDP)
}
