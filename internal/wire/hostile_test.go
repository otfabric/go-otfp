// SPDX-License-Identifier: MIT

package wire_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/wire"
)

// datagrams answers every request with the given datagrams, in order.
func datagrams(t *testing.T, dgs ...[]byte) core.Target {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = pc.Close(); wg.Wait() })
	wg.Go(func() {
		buf := make([]byte, 2048)
		for {
			_, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			for _, dg := range dgs {
				_, _ = pc.WriteTo(dg, from)
			}
		}
	})
	return chaos.Target(t, pc.LocalAddr(), core.UDP)
}

func verdict(dg []byte) wire.Verdict {
	switch {
	case bytes.HasPrefix(dg, []byte("answer")):
		return wire.Answer
	case bytes.HasPrefix(dg, []byte("stale")):
		return wire.Discard
	}
	return wire.Foreign
}

// The answer wins over foreign and stale datagrams that arrive first; a
// foreign datagram is returned only when no answer comes; an empty
// datagram is foreign.
func TestDatagramVerdicts(t *testing.T) {
	cases := map[string]struct {
		dgs  [][]byte
		want []byte
	}{
		"answer after junk":  {[][]byte{[]byte("junk"), []byte("stale"), {}, []byte("answer")}, []byte("answer")},
		"foreign only":       {[][]byte{[]byte("junk1"), []byte("junk2")}, []byte("junk1")},
		"empty only":         {[][]byte{{}}, []byte{}},
		"empty then answer":  {[][]byte{{}, []byte("answer!")}, []byte("answer!")},
		"stale then foreign": {[][]byte{[]byte("stale"), []byte("x")}, []byte("x")},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			target := datagrams(t, c.dgs...)
			target.Timeout = 400 * time.Millisecond
			s := dial(t, target, core.Options{Trace: true})
			defer func() { _ = s.Close() }()
			start := time.Now()
			got, err := s.RoundTripDatagram("probe", []byte("probe"), 1500, verdict)
			if err != nil || !bytes.Equal(got, c.want) || got == nil {
				t.Fatalf("got %q (%v), want %q", got, err, c.want)
			}
			// A foreign datagram ends the exchange at the end of the
			// first window: no retransmission.
			if d := time.Since(start); d > 350*time.Millisecond {
				t.Fatalf("took %v", d)
			}
		})
	}
	// Only stale datagrams: a timeout, after the retransmission.
	target := datagrams(t, []byte("stale"))
	target.Timeout = 200 * time.Millisecond
	s := dial(t, target, core.Options{})
	defer func() { _ = s.Close() }()
	if _, err := s.RoundTripDatagram("probe", []byte("probe"), 1500, verdict); !core.IsTimeout(err) {
		t.Fatalf("stale only: %v", err)
	}
}

// RoundTripUDP keeps its accept/discard meaning on top of the verdicts.
func TestRoundTripUDPAccept(t *testing.T) {
	target := datagrams(t, []byte("no"), []byte("yes"))
	s := dial(t, target, core.Options{})
	defer func() { _ = s.Close() }()
	got, err := s.RoundTripUDP("probe", []byte("p"), 64, func(dg []byte) bool { return string(dg) == "yes" })
	if err != nil || string(got) != "yes" {
		t.Fatalf("%q %v", got, err)
	}
}

// An ICMP port unreachable fails the exchange at once as a refused
// connection, not as a timeout.
func TestDatagramPortUnreachable(t *testing.T) {
	target := chaos.ClosedUDP(t)
	target.Timeout = time.Second
	s := dial(t, target, core.Options{})
	defer func() { _ = s.Close() }()
	start := time.Now()
	_, err := s.RoundTripDatagram("probe", []byte("probe"), 64, verdict)
	var ce *core.ConnectionError
	if !errors.As(err, &ce) || !ce.Refused() {
		t.Fatalf("%T %v", err, err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("took %v", d)
	}
}

// A framed read reassembles a frame written one octet at a time, and
// returns a prefix cut by a stall after the idle gap, not the timeout.
func TestFramedReadUnderChaos(t *testing.T) {
	payload := bytes.Repeat([]byte("0123456789"), 50)
	reply := binary.BigEndian.AppendUint16(nil, wire.Len16(len(payload)))
	reply = append(reply, payload...)
	for _, f := range []chaos.Fault{chaos.OneByte, chaos.Chunks, chaos.Delay} {
		target := chaos.TCP(t, chaos.Config{Fault: f, Seed: 3}, func([]byte) ([]byte, bool) { return reply, false })
		s := dial(t, target, core.Options{})
		got, err := s.RoundTrip("x", []byte("x"), lenFramer, 4096)
		_ = s.Close()
		if err != nil || !bytes.Equal(got, reply) {
			t.Fatalf("%s: %d octets (%v)", f, len(got), err)
		}
	}
	target := chaos.TCP(t, chaos.Config{Fault: chaos.Stall, Seed: 5}, func([]byte) ([]byte, bool) { return reply, false })
	target.Timeout = 4 * time.Second // the idle gap is a quarter of it
	s := dial(t, target, core.Options{})
	defer func() { _ = s.Close() }()
	start := time.Now()
	got, err := s.RoundTrip("x", []byte("x"), lenFramer, 4096)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("a stalled frame took %v", d)
	}
	if len(got) > 0 && (err != nil || len(got) >= len(reply)) {
		t.Fatalf("%d octets (%v)", len(got), err)
	}
}

// A context deadline ends a datagram exchange promptly, as a timeout.
func TestDatagramCancelled(t *testing.T) {
	target := datagrams(t)
	target.Timeout = 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	s, err := wire.Dial(ctx, core.ProtocolBACnet, target, core.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	// At the context's deadline the I/O deadline fires too: either error
	// may win, both are timeouts.
	start := time.Now()
	var te *core.TimeoutError
	if _, err := s.RoundTripDatagram("probe", []byte("probe"), 64, verdict); !errors.As(err, &te) {
		t.Fatalf("%T %v", err, err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("a cancelled exchange took %v", d)
	}
}
