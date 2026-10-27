// SPDX-License-Identifier: MIT

package wire_test

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
	"github.com/otfabric/go-otfp/internal/wire"
)

// lenFramer frames a 2-byte big-endian length prefix plus payload.
var lenFramer = wire.FixedHeader(2, func(h []byte) int { return 2 + int(binary.BigEndian.Uint16(h)) })

func dial(t *testing.T, target core.Target, opts core.Options) *wire.Session {
	t.Helper()
	s, err := wire.Dial(context.Background(), core.ProtocolModbus, target, opts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFramedReadKeepsOverflow(t *testing.T) {
	// The server sends two frames in one write; two Reads must split them.
	frame := func(p string) []byte { return append([]byte{0, byte(len(p))}, p...) }
	target := testsrv.TCP(t, testsrv.Script(append(frame("AB"), frame("CDE")...)))
	s := dial(t, target, core.Options{Trace: true})
	defer s.Close()
	first, err := s.RoundTrip("one", []byte("go"), lenFramer, 64)
	if err != nil || string(first[2:]) != "AB" {
		t.Fatalf("first %q %v", first, err)
	}
	second, err := s.Next("two", lenFramer, 64)
	if err != nil || string(second[2:]) != "CDE" {
		t.Fatalf("second %q %v", second, err)
	}
	if len(s.Exchanges()) != 2 {
		t.Fatalf("%d exchanges", len(s.Exchanges()))
	}
}

func TestClosedReturnsErrClosed(t *testing.T) {
	target := testsrv.TCP(t, func([]byte) ([]byte, bool) { return nil, true })
	s := dial(t, target, core.Options{})
	defer s.Close()
	_, err := s.RoundTrip("x", []byte("hi"), lenFramer, 64)
	if !errors.Is(err, wire.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
}

func TestTimeout(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script())
	target.Timeout = 150 * time.Millisecond
	s := dial(t, target, core.Options{})
	defer s.Close()
	_, err := s.RoundTrip("x", []byte("hi"), lenFramer, 64)
	var te *core.TimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("want TimeoutError, got %v", err)
	}
}

func TestContextCancel(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script())
	ctx, cancel := context.WithCancel(context.Background())
	s, err := wire.Dial(ctx, core.ProtocolModbus, target, core.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	_, err = s.RoundTrip("x", []byte("hi"), lenFramer, 64)
	if err == nil {
		t.Fatal("want error on cancel")
	}
}

func TestUDPRoundTrip(t *testing.T) {
	target := testsrv.UDP(t, testsrv.Script([]byte{0, 1, 'Z'}))
	s := dial(t, target, core.Options{})
	defer s.Close()
	resp, err := s.RoundTrip("x", []byte("ping"), nil, 64)
	if err != nil || len(resp) != 3 {
		t.Fatalf("%q %v", resp, err)
	}
}

func TestDialFails(t *testing.T) {
	_, err := wire.Dial(context.Background(), core.ProtocolModbus, testsrv.Closed(t), core.Options{})
	var ce *core.ConnectionError
	if !errors.As(err, &ce) {
		t.Fatalf("want ConnectionError, got %v", err)
	}
}

func TestWrapAndAccessors(t *testing.T) {
	// Wrap an in-memory pipe as a session.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	target := core.Target{Host: "127.0.0.1", Port: 1}
	s := wire.Wrap(context.Background(), core.ProtocolModbus, target, c1, core.Options{Trace: true})
	if s.Conn() != c1 || s.Timeout() <= 0 {
		t.Fatal("accessors")
	}
	go func() { b := make([]byte, 8); _, _ = c2.Read(b); _, _ = c2.Write([]byte{0, 1, 'Z'}) }()
	resp, err := s.RoundTrip("x", []byte("hi"), lenFramer, 16)
	if err != nil || len(resp) != 3 {
		t.Fatalf("%q %v", resp, err)
	}
	s.Record("manual", []byte("p"), []byte("r"))
	if len(s.Exchanges()) != 2 {
		t.Fatalf("%d exchanges", len(s.Exchanges()))
	}
}

func TestUDPRetries(t *testing.T) {
	// The server answers only the second datagram.
	var n int
	target := testsrv.UDP(t, func([]byte) ([]byte, bool) {
		n++
		if n < 2 {
			return nil, false
		}
		return []byte{0, 1, 'Z'}, false
	})
	target.Timeout = 600 * time.Millisecond
	s := dial(t, target, core.Options{})
	defer s.Close()
	s.Retries = 2
	resp, err := s.RoundTrip("x", []byte("ping"), nil, 16)
	if err != nil || len(resp) != 3 {
		t.Fatalf("%q %v", resp, err)
	}
}

// A cancellation that happens before an operation arms its deadline must
// still stop it: the operation's own SetDeadline would otherwise override the
// past deadline set on cancel and wait out the full timeout.
func TestCancelBeforeOperation(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script())
	target.Timeout = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	s, err := wire.Dial(ctx, core.ProtocolModbus, target, core.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cancel()
	start := time.Now()
	_, err = s.RoundTrip("x", []byte("hi"), lenFramer, 64)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("cancelled read took %v", d)
	}
	// And every later step returns at once too.
	start = time.Now()
	if _, err := s.Next("y", lenFramer, 64); err == nil || time.Since(start) > time.Second {
		t.Fatalf("second step: %v after %v", err, time.Since(start))
	}
}

// The scan's overall deadline caps every per-operation timeout.
func TestContextDeadlineCapsTimeout(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script())
	target.Timeout = 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	s, err := wire.Dial(ctx, core.ProtocolModbus, target, core.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	start := time.Now()
	_, err = s.RoundTrip("x", []byte("hi"), lenFramer, 64)
	var te *core.TimeoutError
	if !errors.As(err, &te) || time.Since(start) > 2*time.Second {
		t.Fatalf("want a prompt TimeoutError, got %v after %v", err, time.Since(start))
	}
}

// A stray datagram (a late answer to an earlier request) is discarded by
// RoundTripUDP instead of being taken as the answer.
func TestRoundTripUDPDiscardsStray(t *testing.T) {
	target := testsrv.UDP(t, func(req []byte) ([]byte, bool) { return nil, false })
	// Replace the silent server with one that sends a stray then the answer.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 64)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo([]byte("stray"), from)
		_, _ = pc.WriteTo(append([]byte("ok:"), buf[:n]...), from)
	}()
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	target.Port = atoi(port)
	s := dial(t, target, core.Options{Trace: true})
	defer s.Close()
	resp, err := s.RoundTripUDP("x", []byte("req"), 64, func(b []byte) bool { return len(b) > 3 && string(b[:3]) == "ok:" })
	if err != nil || string(resp) != "ok:req" {
		t.Fatalf("%q %v", resp, err)
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// A peer that starts a frame and never finishes it costs the idle gap, not
// the whole timeout; the partial frame is returned for judging.
func TestIdleGapAfterPartialFrame(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script([]byte{0, 20, 'p', 'a', 'r', 't'})) // promises 20, sends 4
	target.Timeout = 5 * time.Second
	s := dial(t, target, core.Options{})
	defer s.Close()
	start := time.Now()
	resp, err := s.RoundTrip("x", []byte("hi"), lenFramer, 64)
	if err != nil || string(resp[2:]) != "part" {
		t.Fatalf("%q %v", resp, err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("partial frame took %v; the idle gap is %v", d, max(250*time.Millisecond, target.Timeout/4))
	}
}

func TestIsTransport(t *testing.T) {
	for _, err := range []error{&core.TimeoutError{}, &core.ConnectionError{}, &core.DetectError{}} {
		if !wire.IsTransport(err) {
			t.Errorf("%T", err)
		}
	}
	if wire.IsTransport(wire.ErrClosed) || wire.IsTransport(errors.New("parse")) || wire.IsTransport(nil) {
		t.Fatal("non-transport errors")
	}
}

func TestFixedHeaderFramer(t *testing.T) {
	f := wire.FixedHeader(4, func(h []byte) int { return int(h[3]) })
	if f([]byte{1, 2}) != 0 || f([]byte{0, 0, 0, 2}) != -1 || f([]byte{0, 0, 0, 9}) != 9 {
		t.Fatal("FixedHeader")
	}
}

// A frame larger than max returns what fits; with no framer, the first
// chunk; with a framer that rejects, what was read.
func TestReadLimits(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script([]byte("0123456789")))
	s := dial(t, target, core.Options{})
	defer s.Close()
	if resp, err := s.RoundTrip("x", []byte("q"), func([]byte) int { return 0 }, 4); err != nil || string(resp) != "0123" {
		t.Fatalf("max: %q %v", resp, err)
	}
	if resp, err := s.Read(nil, 64); err != nil || string(resp) != "456789" {
		t.Fatalf("no framer: %q %v", resp, err)
	}
	target = testsrv.TCP(t, testsrv.Script([]byte("xyz")))
	s2 := dial(t, target, core.Options{})
	defer s2.Close()
	if resp, err := s2.RoundTrip("x", []byte("q"), func([]byte) int { return -1 }, 64); err != nil || string(resp) != "xyz" {
		t.Fatalf("reject: %q %v", resp, err)
	}
}

// Writes and reads on a closed connection are DetectErrors; reads after the
// peer reset with nothing received are ErrClosed.
func TestIOAfterClose(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script())
	s := dial(t, target, core.Options{})
	_ = s.Conn().Close()
	var de *core.DetectError
	if err := s.Send([]byte("x")); !errors.As(err, &de) {
		t.Fatalf("send on closed: %v", err)
	}
	if _, err := s.Read(lenFramer, 8); !errors.As(err, &de) {
		t.Fatalf("read on closed: %v", err)
	}
	u := testsrv.UDP(t, testsrv.Script())
	su := dial(t, u, core.Options{})
	_ = su.Conn().Close()
	if _, err := su.RoundTrip("x", []byte("q"), nil, 8); !errors.As(err, &de) {
		t.Fatalf("udp send on closed: %v", err)
	}
	if _, err := su.RoundTripUDP("x", []byte("q"), 8, nil); err == nil {
		t.Fatal("udp on closed")
	}
}

// UDP to a port where nothing listens: ICMP port unreachable surfaces as a
// refused ConnectionError on the connected socket's read.
func TestUDPPortUnreachable(t *testing.T) {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	_ = pc.Close()
	target := core.Target{Host: "127.0.0.1", Port: atoi(port), Network: core.UDP, Timeout: 500 * time.Millisecond}
	s := dial(t, target, core.Options{})
	defer s.Close()
	_, err := s.RoundTrip("x", []byte("q"), nil, 8)
	if !wire.IsTransport(err) {
		t.Fatalf("want a transport error, got %v", err)
	}
}

// The context deadline also caps a ReadUntil window.
func TestReadUntilCappedByContext(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script())
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	s, _ := wire.Dial(ctx, core.ProtocolModbus, target, core.Options{})
	defer s.Close()
	start := time.Now()
	_, _ = s.ReadUntil(lenFramer, 8, time.Now().Add(time.Hour))
	if time.Since(start) > 2*time.Second {
		t.Fatalf("took %v", time.Since(start))
	}
}
