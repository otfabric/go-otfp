// SPDX-License-Identifier: MIT

package wire_test

import (
	"context"
	"encoding/binary"
	"errors"
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
