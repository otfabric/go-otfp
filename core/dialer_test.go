// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func listenTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().String()
}

func TestOptionsDialDefault(t *testing.T) {
	addr := listenTCP(t)
	conn, err := Options{}.Dial(context.Background(), "tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = conn.Close()
	var nilCtx context.Context // accepted like context.Background
	conn, err = Options{}.Dial(nilCtx, "tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Dial with nil ctx: %v", err)
	}
	_ = conn.Close()
}

func TestOptionsDialCustom(t *testing.T) {
	addr := listenTCP(t)
	var gotNetwork, gotAddr string
	var deadline time.Time
	var hasDeadline bool
	opts := Options{Dialer: func(ctx context.Context, network, a string) (net.Conn, error) {
		gotNetwork, gotAddr = network, a
		deadline, hasDeadline = ctx.Deadline()
		var d net.Dialer
		return d.DialContext(ctx, network, a)
	}}
	start := time.Now()
	conn, err := opts.Dial(context.Background(), "tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = conn.Close()
	if gotNetwork != "tcp" || gotAddr != addr {
		t.Errorf("dialer got %s %s, want tcp %s", gotNetwork, gotAddr, addr)
	}
	if !hasDeadline || deadline.Before(start.Add(2*time.Second)) || deadline.After(time.Now().Add(2*time.Second)) {
		t.Errorf("dialer deadline %v (set %v), want the 2s timeout", deadline, hasDeadline)
	}
}

func TestOptionsDialNoTimeoutNoDeadline(t *testing.T) {
	var hasDeadline bool
	opts := Options{Dialer: func(ctx context.Context, _, _ string) (net.Conn, error) {
		_, hasDeadline = ctx.Deadline()
		return nil, errors.New("stop")
	}}
	_, _ = opts.Dial(context.Background(), "udp", "127.0.0.1:1", 0)
	if hasDeadline {
		t.Error("dialer context has a deadline although the timeout is 0")
	}
}

func TestOptionsDialErrors(t *testing.T) {
	errBlocked := errors.New("blocked")
	opts := Options{Dialer: func(context.Context, string, string) (net.Conn, error) { return nil, errBlocked }}
	if _, err := opts.Dial(context.Background(), "tcp", "127.0.0.1:1", time.Second); !errors.Is(err, errBlocked) {
		t.Errorf("err = %v, want the dialer's error", err)
	}
	opts.Dialer = func(context.Context, string, string) (net.Conn, error) { return nil, nil }
	if _, err := opts.Dial(context.Background(), "tcp", "127.0.0.1:1", time.Second); !errors.Is(err, errNoConnection) {
		t.Errorf("err = %v, want errNoConnection", err)
	}
	// A dialer error reaches the caller through ClassifyDial.
	opts.Dialer = func(context.Context, string, string) (net.Conn, error) { return nil, errBlocked }
	_, err := opts.Dial(context.Background(), "tcp", "127.0.0.1:1", time.Second)
	if cerr := ClassifyDial(ProtocolModbus, "127.0.0.1:1", err); !errors.Is(cerr, errBlocked) {
		t.Errorf("classified %v, want it to wrap the dialer's error", cerr)
	}
}

type closeCounting struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeCounting) Close() error { c.closed.Store(true); return nil }

func TestOptionsDialClosesConnWithError(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	cc := &closeCounting{Conn: a}
	errBlocked := errors.New("blocked")
	opts := Options{Dialer: func(context.Context, string, string) (net.Conn, error) { return cc, errBlocked }}
	conn, err := opts.Dial(context.Background(), "tcp", "x:1", time.Second)
	if conn != nil || !errors.Is(err, errBlocked) {
		t.Fatalf("Dial = %v, %v; want nil and the dialer's error", conn, err)
	}
	if !cc.closed.Load() {
		t.Error("connection returned with an error was not closed")
	}
}

func TestEngineOptionsCarryDialer(t *testing.T) {
	d := Dialer(func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("x") })
	e := NewEngine(NewRegistry(), EngineConfig{Dialer: d})
	if e.options().Dialer == nil {
		t.Error("EngineConfig.Dialer not passed to the fingerprinters' Options")
	}
}
