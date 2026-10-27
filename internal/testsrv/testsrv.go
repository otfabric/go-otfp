// SPDX-License-Identifier: MIT

// Package testsrv runs scripted fake endpoints on loopback for the
// fingerprinters' unit tests.
package testsrv

import (
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
)

// Handler answers one request; returning nil sends nothing, and close
// reports whether to close the connection afterwards.
type Handler func(req []byte) (resp []byte, closeConn bool)

// TCP serves h on a loopback TCP listener until the test ends and returns
// a target for it. Each read of the server is one request; tests should
// send whole frames, as the fingerprinters do.
func TCP(t testing.TB, h Handler) core.Target {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close() //nolint:errcheck
				buf := make([]byte, 65536)
				for {
					_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					resp, closeConn := h(append([]byte(nil), buf[:n]...))
					if resp != nil {
						if _, err := c.Write(resp); err != nil {
							return
						}
					}
					if closeConn {
						return
					}
				}
			}()
		}
	}()
	return target(t, ln.Addr(), core.TCP)
}

// Raw serves fn with every accepted connection, for tests that need full
// control (TLS, partial writes, silence).
func Raw(t testing.TB, fn func(c net.Conn)) core.Target {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close() //nolint:errcheck
				fn(c)
			}()
		}
	}()
	return target(t, ln.Addr(), core.TCP)
}

// UDP serves h on a loopback UDP socket: each datagram is a request.
func UDP(t testing.TB, h Handler) core.Target {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { _ = pc.Close(); <-done })
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp, _ := h(append([]byte(nil), buf[:n]...)); resp != nil {
				_, _ = pc.WriteTo(resp, from)
			}
		}
	}()
	return target(t, pc.LocalAddr(), core.UDP)
}

// Closed returns a TCP target on which nothing listens.
func Closed(t testing.TB) core.Target {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr()
	_ = ln.Close()
	return target(t, addr, core.TCP)
}

// Script returns a handler that answers the i-th request with resps[i] and
// stays silent after the last.
func Script(resps ...[]byte) Handler {
	var mu sync.Mutex
	i := 0
	return func([]byte) ([]byte, bool) {
		mu.Lock()
		defer mu.Unlock()
		if i >= len(resps) {
			return nil, false
		}
		i++
		return resps[i-1], false
	}
}

func target(t testing.TB, a net.Addr, n core.Network) core.Target {
	t.Helper()
	host, port, err := net.SplitHostPort(a.String())
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(port)
	return core.Target{Host: host, Port: p, Network: n, Timeout: 2 * time.Second}
}
