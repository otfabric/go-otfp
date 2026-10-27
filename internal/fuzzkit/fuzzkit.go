// SPDX-License-Identifier: MIT

// Package fuzzkit fuzzes fingerprinters end to end: a loopback server
// answers the fingerprinter's probes with fuzzer-chosen bytes, and every
// result is checked against the Fingerprinter contract.
package fuzzkit

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/otfabric/go-otfp/core"
)

// Timeout is the per-operation timeout the fuzzed fingerprinters run with.
const Timeout = 60 * time.Millisecond

// maxDuration bounds a whole Detect call. The slowest built-in
// fingerprinters make a few dozen bounded exchanges; a run far beyond this
// means an unbounded loop.
const maxDuration = 64 * Timeout

// Split cuts fuzz input into the server's successive replies: each reply
// is a length octet followed by that many bytes (the last one takes the
// rest). At most 8 replies are produced.
func Split(data []byte) [][]byte {
	var out [][]byte
	for len(data) > 0 && len(out) < 8 {
		n := int(data[0])
		data = data[1:]
		if n > len(data) || len(out) == 7 {
			n = len(data)
		}
		out = append(out, data[:n])
		data = data[n:]
	}
	return out
}

// Join is the inverse of Split, for seeding a corpus with real replies.
func Join(replies ...[]byte) []byte {
	var out []byte
	for i, r := range replies {
		if i == len(replies)-1 || len(r) > 255 {
			out = append(out, 255)
			out = append(out, r...)
			continue
		}
		out = append(out, byte(len(r)))
		out = append(out, r...)
	}
	return out
}

// Detect runs fp against a server replying with Split(data), in detect and
// identify mode, and fails t when the result breaks the contract.
func Detect(t *testing.T, fp core.Fingerprinter, data []byte) {
	t.Helper()
	info := fp.Info()
	replies := Split(data)
	for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
		target := serve(t, info.Network, replies)
		opts := core.Options{Mode: mode, Trace: true, MaxIntrusiveness: core.ReadOnly}
		start := time.Now()
		r, err := fp.Detect(context.Background(), target, opts)
		if d := time.Since(start); d > maxDuration {
			t.Fatalf("%s %s: Detect took %v (bound %v): unbounded exchange", info.Protocol.Slug(), mode, d, maxDuration)
		}
		Check(t, info.Protocol, r, err)
	}
}

// Check fails t when r and err break the Fingerprinter contract.
func Check(t *testing.T, p core.Protocol, r core.Result, err error) {
	t.Helper()
	if r.Protocol != p && r.Protocol != core.ProtocolUnknown {
		t.Fatalf("result protocol %s, want %s", r.Protocol, p)
	}
	if !r.Confidence.Valid() {
		t.Fatalf("confidence %v out of range", r.Confidence)
	}
	if r.Matched != (r.Confidence >= core.MatchThreshold) {
		t.Fatalf("matched=%v with confidence %.2f (threshold %.2f)", r.Matched, r.Confidence, core.MatchThreshold)
	}
	if err != nil && r.Matched {
		t.Fatalf("matched result with error %v", err)
	}
	if err != nil && errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation without a cancelled context: %v", err)
	}
	// An error means "could not decide" and is always a typed transport
	// error. A reply that is merely not this protocol (garbage, a close, a
	// framing mismatch) is a NoMatch result with a nil error.
	if err != nil {
		var te *core.TimeoutError
		var ce *core.ConnectionError
		var de *core.DetectError
		if !errors.As(err, &te) && !errors.As(err, &ce) && !errors.As(err, &de) {
			t.Fatalf("error %T %q is not a transport error: a wrong reply must be a NoMatch", err, err)
		}
	}
	strs := append([]string{r.Variant, r.Details}, r.Evidence...)
	if id := r.Identity; id != nil {
		strs = append(strs, id.Vendor, id.VendorID, id.Product, id.Model, id.Version, id.Serial, id.Name)
		for k, v := range id.Attributes {
			if v == "" {
				t.Fatalf("empty identity attribute %q", k)
			}
			strs = append(strs, k, v)
		}
	}
	if fp := r.Fingerprint; fp != nil {
		strs = append(strs, fp.ID, fp.Signature)
		for k, v := range fp.Metadata {
			strs = append(strs, k, v)
		}
	}
	for _, s := range strs {
		if !utf8.ValidString(s) {
			t.Fatalf("invalid UTF-8 in result: %q", s)
		}
	}
	if _, err := json.Marshal(r); err != nil {
		t.Fatalf("result does not marshal: %v", err)
	}
}

// serve answers successive requests with the replies, then closes (TCP) or
// stays silent (UDP), and returns the target.
func serve(t *testing.T, n core.Network, replies [][]byte) core.Target {
	t.Helper()
	if n == core.UDP {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("loopback exhausted: %v", err) // the environment, not the code
		}
		done := make(chan struct{})
		t.Cleanup(func() { _ = pc.Close(); <-done })
		go func() {
			defer close(done)
			buf := make([]byte, 2048)
			for i := 0; ; i++ {
				_, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				if i < len(replies) && len(replies[i]) > 0 {
					_, _ = pc.WriteTo(replies[i], from)
				}
			}
		}()
		return target(pc.LocalAddr(), n)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback exhausted: %v", err) // the environment, not the code
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	var mu sync.Mutex
	next := 0 // replies are shared across connections, in order
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			// Close with RST: no TIME_WAIT, so fuzzing at thousands of
			// connections per second does not exhaust the loopback ports.
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0)
			}
			go func() {
				defer wg.Done()
				defer c.Close() //nolint:errcheck
				buf := make([]byte, 2048)
				for {
					_ = c.SetReadDeadline(time.Now().Add(maxDuration))
					if _, err := c.Read(buf); err != nil {
						return
					}
					mu.Lock()
					i := next
					next++
					mu.Unlock()
					if i >= len(replies) {
						return // out of replies: close
					}
					if _, err := c.Write(replies[i]); err != nil {
						return
					}
				}
			}()
		}
	}()
	return target(ln.Addr(), n)
}

func target(a net.Addr, n core.Network) core.Target {
	host, port, _ := net.SplitHostPort(a.String())
	p, _ := strconv.Atoi(port)
	return core.Target{Host: host, Port: p, Network: n, Timeout: Timeout}
}
