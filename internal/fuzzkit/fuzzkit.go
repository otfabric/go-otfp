// SPDX-License-Identifier: MIT

// Package fuzzkit fuzzes fingerprinters end to end: a loopback server
// answers the fingerprinter's probes with fuzzer-chosen bytes, and every
// result is checked against the Fingerprinter contract.
package fuzzkit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/otfabric/go-otfp/core"
)

// Timeout is the per-operation timeout the fuzzed fingerprinters run with.
const Timeout = 60 * time.Millisecond

// maxDuration bounds a whole Detect call. The slowest built-in
// fingerprinters make a few dozen bounded exchanges; a run far beyond this
// means an unbounded loop.
const maxDuration = 64 * Timeout

// maxRunes bounds every string of a result (fpx.MaxLine).
const maxRunes = 4096

// NonText holds characters that are not text for a terminal or a log line:
// C0 controls (ESC, BEL, CR, LF, TAB), DEL, C1 controls (NEL, CSI), format
// characters (a directional override, a zero-width space, a byte order
// mark), the line and paragraph separators and an octet that is not UTF-8.
// Tests put it into what a fake endpoint sends and expect none of it in a
// Result.
const NonText = "\x1b\a\r\n\t\x7f\u0085\u009b\u202e\u200b\ufeff\u2028\u2029\xff"

// Allocated returns the octets f allocates while it runs, garbage included
// (runtime.MemStats.TotalAlloc), for the allocation budgets of the limit
// tests: a budget derived from the input size shows that nothing of a
// declared or unbounded size was allocated, which a run that merely ends
// does not. The figure is the whole process's: a test that uses it does not
// call t.Parallel, and keeps its budget well above the work of a fake peer
// that runs beside f.
func Allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

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
		n := len(r)
		if i == len(replies)-1 || n > 255 {
			out = append(out, 255)
			out = append(out, r...)
			continue
		}
		out = append(out, byte(n))
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

// Limit is one case of a limit test: what the peer answers, in which mode,
// and how much the probe may allocate for it.
type Limit struct {
	Name string
	// Mode is ModeDetect unless set.
	Mode core.Mode
	// Replies are the peer's successive replies, one per request it reads
	// (as in Detect). A reply at a limit and one just beyond it are the
	// two cases a limit needs.
	Replies [][]byte
	// Budget is the most octets Detect may allocate, garbage included. It
	// is derived from what the fingerprinter may read for the case, with
	// room to spare: at a limit a few times the limit, beyond it far less
	// than the size the peer declared.
	Budget uint64
	// Want, when set, checks the outcome.
	Want func(t *testing.T, r core.Result, err error)
	// Timeout is the target's timeout; LimitTimeout unless set.
	Timeout time.Duration
}

// LimitTimeout is the per-operation timeout of a limit test: long enough
// for a megabyte to arrive on loopback under the race detector.
const LimitTimeout = time.Second

// Limits runs fp against a peer for each case and fails t when the result
// breaks the Fingerprinter contract, when Detect takes longer than any
// peer may make it take, or when it allocates more than the case's budget.
// The cases run one after the other: the allocation count is the
// process's.
func Limits(t *testing.T, fp core.Fingerprinter, cases ...Limit) {
	t.Helper()
	info := fp.Info()
	for _, c := range cases {
		target := serve(t, info.Network, c.Replies)
		target.Timeout = c.Timeout
		if target.Timeout <= 0 {
			target.Timeout = LimitTimeout
		}
		opts := core.Options{Mode: c.Mode, MaxIntrusiveness: core.ReadOnly}
		var r core.Result
		var err error
		start := time.Now()
		allocated := Allocated(func() { r, err = fp.Detect(context.Background(), target, opts) })
		if d, bound := time.Since(start), 64*target.Timeout; d > bound {
			t.Errorf("%s: Detect took %v (bound %v)", c.Name, d, bound)
		}
		if testing.Verbose() {
			t.Logf("%s: %d octets allocated (budget %d): %v, %v", c.Name, allocated, c.Budget, r, err)
		}
		if msg := Violation(info.Protocol, r, err); msg != "" {
			t.Errorf("%s: %s", c.Name, msg)
		}
		if allocated > c.Budget {
			t.Errorf("%s: %d octets allocated, budget %d", c.Name, allocated, c.Budget)
		}
		if c.Want != nil {
			c.Want(t, r, err)
		}
	}
}

// Check fails t when r and err break the Fingerprinter contract.
func Check(t *testing.T, p core.Protocol, r core.Result, err error) {
	t.Helper()
	if msg := Violation(p, r, err); msg != "" {
		t.Fatal(msg)
	}
}

// Violation describes how r and err break the Fingerprinter contract, or
// returns "" when they keep it. Unlike Check it is safe in goroutines.
func Violation(p core.Protocol, r core.Result, err error) string {
	if r.Protocol != p && r.Protocol != core.ProtocolUnknown {
		return fmt.Sprintf("result protocol %s, want %s", r.Protocol, p)
	}
	if !r.Confidence.Valid() {
		return fmt.Sprintf("confidence %v out of range", r.Confidence)
	}
	if r.Matched != (r.Confidence >= core.MatchThreshold) {
		return fmt.Sprintf("matched=%v with confidence %.2f (threshold %.2f)", r.Matched, r.Confidence, core.MatchThreshold)
	}
	if err != nil && r.Matched {
		return fmt.Sprintf("matched result with error %v", err)
	}
	if err != nil && errors.Is(err, context.Canceled) {
		return fmt.Sprintf("cancellation without a cancelled context: %v", err)
	}
	// An error means "could not decide" and is always a typed transport
	// error. A reply that is merely not this protocol (garbage, a close, a
	// framing mismatch) is a NoMatch result with a nil error.
	if err != nil {
		var te *core.TimeoutError
		var ce *core.ConnectionError
		var de *core.DetectError
		if !errors.As(err, &te) && !errors.As(err, &ce) && !errors.As(err, &de) {
			return fmt.Sprintf("error %T %q is not a transport error: a wrong reply must be a NoMatch", err, err)
		}
	}
	strs := append([]string{r.Variant, r.Details}, r.Evidence...)
	if id := r.Identity; id != nil {
		strs = append(strs, id.Vendor, id.VendorID, id.Product, id.Model, id.Version, id.Serial, id.Name)
		for k, v := range id.Attributes {
			if v == "" {
				return fmt.Sprintf("empty identity attribute %q", k)
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
	// Every string of a result is text for a person or a log: valid UTF-8
	// of graphic characters only (no control or format character, no line
	// separator), and bounded.
	for _, s := range strs {
		if !utf8.ValidString(s) {
			return fmt.Sprintf("invalid UTF-8 in result: %q", s)
		}
		n := 0
		for _, r := range s {
			if !unicode.IsGraphic(r) {
				return fmt.Sprintf("character %U that is not graphic in result: %q", r, s)
			}
			n++
		}
		if n > maxRunes {
			return fmt.Sprintf("result string of %d runes (bound %d): %.80q...", n, maxRunes, s)
		}
	}
	if _, err := json.Marshal(r); err != nil {
		return fmt.Sprintf("result does not marshal: %v", err)
	}
	return ""
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
	wg.Go(func() {
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
	})
	return target(ln.Addr(), n)
}

func target(a net.Addr, n core.Network) core.Target {
	host, port, _ := net.SplitHostPort(a.String())
	p, _ := strconv.Atoi(port)
	return core.Target{Host: host, Port: p, Network: n, Timeout: Timeout}
}
