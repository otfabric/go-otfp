// SPDX-License-Identifier: MIT

// Package chaos injects deterministic, seeded transport faults between the
// fingerprinters and the scripted endpoints of their tests: a net.Conn and
// listener wrapper whose writes are fragmented, delayed, duplicated,
// bit-flipped, truncated, reset or stalled, and a UDP endpoint that drops,
// duplicates, reorders, truncates and corrupts datagrams, floods spoofed
// ones before the answer or answers from another port.
//
// Every fault is driven by a seed, so a failing case replays exactly. The
// pseudo-random source is a splitmix64 generator: fault injection needs
// reproducibility, not unpredictability.
package chaos

import (
	"errors"
	"io"
	"math"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// Rand is a deterministic splitmix64 generator.
type Rand struct{ s uint64 }

// NewRand returns a generator seeded with seed.
func NewRand(seed uint64) *Rand { return &Rand{s: seed} }

// Uint64 returns the next pseudo-random value.
func (r *Rand) Uint64() uint64 {
	r.s += 0x9e3779b97f4a7c15
	z := r.s
	z = (z ^ z>>30) * 0xbf58476d1ce4e5b9
	z = (z ^ z>>27) * 0x94d049bb133111eb
	return z ^ z>>31
}

// Intn returns a value in [0, n), or 0 when n < 1.
func (r *Rand) Intn(n int) int {
	if n < 1 {
		return 0
	}
	v := r.Uint64() >> 33 // 31 bits: fits every int
	if v > math.MaxInt32 {
		v = 0
	}
	return int(v) % n
}

// Duration returns a duration in [0, d), or 0 when d <= 0.
func (r *Rand) Duration(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	v := r.Uint64() >> 1
	if v > math.MaxInt64 {
		v = 0
	}
	return time.Duration(int64(v) % int64(d))
}

// Fault is a TCP fault applied to the endpoint's writes.
type Fault uint8

// TCP faults. The first four deliver every byte, intact and in order: a
// fingerprinter must still match its own protocol through them.
const (
	// Clean writes unchanged.
	Clean Fault = iota
	// OneByte splits every write into 1-octet writes.
	OneByte
	// Chunks splits every write at random points.
	Chunks
	// Delay splits every write at random points and pauses between the
	// pieces (up to Config.MaxDelay, far below the read idle gap).
	Delay
	// Duplicate writes the response twice.
	Duplicate
	// BitFlip flips one random bit of the response.
	BitFlip
	// Truncate writes a prefix of the response, then closes (FIN).
	Truncate
	// Reset writes a prefix of the response, then resets (RST).
	Reset
	// Stall writes a prefix of the response, then sends nothing more and
	// discards what it receives until the client closes.
	Stall
)

// Faults lists every TCP fault.
var Faults = []Fault{Clean, OneByte, Chunks, Delay, Duplicate, BitFlip, Truncate, Reset, Stall}

var faultNames = [...]string{"clean", "one-byte", "chunks", "delay", "duplicate", "bit-flip", "truncate", "reset", "stall"}

// String returns the fault's name.
func (f Fault) String() string {
	if int(f) < len(faultNames) {
		return faultNames[f]
	}
	return "fault?"
}

// Complete reports whether the fault delivers every response octet intact
// and in order.
func (f Fault) Complete() bool { return f <= Delay }

// Lossy reports whether the fault cuts the response short.
func (f Fault) Lossy() bool { return f >= Truncate }

// Config selects a fault.
type Config struct {
	Fault Fault
	// Seed drives every random choice; connections derive their own seed
	// from it and their accept order.
	Seed uint64
	// After is the number of writes of a connection that pass untouched
	// before a Duplicate, BitFlip or lossy fault strikes (fragmenting
	// faults apply to every write).
	After int
	// MaxDelay bounds a Delay pause (default 3 ms).
	MaxDelay time.Duration
}

// errInjected is what a faulted write returns to the endpoint once the
// connection is dead.
var errInjected = errors.New("chaos: connection cut by an injected fault")

// Conn is a net.Conn whose writes suffer a fault.
type Conn struct {
	net.Conn
	cfg Config
	rng *Rand

	mu     sync.Mutex
	writes int
	dead   bool
}

// Wrap returns c with cfg's fault on its writes.
func Wrap(c net.Conn, cfg Config) *Conn {
	if cfg.MaxDelay <= 0 {
		cfg.MaxDelay = 3 * time.Millisecond
	}
	return &Conn{Conn: c, cfg: cfg, rng: NewRand(cfg.Seed)}
}

// Write writes b through the fault.
func (c *Conn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead {
		return 0, errInjected
	}
	i := c.writes
	c.writes++
	switch c.cfg.Fault {
	case OneByte:
		return c.pieces(b, func(int) int { return 1 }, false)
	case Chunks:
		return c.pieces(b, func(rest int) int { return 1 + c.rng.Intn(rest) }, false)
	case Delay:
		return c.pieces(b, func(rest int) int { return 1 + c.rng.Intn(rest) }, true)
	}
	if i < c.cfg.After || c.cfg.Fault == Clean || len(b) == 0 {
		return c.Conn.Write(b)
	}
	switch c.cfg.Fault {
	case Duplicate:
		if _, err := c.Conn.Write(b); err != nil {
			return 0, err
		}
		return c.Conn.Write(b)
	case BitFlip:
		out := append([]byte(nil), b...)
		bit := c.rng.Intn(8 * len(out))
		out[bit/8] ^= 1 << (bit % 8)
		return c.Conn.Write(out)
	}
	// Lossy faults: a strict prefix (possibly empty) of the response.
	cut := c.rng.Intn(len(b))
	if cut > 0 {
		if _, err := c.Conn.Write(b[:cut]); err != nil {
			return 0, err
		}
	}
	c.dead = true
	switch c.cfg.Fault {
	case Reset:
		if tc, ok := c.Conn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = c.Close()
	case Stall:
		// Hold the connection open, silently, until the client gives up.
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, _ = io.Copy(io.Discard, c.Conn)
		_ = c.Close()
	default: // Truncate
		_ = c.Close()
	}
	return cut, errInjected
}

// pieces writes b in pieces of size(rest) octets.
func (c *Conn) pieces(b []byte, size func(rest int) int, pause bool) (int, error) {
	n := 0
	for n < len(b) {
		k := min(size(len(b)-n), len(b)-n)
		w, err := c.Conn.Write(b[n : n+k])
		n += w
		if err != nil {
			return n, err
		}
		if pause {
			time.Sleep(c.rng.Duration(c.cfg.MaxDelay))
		}
	}
	return n, nil
}

// Listener wraps the connections a listener accepts.
type Listener struct {
	net.Listener
	cfg Config

	mu sync.Mutex
	n  uint64
}

// Listen wraps ln: its i-th accepted connection suffers cfg's fault with
// a seed derived from cfg.Seed and i.
func Listen(ln net.Listener, cfg Config) *Listener { return &Listener{Listener: ln, cfg: cfg} }

// Accept accepts and wraps the next connection.
func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.n++
	cfg := l.cfg
	cfg.Seed = NewRand(l.cfg.Seed ^ l.n<<32).Uint64()
	l.mu.Unlock()
	return Wrap(c, cfg), nil
}

// TCP serves h behind cfg's fault on loopback until the test ends, like
// testsrv.TCP: each read of the server is one request.
func TCP(t testing.TB, cfg Config, h testsrv.Handler) core.Target {
	t.Helper()
	return Raw(t, cfg, func(c net.Conn) {
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
	})
}

// Raw serves fn with every accepted connection, wrapped in cfg's fault,
// and closes the connection when fn returns.
func Raw(t testing.TB, cfg Config, fn func(c net.Conn)) core.Target {
	t.Helper()
	ln := listen(t)
	cl := Listen(ln, cfg)
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			c, err := cl.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = c.Close() }()
				fn(c)
			})
		}
	})
	return Target(t, ln.Addr(), core.TCP)
}

// NewListener returns a loopback TCP listener wrapped in cfg's fault, closed
// when the test ends, for servers that run their own accept loop (HTTP,
// TLS).
func NewListener(t testing.TB, cfg Config) *Listener {
	t.Helper()
	ln := listen(t)
	t.Cleanup(func() { _ = ln.Close() })
	return Listen(ln, cfg)
}

func listen(t testing.TB) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

// Target returns the target of a listening address, with a 2 s timeout.
func Target(t testing.TB, a net.Addr, n core.Network) core.Target {
	t.Helper()
	host, port, err := net.SplitHostPort(a.String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return core.Target{Host: host, Port: p, Network: n, Timeout: 2 * time.Second}
}

// Recorder records the requests a handler receives.
type Recorder struct {
	mu   sync.Mutex
	reqs [][]byte
}

// Wrap returns h recording every request into r.
func (r *Recorder) Wrap(h testsrv.Handler) testsrv.Handler {
	return func(req []byte) ([]byte, bool) {
		r.Add(req)
		return h(req)
	}
}

// Add records one request.
func (r *Recorder) Add(req []byte) {
	r.mu.Lock()
	r.reqs = append(r.reqs, append([]byte(nil), req...))
	r.mu.Unlock()
}

// Requests returns the recorded requests, in arrival order.
func (r *Recorder) Requests() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.reqs...)
}

// Reset forgets the recorded requests.
func (r *Recorder) Reset() {
	r.mu.Lock()
	r.reqs = nil
	r.mu.Unlock()
}
