// SPDX-License-Identifier: MIT

package e2e_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// failingNth is a Logger whose Debugf does not return normally on the n-th
// line of each protocol (the first argument of every session line is the
// protocol's slug).
type failingNth struct {
	core.Logger
	n     int
	mu    sync.Mutex
	count map[any]int
}

func (l *failingNth) Debugf(format string, args ...any) {
	var key any
	if len(args) > 0 {
		key = args[0]
	}
	l.mu.Lock()
	l.count[key]++
	c := l.count[key]
	l.mu.Unlock()
	if c == l.n {
		panic(fmt.Sprintf("logger fails on line %d", c))
	}
}

// closeTracker records the connections a Dialer opened and which of them
// were closed.
type closeTracker struct {
	mu     sync.Mutex
	opened int
	closed map[*trackedConn]bool
}

type trackedConn struct {
	net.Conn
	t *closeTracker
}

func (c *trackedConn) Close() error {
	c.t.mu.Lock()
	c.t.closed[c] = true
	c.t.mu.Unlock()
	return c.Conn.Close()
}

func (t *closeTracker) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tc := &trackedConn{Conn: c, t: t}
	t.mu.Lock()
	t.opened++
	t.closed[tc] = false
	t.mu.Unlock()
	return tc, nil
}

func (t *closeTracker) open() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, closed := range t.closed {
		if !closed {
			n++
		}
	}
	return n
}

// A Logger that does not return normally, on the first line of a probe or
// on a later one, ends that probe with an error, and every connection the
// probe opened is closed when Scan returns: no fingerprinter leaves one
// open, whichever exchange the Logger failed on.
func TestLoggerFailureClosesEveryConnection(t *testing.T) {
	targets := map[string]core.Target{
		"mqtt": testsrv.Raw(t, mqttBroker),
		"silent": testsrv.Raw(t, func(c net.Conn) {
			_, _ = io.Copy(io.Discard, c)
		}),
	}
	for p, h := range speakers() {
		targets[p.Slug()] = testsrv.TCP(t, h)
	}
	for name, target := range targets {
		target.Timeout = 150 * time.Millisecond
		for _, n := range []int{1, 2, 3, 5} {
			tr := &closeTracker{closed: map[*trackedConn]bool{}}
			log := &failingNth{Logger: core.NopLogger(), n: n, count: map[any]int{}}
			engine := otfp.NewEngine(core.EngineConfig{
				Mode: core.ModeIdentify, MaxIntrusiveness: core.ReadOnly,
				Parallel: true, Dialer: tr.dial, Logger: log,
			})
			if _, err := engine.Scan(context.Background(), target); err != nil {
				t.Fatalf("%s, line %d: %v", name, n, err)
			}
			if open := tr.open(); open > 0 {
				t.Errorf("%s, Logger failing on line %d: %d of %d connections left open", name, n, open, tr.opened)
			}
		}
	}
}
