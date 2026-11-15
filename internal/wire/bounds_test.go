// SPDX-License-Identifier: MIT

package wire

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
)

func tracingSession(c *fakeConn) *Session {
	return newSession(context.Background(), core.ProtocolBACnet, "192.0.2.1:47808", c, true, 100*time.Millisecond, core.Options{Trace: true})
}

func traceOctets(ex []core.Exchange) (n int) {
	for _, x := range ex {
		n += len(x.Probe) + len(x.Response)
	}
	return n
}

// The trace of a session holds at most MaxExchanges exchanges; what does
// not fit is counted in one last entry.
func TestTraceExchangeBound(t *testing.T) {
	for _, n := range []int{0, 1, MaxExchanges - 1, MaxExchanges, MaxExchanges + 1, 100 * MaxExchanges} {
		s := tracingSession(&fakeConn{})
		for range n {
			s.Record("x", []byte{1}, []byte{2, 3})
		}
		ex := s.Exchanges()
		kept, left := min(n, MaxExchanges), max(n-MaxExchanges, 0)
		if left == 0 {
			if len(ex) != kept {
				t.Errorf("%d exchanges recorded: %d in the trace, want %d", n, len(ex), kept)
			}
			continue
		}
		if len(ex) != kept+1 {
			t.Fatalf("%d exchanges recorded: %d in the trace, want %d and the closing entry", n, len(ex), kept)
		}
		last := ex[len(ex)-1]
		want := fmt.Sprintf("not recorded: %d exchanges, %d octets ", left, 3*left)
		if !strings.HasPrefix(last.Label, want) || len(last.Probe)+len(last.Response) != 0 {
			t.Errorf("%d exchanges recorded: closing entry %+v, want a label starting %q and no octets", n, last, want)
		}
		if again := s.Exchanges(); len(again) != len(ex) || len(s.ex) != kept {
			t.Errorf("Exchanges changed the trace: %d then %d entries, %d kept", len(ex), len(again), len(s.ex))
		}
	}
}

// The trace of a session holds at most MaxTraceBytes octets of probes and
// responses, however large one exchange is.
func TestTraceOctetBound(t *testing.T) {
	const q = MaxTraceBytes / 4
	for _, tc := range []struct {
		name       string
		sizes      []int
		kept, left int
		leftOctets uint64
	}{
		{"one octet below the bound", []int{MaxTraceBytes - 1}, 1, 0, 0},
		{"the bound", []int{MaxTraceBytes}, 1, 0, 0},
		{"one octet above the bound", []int{MaxTraceBytes + 1}, 0, 1, MaxTraceBytes + 1},
		{"the bound, then one octet", []int{MaxTraceBytes, 1}, 1, 1, 1},
		{"the bound, then nothing", []int{MaxTraceBytes, 0}, 2, 0, 0},
		{"one above, then one that fits", []int{MaxTraceBytes + 1, 16}, 1, 1, MaxTraceBytes + 1},
		{"five quarters", []int{q, q, q, q, q}, 4, 1, q},
	} {
		s := tracingSession(&fakeConn{})
		for _, n := range tc.sizes {
			s.Record("x", make([]byte, n/2), make([]byte, n-n/2))
		}
		ex := s.Exchanges()
		if len(s.ex) != tc.kept || s.left != tc.left || s.leftLen != tc.leftOctets {
			t.Errorf("%s: %d kept, %d left out (%d octets); want %d, %d (%d)", tc.name, len(s.ex), s.left, s.leftLen, tc.kept, tc.left, tc.leftOctets)
		}
		if n := traceOctets(ex); n > MaxTraceBytes {
			t.Errorf("%s: the trace holds %d octets, bound %d", tc.name, n, MaxTraceBytes)
		}
		if tc.left > 0 && !strings.Contains(ex[len(ex)-1].Label, fmt.Sprintf("%d exchanges, %d octets", tc.left, tc.leftOctets)) {
			t.Errorf("%s: closing entry %q", tc.name, ex[len(ex)-1].Label)
		}
	}
	// Without tracing nothing is kept and nothing is counted.
	s := fakeSession(&fakeConn{})
	s.Record("x", make([]byte, 64), nil)
	if s.Exchanges() != nil || s.left != 0 {
		t.Errorf("not tracing: %v, %d left out", s.Exchanges(), s.left)
	}
}

// What a session keeps of a long exchange is bounded in memory as well: a
// million recorded exchanges of 1 KiB retain the trace bounds, not a
// gigabyte.
func TestTraceRetainsBoundedMemory(t *testing.T) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	s := tracingSession(&fakeConn{})
	probe, resp := make([]byte, 512), make([]byte, 512)
	for range 1_000_000 {
		s.keep("spontaneous", probe, resp)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	const budget = 2 * MaxTraceBytes // the trace bound, with room for the test binary's own garbage
	if grown := int64(after.HeapAlloc) - int64(before.HeapAlloc); grown > budget {
		t.Errorf("a million exchanges of 1 KiB retain %d octets, budget %d", grown, budget)
	}
	if n := traceOctets(s.Exchanges()); n > MaxTraceBytes || len(s.ex) > MaxExchanges {
		t.Errorf("trace of %d exchanges and %d octets", len(s.ex), n)
	}
	runtime.KeepAlive(s)
}

// strays returns n scripted reads of a datagram that is not the answer.
func strays(n int, dg string) []readResult {
	out := make([]readResult, n)
	for i := range out {
		out[i] = readResult{data: []byte(dg)}
	}
	return out
}

func stale(dg []byte) Verdict {
	switch string(dg) {
	case "answer":
		return Answer
	case "stale":
		return Discard
	}
	return Foreign
}

// A UDP round trip reads at most MaxStrays datagrams that are not its
// answer. Up to that many before the answer do not hide it; at the bound
// the round trip ends at once, as it does when its window ends: with the
// first foreign datagram when there was one, otherwise with an error that
// says "could not decide".
func TestStrayDatagramBound(t *testing.T) {
	for _, tc := range []struct {
		name   string
		before int // stale datagrams ahead of the answer
		answer bool
	}{
		{"no stray", 0, true},
		{"one stray", 1, true},
		{"one below the bound", MaxStrays - 1, true},
		{"the bound", MaxStrays, false},
		{"one above the bound", MaxStrays + 1, false},
		{"a hundred times the bound", 100 * MaxStrays, false},
	} {
		c := &fakeConn{reads: append(strays(tc.before, "stale"), readResult{data: []byte("answer")})}
		s := tracingSession(c)
		s.Retries = 0
		got, err := s.RoundTripDatagram("probe", []byte("probe"), 64, stale)
		read := tc.before + 1 - len(c.reads)
		if tc.answer {
			if err != nil || string(got) != "answer" || read != tc.before+1 {
				t.Errorf("%s: %q, %v after %d reads; want the answer", tc.name, got, err, read)
			}
			continue
		}
		var de *core.DetectError
		if got != nil || !errors.As(err, &de) || de.Op != "read" || !errors.Is(err, errStrays) || !IsTransport(err) {
			t.Errorf("%s: %q, %v; want a DetectError of operation read", tc.name, got, err)
		}
		if read != MaxStrays {
			t.Errorf("%s: %d datagrams read, want %d", tc.name, read, MaxStrays)
		}
		if n := len(s.Exchanges()); n != MaxStrays+1 {
			t.Errorf("%s: %d exchanges in the trace, want the %d strays and the round trip", tc.name, n, MaxStrays)
		}
	}

	// A foreign datagram among the strays is what the round trip returns at
	// the bound, as at the end of its window.
	c := &fakeConn{reads: append(append(strays(3, "stale"), readResult{data: []byte("foreign")}), strays(2*MaxStrays, "stale")...)}
	s := fakeSession(c)
	if got, err := s.RoundTripDatagram("probe", []byte("probe"), 64, stale); err != nil || string(got) != "foreign" {
		t.Errorf("foreign among strays: %q, %v; want the foreign datagram", got, err)
	}
	// Datagrams too large for the buffer count as strays too (Windows).
	tooLarge := errors.New("WSAEMSGSIZE")
	saved := msgTooLarge
	t.Cleanup(func() { msgTooLarge = saved })
	msgTooLarge = func(err error) bool { return errors.Is(err, tooLarge) }
	reads := make([]readResult, 2*MaxStrays)
	for i := range reads {
		reads[i] = readResult{data: make([]byte, 8), err: tooLarge}
	}
	c = &fakeConn{reads: reads}
	if _, err := fakeSession(c).RoundTripDatagram("probe", []byte("probe"), 8, nil); !errors.Is(err, errStrays) || len(c.reads) != MaxStrays {
		t.Errorf("oversized datagrams: %v with %d reads left, want the bound after %d", err, len(c.reads), MaxStrays)
	}
}

// loggedLines counts the lines a session logs.
type loggedLines struct {
	core.Logger
	lines []string
}

func (l *loggedLines) Debugf(format string, args ...any) {
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

// The first strays of a round trip are logged with their octets, the rest
// as one count.
func TestStraysAreLoggedAsACount(t *testing.T) {
	log := &loggedLines{Logger: core.NopLogger()}
	c := &fakeConn{reads: append(strays(20, "stale"), readResult{data: []byte("answer")})}
	s := newSession(context.Background(), core.ProtocolBACnet, "192.0.2.1:47808", c, true, 100*time.Millisecond, core.Options{Logger: log})
	if got, err := s.RoundTripDatagram("probe", []byte("probe"), 64, stale); err != nil || string(got) != "answer" {
		t.Fatalf("%q %v", got, err)
	}
	withOctets, counts := 0, 0
	for _, l := range log.lines {
		switch {
		case strings.Contains(l, "discarded: sent"):
			withOctets++
		case strings.Contains(l, fmt.Sprintf("%d more datagrams discarded", 20-maxStraysLogged)):
			counts++
		}
	}
	if withOctets != maxStraysLogged || counts != 1 {
		t.Errorf("%d strays logged with their octets and %d count lines, want %d and 1:\n%s", withOctets, counts, maxStraysLogged, strings.Join(log.lines, "\n"))
	}
}

// Close twice (lifecycle matrix, L1): the second call does nothing and
// returns nil; operations after Close fail with the connection's error.
func TestCloseTwice(t *testing.T) {
	c := &closeCounter{}
	s := newSession(context.Background(), core.ProtocolModbus, "192.0.2.1:502", c, false, time.Second, core.Options{})
	c.err = errors.New("close failed")
	if err := s.Close(); !errors.Is(err, c.err) {
		t.Errorf("first Close: %v, want the connection's error", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v, want nil", err)
	}
	if c.closes != 1 {
		t.Errorf("the connection was closed %d times, want 1", c.closes)
	}
}

type closeCounter struct {
	fakeConn
	closes int
	err    error
}

func (c *closeCounter) Close() error { c.closes++; return c.err }
