// SPDX-License-Identifier: MIT

package chaos

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestRandIsDeterministicAndBounded(t *testing.T) {
	a, b := NewRand(42), NewRand(42)
	for range 1000 {
		if a.Uint64() != b.Uint64() {
			t.Fatal("same seed, different streams")
		}
		if v := a.Intn(7); v < 0 || v >= 7 {
			t.Fatalf("Intn %d", v)
		}
		if d := a.Duration(time.Millisecond); d < 0 || d >= time.Millisecond {
			t.Fatalf("Duration %v", d)
		}
		b.Intn(7)
		b.Duration(time.Millisecond)
	}
	if a.Intn(0) != 0 || a.Duration(0) != 0 {
		t.Fatal("empty ranges")
	}
}

// The complete faults deliver every octet in order; the lossy ones a
// strict prefix.
func TestFaultsOnTheWire(t *testing.T) {
	reply := bytes.Repeat([]byte("abcdefgh"), 64)
	for _, f := range Faults {
		target := TCP(t, Config{Fault: f, Seed: 1}, func([]byte) ([]byte, bool) { return reply, false })
		c, err := net.Dial("tcp", target.Addr())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("go"))
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		got, _ := io.ReadAll(io.LimitReader(c, int64(2*len(reply))))
		_ = c.Close()
		switch {
		case f.Complete() && !bytes.Equal(got, reply):
			t.Fatalf("%s: %d octets", f, len(got))
		case f == Duplicate && !bytes.Equal(got, append(append([]byte(nil), reply...), reply...)):
			t.Fatalf("%s: %d octets", f, len(got))
		case f == BitFlip && (len(got) != len(reply) || bytes.Equal(got, reply)):
			t.Fatalf("%s: unchanged", f)
		case f.Lossy() && (len(got) >= len(reply) || !bytes.HasPrefix(reply, got)):
			t.Fatalf("%s: %d octets, not a strict prefix", f, len(got))
		}
		if f.String() == "fault?" {
			t.Fatalf("fault %d has no name", f)
		}
	}
	for _, f := range UDPFaults {
		if f.String() == "fault?" {
			t.Fatalf("UDP fault %d has no name", f)
		}
	}
}
