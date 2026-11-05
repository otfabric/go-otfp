// SPDX-License-Identifier: MIT

package chaos

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// Server starts an endpoint that speaks the fingerprinter's protocol
// correctly, behind cfg's fault, and returns its target.
type Server func(t testing.TB, cfg Config) core.Target

// UDPServer is Server for a UDP endpoint.
type UDPServer func(t testing.TB, cfg UDPConfig) core.Target

// Timeouts of the suites: complete deliveries get a generous one (under
// -race on a loaded runner a 1-octet-per-write response is slow), faults
// that cut the response a short one, since the fingerprinter waits it out.
const (
	CompleteTimeout = 2 * time.Second
	LossyTimeout    = 250 * time.Millisecond
	UDPTimeout      = 400 * time.Millisecond
)

// Suite runs one fingerprinter against a speaker of its own protocol behind
// every fault, in detect and identify mode, and checks that it
//
//   - keeps the Fingerprinter contract (fuzzkit.Check) and never panics;
//   - returns within Exchanges sequential timeouts plus a little slack;
//   - still matches, with the clean run's confidence, when every response
//     octet arrives (fragmented into 1-octet or random writes, delayed,
//     or, on UDP, dropped once, duplicated, reordered, behind spoofed,
//     empty or oversized datagrams);
//   - does not reach ConfidenceHigh from a response truncated, reset or
//     stalled before its end;
//   - leaves no goroutine or file descriptor behind.
type Suite struct {
	FP core.Fingerprinter
	// TCP or UDP starts the speaker.
	TCP Server
	UDP UDPServer
	// Options are the base options; Mode is set by the suite. The zero
	// value allows passive probes only.
	Options core.Options
	// Seeds is the number of seeds per random fault (default 2).
	Seeds int
	// Exchanges is the number of sequential timeouts a peer can cost the
	// fingerprinter at most (default 8).
	Exchanges int
	// Modes overrides the modes run (default detect and identify).
	Modes []core.Mode
}

type run struct {
	name     string
	mode     core.Mode
	timeout  time.Duration
	complete bool
	cutFirst bool // the fault strikes the first response
	start    func(t testing.TB) core.Target
}

// Run runs the suite.
func (s Suite) Run(t *testing.T) {
	t.Helper()
	if s.Seeds <= 0 {
		s.Seeds = 2
	}
	if s.Exchanges <= 0 {
		s.Exchanges = 8
	}
	modes := s.Modes
	if len(modes) == 0 {
		modes = []core.Mode{core.ModeDetect, core.ModeIdentify}
	}
	p := s.FP.Info().Protocol
	baseline := map[core.Mode]core.Result{}
	for _, mode := range modes {
		r, err := s.detect(s.clean(t), mode)
		if err != nil || !r.Matched {
			t.Fatalf("%s: the clean speaker is not matched: %v %v", mode, r, err)
		}
		baseline[mode] = r
	}

	settle()
	goroutines, fds := runtime.NumGoroutine(), FDs()
	t.Run("faults", func(t *testing.T) {
		for _, x := range s.runs(modes) {
			t.Run(x.name, func(t *testing.T) {
				t.Parallel()
				target := x.start(t)
				target.Timeout = x.timeout
				start := time.Now()
				r, err := s.detect(target, x.mode)
				d := time.Since(start)
				fuzzkit.Check(t, p, r, err)
				if bound := time.Duration(s.Exchanges)*x.timeout + time.Second; d > bound {
					t.Fatalf("Detect took %v, bound %v", d, bound)
				}
				switch {
				case x.complete:
					want := baseline[x.mode]
					if err != nil || !r.Matched || r.Confidence != want.Confidence {
						t.Fatalf("complete delivery: %v (err %v), clean run %v", r, err, want)
					}
				case x.cutFirst && r.Confidence >= core.ConfidenceHigh:
					t.Fatalf("a cut response matched with confidence %.2f: %v", r.Confidence, r)
				}
			})
		}
	})
	CheckLeaks(t, goroutines, fds)
}

func (s Suite) clean(t *testing.T) core.Target {
	t.Helper()
	if s.UDP != nil {
		return s.UDP(t, UDPConfig{})
	}
	return s.TCP(t, Config{})
}

func (s Suite) detect(target core.Target, mode core.Mode) (core.Result, error) {
	opts := s.Options
	opts.Mode = mode
	return s.FP.Detect(context.Background(), target, opts)
}

func (s Suite) runs(modes []core.Mode) []run {
	var out []run
	for _, mode := range modes {
		if s.UDP != nil {
			for _, f := range UDPFaults {
				var seed uint64
				for range s.Seeds {
					seed++
					cfg := UDPConfig{Fault: f, Seed: seed}
					out = append(out, run{
						name: fmt.Sprintf("%s/%s/seed%d", mode, f, seed), mode: mode,
						timeout: UDPTimeout, complete: f.Complete(), cutFirst: f == UDPTruncate || f == OtherPort,
						start: func(t testing.TB) core.Target { return s.UDP(t, cfg) },
					})
				}
			}
			continue
		}
		for _, f := range Faults {
			seeds, afters := s.Seeds, []int{0, 1, 3}
			if f == Clean || f == OneByte {
				seeds = 1
			}
			if f.Complete() {
				afters = []int{0}
			}
			var seed uint64
			for range seeds {
				seed++
				for _, after := range afters {
					cfg := Config{Fault: f, Seed: seed, After: after}
					timeout := LossyTimeout
					if f.Complete() {
						timeout = CompleteTimeout
					}
					out = append(out, run{
						name: fmt.Sprintf("%s/%s/seed%d/after%d", mode, f, seed, after), mode: mode,
						timeout: timeout, complete: f.Complete(), cutFirst: f.Lossy() && after == 0,
						start: func(t testing.TB) core.Target { return s.TCP(t, cfg) },
					})
				}
			}
		}
	}
	return out
}

func settle() {
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
}

// FDs returns the number of open file descriptors of the process, or -1
// where it cannot be counted.
func FDs() int {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return -1
	}
	ents, err := os.ReadDir("/dev/fd")
	if err != nil {
		return -1
	}
	return len(ents)
}

// CheckLeaks fails t when, within 3 s, the goroutine and file-descriptor
// counts do not come back to those given (a little slack allowed for
// runtime and poller goroutines).
func CheckLeaks(t testing.TB, goroutines, fds int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		settle()
		g, f := runtime.NumGoroutine(), FDs()
		gok := g <= goroutines+2
		fok := fds < 0 || f < 0 || f <= fds+2
		if gok && fok {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			t.Fatalf("leak: goroutines %d -> %d, file descriptors %d -> %d\n%s",
				goroutines, g, fds, f, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(50 * time.Millisecond)
	}
}
