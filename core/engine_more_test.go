// SPDX-License-Identifier: MIT

package core

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestExcludeAndLikelyOnly(t *testing.T) {
	a := &fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP, Ports: []int{502}}, result: NoMatch(ProtocolModbus)}
	b := &fakeFP{info: Info{Protocol: ProtocolS7, Network: TCP, Ports: []int{102}}, result: NoMatch(ProtocolS7)}
	reg := NewRegistry().MustRegister(a, b)

	cfg := DefaultEngineConfig()
	cfg.Exclude = []Protocol{ProtocolS7}
	_, _ = NewEngine(reg, cfg).Scan(context.Background(), Target{Host: "h", Port: 1})
	if a.calls != 1 || b.calls != 0 {
		t.Fatalf("exclude: %d %d", a.calls, b.calls)
	}

	cfg = DefaultEngineConfig()
	cfg.LikelyOnly = true
	_, _ = NewEngine(reg, cfg).Scan(context.Background(), Target{Host: "h", Port: 102})
	if b.calls != 1 || a.calls != 1 {
		t.Fatalf("likely only on 102: modbus %d s7 %d", a.calls, b.calls)
	}
	// No likely fingerprinter: all run.
	_, _ = NewEngine(reg, cfg).Scan(context.Background(), Target{Host: "h", Port: 7})
	if a.calls != 2 || b.calls != 2 {
		t.Fatalf("likely only fallback: %d %d", a.calls, b.calls)
	}
}

// A fingerprinter that returns a zero Result is normalised: protocol, ID
// and timestamp are filled in.
func TestResultNormalised(t *testing.T) {
	fp := &fakeFP{info: Info{Protocol: ProtocolDNP3, Network: TCP}}
	rep, _ := NewEngine(NewRegistry().MustRegister(fp), DefaultEngineConfig()).Scan(context.Background(), Target{Host: "h", Port: 1})
	r := rep.Results[0]
	if r.Protocol != ProtocolDNP3 || r.DetectionID == "" || r.Timestamp.IsZero() {
		t.Fatalf("%+v", r)
	}
}

func TestEngineLogsAndInvalidDetect(t *testing.T) {
	var buf bytes.Buffer
	cfg := DefaultEngineConfig()
	cfg.Logger = NewSlogLogger(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	fp := &fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP}, result: NoMatch(ProtocolModbus)}
	e := NewEngine(NewRegistry().MustRegister(fp), cfg)
	_, _ = e.Scan(context.Background(), Target{Host: "h", Port: 1})
	if !strings.Contains(buf.String(), "otfp: tcp://h:1 modbus") {
		t.Fatalf("log: %q", buf.String())
	}
	if _, err := e.Detect(context.Background(), Target{}, ProtocolModbus); err == nil {
		t.Fatal("invalid target")
	}
}

type panicWith struct {
	v any
}

func (p panicWith) Info() Info { return Info{Protocol: ProtocolModbus, Network: TCP} }
func (p panicWith) Detect(context.Context, Target, Options) (Result, error) {
	panic(p.v)
}

func TestPanicValues(t *testing.T) {
	for v, want := range map[any]string{"boom": "boom", errors.New("bad"): "bad", 42: "non-error value"} {
		rep, _ := NewEngine(NewRegistry().MustRegister(panicWith{v}), DefaultEngineConfig()).Scan(context.Background(), Target{Host: "h", Port: 1})
		if msg := rep.Results[0].Error.Error(); !strings.Contains(msg, "panicked: "+want) {
			t.Errorf("%v: %q", v, msg)
		}
	}
}

// Parallel with a concurrency bound: after an early stop, fingerprinters
// not yet started are skipped (only refinements still start).
func TestParallelBoundedSkipsAfterStop(t *testing.T) {
	first := &fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP, Priority: 1}, result: mod(ProtocolModbus, ConfidenceCertain)}
	later := &fakeFP{info: Info{Protocol: ProtocolS7, Network: TCP, Priority: 2}, result: NoMatch(ProtocolS7)}
	refine := &fakeFP{info: Info{Protocol: ProtocolSunSpec, Network: TCP, Priority: 3, Refines: ProtocolModbus}, result: mod(ProtocolSunSpec, ConfidenceCertain)}
	cfg := DefaultEngineConfig()
	cfg.Parallel = true
	cfg.MaxConcurrency = 1
	rep, _ := NewEngine(NewRegistry().MustRegister(first, later, refine), cfg).Scan(context.Background(), Target{Host: "h", Port: 1})
	if later.calls != 0 || refine.calls != 1 || rep.Best.Protocol != ProtocolSunSpec {
		t.Fatalf("later %d refine %d best %s", later.calls, refine.calls, rep.Best.Protocol)
	}
}

// A cancelled context ends a paced or bounded scan before the next start.
func TestCancelledWhileWaiting(t *testing.T) {
	fps := []Fingerprinter{
		&fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP, Priority: 1}, result: NoMatch(ProtocolModbus)},
		&fakeFP{info: Info{Protocol: ProtocolS7, Network: TCP, Priority: 2}, result: NoMatch(ProtocolS7)},
	}
	for _, parallel := range []bool{false, true} {
		cfg := DefaultEngineConfig()
		cfg.Parallel = parallel
		cfg.MinInterval = time.Hour
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		start := time.Now()
		rep, _ := NewEngine(NewRegistry().MustRegister(fps...), cfg).Scan(ctx, Target{Host: "h", Port: 1})
		cancel()
		if time.Since(start) > time.Second || len(rep.Results) != 1 {
			t.Fatalf("parallel=%v: %d results after %v", parallel, len(rep.Results), time.Since(start))
		}
	}
	// A context done before a bounded slot frees up.
	slow := &fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP, Priority: 1}, result: NoMatch(ProtocolModbus), delay: time.Second}
	next := &fakeFP{info: Info{Protocol: ProtocolS7, Network: TCP, Priority: 2}, result: NoMatch(ProtocolS7)}
	cfg := DefaultEngineConfig()
	cfg.Parallel, cfg.MaxConcurrency = true, 1
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _ = NewEngine(NewRegistry().MustRegister(slow, next), cfg).Scan(ctx, Target{Host: "h", Port: 1})
	if next.calls != 0 {
		t.Fatal("started after the context ended")
	}
}
