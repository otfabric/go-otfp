// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"sync"
	"testing"
	"time"
)

func mod(p Protocol, c Confidence) Result { return Match(p, c, p.String()) }

func TestScanBestAndEarlyStop(t *testing.T) {
	high := &fakeFP{info: Info{Protocol: ProtocolMMS, Network: TCP, Priority: 10}, result: mod(ProtocolMMS, ConfidenceCertain)}
	low := &fakeFP{info: Info{Protocol: ProtocolS7, Network: TCP, Priority: 20}, result: mod(ProtocolS7, ConfidenceLow)}
	e := NewEngine(NewRegistry().MustRegister(high, low), DefaultEngineConfig())
	rep, err := e.Scan(context.Background(), Target{Host: "127.0.0.1", Port: 102})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Best.Protocol != ProtocolMMS || !rep.Best.Matched {
		t.Fatalf("best %v", rep.Best)
	}
	if low.calls != 0 {
		t.Fatal("early stop should have skipped the low fingerprinter")
	}
}

func TestScanNoMatch(t *testing.T) {
	fp := &fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP}, result: NoMatch(ProtocolModbus)}
	e := NewEngine(NewRegistry().MustRegister(fp), DefaultEngineConfig())
	rep, _ := e.Scan(context.Background(), Target{Host: "127.0.0.1", Port: 502})
	if rep.Best.Protocol != ProtocolUnknown || len(rep.Matches()) != 0 {
		t.Fatalf("best %v", rep.Best)
	}
}

func TestRefinementPreferred(t *testing.T) {
	base := &fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP, Priority: 60}, result: mod(ProtocolModbus, ConfidenceCertain)}
	refine := &fakeFP{info: Info{Protocol: ProtocolSunSpec, Network: TCP, Priority: 61, Refines: ProtocolModbus, Intrusiveness: ReadOnly}, result: mod(ProtocolSunSpec, ConfidenceCertain)}
	cfg := DefaultEngineConfig()
	e := NewEngine(NewRegistry().MustRegister(base, refine), cfg)
	rep, _ := e.Scan(context.Background(), Target{Host: "127.0.0.1", Port: 502})
	if rep.Best.Protocol != ProtocolSunSpec {
		t.Fatalf("best %v; refine should win a tie", rep.Best.Protocol)
	}
	if refine.calls != 1 {
		t.Fatal("refinement should run even after an early stop on Modbus")
	}
}

func TestMaxIntrusivenessSkips(t *testing.T) {
	passive := &fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP, Intrusiveness: Passive}, result: mod(ProtocolModbus, ConfidenceCertain)}
	readonly := &fakeFP{info: Info{Protocol: ProtocolSunSpec, Network: TCP, Intrusiveness: ReadOnly}, result: mod(ProtocolSunSpec, ConfidenceCertain)}
	cfg := DefaultEngineConfig()
	cfg.MaxIntrusiveness = Passive
	cfg.EarlyStop = false
	e := NewEngine(NewRegistry().MustRegister(passive, readonly), cfg)
	rep, _ := e.Scan(context.Background(), Target{Host: "127.0.0.1", Port: 502})
	if readonly.calls != 0 {
		t.Fatal("read-only fingerprinter should be skipped")
	}
	if len(rep.Results) != 1 {
		t.Fatalf("%d results", len(rep.Results))
	}
}

func TestProtocolFilter(t *testing.T) {
	a := &fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP}, result: mod(ProtocolModbus, ConfidenceCertain)}
	b := &fakeFP{info: Info{Protocol: ProtocolS7, Network: TCP}, result: mod(ProtocolS7, ConfidenceCertain)}
	cfg := DefaultEngineConfig()
	cfg.Protocols = []Protocol{ProtocolS7}
	e := NewEngine(NewRegistry().MustRegister(a, b), cfg)
	rep, _ := e.Scan(context.Background(), Target{Host: "127.0.0.1", Port: 102})
	if a.calls != 0 || b.calls != 1 {
		t.Fatalf("filter: a=%d b=%d", a.calls, b.calls)
	}
	_ = rep
}

func TestDetectSingle(t *testing.T) {
	fp := &fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP}, result: mod(ProtocolModbus, ConfidenceCertain)}
	e := NewEngine(NewRegistry().MustRegister(fp), DefaultEngineConfig())
	r, err := e.Detect(context.Background(), Target{Host: "127.0.0.1", Port: 502}, ProtocolModbus)
	if err != nil || !r.Matched {
		t.Fatalf("%v %v", r, err)
	}
	if _, err := e.Detect(context.Background(), Target{Host: "127.0.0.1", Port: 502}, ProtocolS7); err == nil {
		t.Fatal("want ProtocolNotFoundError")
	}
}

func TestPanicRecovered(t *testing.T) {
	fp := panicFP{info: Info{Protocol: ProtocolModbus, Network: TCP}}
	e := NewEngine(NewRegistry().MustRegister(fp), DefaultEngineConfig())
	rep, err := e.Scan(context.Background(), Target{Host: "127.0.0.1", Port: 502})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].Error == nil {
		t.Fatal("panic should become an error result")
	}
}

func TestParallel(t *testing.T) {
	var fps []Fingerprinter
	for i := ProtocolModbus; i <= ProtocolENIP; i++ {
		fps = append(fps, &fakeFP{info: Info{Protocol: i, Network: TCP, Priority: int(i)}, result: NoMatch(i), delay: 10 * time.Millisecond})
	}
	cfg := DefaultEngineConfig()
	cfg.Parallel = true
	cfg.MaxConcurrency = 4
	cfg.EarlyStop = false
	cfg.StopOnRefused = false
	e := NewEngine(NewRegistry().MustRegister(fps...), cfg)
	rep, _ := e.Scan(context.Background(), Target{Host: "127.0.0.1", Port: 1})
	if len(rep.Results) != len(fps) {
		t.Fatalf("%d of %d results", len(rep.Results), len(fps))
	}
}

func TestObserver(t *testing.T) {
	var mu sync.Mutex
	starts, results := 0, 0
	cfg := DefaultEngineConfig()
	cfg.Observer = obs{onStart: func() { mu.Lock(); starts++; mu.Unlock() }, onResult: func() { mu.Lock(); results++; mu.Unlock() }}
	fp := &fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP}, result: NoMatch(ProtocolModbus)}
	e := NewEngine(NewRegistry().MustRegister(fp), cfg)
	_, _ = e.Scan(context.Background(), Target{Host: "127.0.0.1", Port: 502})
	if starts != 1 || results != 1 {
		t.Fatalf("observer starts=%d results=%d", starts, results)
	}
}

func TestInvalidTargetAndNoFingerprinters(t *testing.T) {
	e := NewEngine(NewRegistry(), DefaultEngineConfig())
	if _, err := e.Scan(context.Background(), Target{Port: 1}); err == nil {
		t.Fatal("invalid target")
	}
	if _, err := e.Scan(context.Background(), Target{Host: "127.0.0.1", Port: 1}); err != ErrNoFingerprinters {
		t.Fatalf("want ErrNoFingerprinters, got %v", err)
	}
}

type panicFP struct{ info Info }

func (p panicFP) Info() Info { return p.info }
func (p panicFP) Detect(context.Context, Target, Options) (Result, error) {
	panic("boom")
}

type obs struct {
	onStart, onResult func()
}

func (o obs) OnStart(Protocol, Target) { o.onStart() }
func (o obs) OnResult(Result)          { o.onResult() }
