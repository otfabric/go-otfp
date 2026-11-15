// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// failingObserver is an Observer whose methods do not return normally for
// the protocols listed.
type failingObserver struct {
	mu              sync.Mutex
	onStart, onDone map[Protocol]bool
	started, done   []Protocol
}

func (o *failingObserver) OnStart(p Protocol, _ Target) {
	o.mu.Lock()
	o.started = append(o.started, p)
	fail := o.onStart[p]
	o.mu.Unlock()
	if fail {
		panic("OnStart of the test")
	}
}

func (o *failingObserver) OnResult(r Result) {
	o.mu.Lock()
	o.done = append(o.done, r.Protocol)
	fail := o.onDone[r.Protocol]
	o.mu.Unlock()
	if fail {
		panic(errors.New("OnResult of the test"))
	}
}

// failingLogger is a Logger whose Debugf does not return normally.
type failingLogger struct{ Logger }

func (failingLogger) Debugf(string, ...any) { panic(42) }

var loopback = Target{Host: "127.0.0.1", Port: 502}

func resultOf(t *testing.T, rep Report, p Protocol) Result {
	t.Helper()
	for _, r := range rep.Results {
		if r.Protocol == p {
			return r
		}
	}
	t.Fatalf("no result for %s in %v", p, rep.Results)
	return Result{}
}

// A callback of the caller's that does not return normally ends its probe
// with an error, in sequential and in parallel scans: Scan returns, the
// other probes run, and a fingerprinter whose OnStart did not return is not
// run.
func TestObserverThatDoesNotReturnNormally(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		name := map[bool]string{false: "sequential", true: "parallel"}[parallel]
		t.Run(name, func(t *testing.T) {
			a := &fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP, Priority: 1}, result: mod(ProtocolModbus, ConfidenceCertain)}
			b := &fakeFP{info: Info{Protocol: ProtocolS7, Network: TCP, Priority: 2}, result: mod(ProtocolS7, ConfidenceCertain)}
			c := &fakeFP{info: Info{Protocol: ProtocolMMS, Network: TCP, Priority: 3}, result: mod(ProtocolMMS, ConfidenceMedium)}
			obs := &failingObserver{onStart: map[Protocol]bool{ProtocolModbus: true}, onDone: map[Protocol]bool{ProtocolS7: true}}
			e := NewEngine(NewRegistry().MustRegister(a, b, c), EngineConfig{Parallel: parallel, Observer: obs})
			rep, err := e.Scan(context.Background(), loopback)
			if err != nil || len(rep.Results) != 3 {
				t.Fatalf("Scan: %v, %d results; want all three", err, len(rep.Results))
			}
			if a.calls != 0 || b.calls != 1 || c.calls != 1 {
				t.Errorf("fingerprinters called %d, %d, %d times; want 0 (OnStart did not return), 1, 1", a.calls, b.calls, c.calls)
			}
			for p, want := range map[Protocol]string{
				ProtocolModbus: "Observer.OnStart did not return normally: OnStart of the test",
				ProtocolS7:     "Observer.OnResult did not return normally: OnResult of the test",
			} {
				r := resultOf(t, rep, p)
				var de *DetectError
				if r.Matched || !errors.As(r.Error, &de) || de.Op != "observer" || de.Protocol != p || !strings.HasSuffix(r.Error.Error(), want) {
					t.Errorf("%s: %v with error %v; want a DetectError of operation observer ending in %q", p, r, r.Error, want)
				}
				if r.DetectionID == "" || r.Timestamp.IsZero() {
					t.Errorf("%s: the result has no identifier or time: %+v", p, r)
				}
			}
			if r := resultOf(t, rep, ProtocolMMS); !r.Matched || r.Error != nil || rep.Best.Protocol != ProtocolMMS {
				t.Errorf("the probe whose callbacks returned: %v, best %v", r, rep.Best)
			}
			if len(obs.started) != 3 || len(obs.done) != 3 {
				t.Errorf("observer saw %d starts and %d results, want 3 and 3", len(obs.started), len(obs.done))
			}
		})
	}
}

func TestLoggerThatDoesNotReturnNormally(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		fp := &fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP}, result: mod(ProtocolModbus, ConfidenceCertain)}
		e := NewEngine(NewRegistry().MustRegister(fp), EngineConfig{Parallel: parallel, Logger: failingLogger{NopLogger()}})
		rep, err := e.Scan(context.Background(), loopback)
		if err != nil || len(rep.Results) != 1 {
			t.Fatalf("parallel %v: %v, %d results", parallel, err, len(rep.Results))
		}
		var de *DetectError
		if r := rep.Results[0]; r.Matched || !errors.As(r.Error, &de) || de.Op != "logger" ||
			r.Error.Error() != "modbus logger: Logger.Debugf did not return normally: non-error value" {
			t.Errorf("parallel %v: %v with error %v; want a DetectError of operation logger", parallel, r, r.Error)
		}
	}
}

// reentrant is an Observer that calls the engine from its callbacks
// (lifecycle matrix, L9) and can cancel the scan (L10).
type reentrant struct {
	e      *Engine
	cancel context.CancelFunc
	inner  []Result
	errs   []error
}

func (o *reentrant) OnStart(Protocol, Target) { _ = o.e.Config() }

func (o *reentrant) OnResult(r Result) {
	if r.Protocol != ProtocolModbus {
		return
	}
	// A whole detection of another protocol from inside the callback.
	x, err := o.e.Detect(context.Background(), loopback, ProtocolS7)
	o.inner, o.errs = append(o.inner, x), append(o.errs, err)
	if o.cancel != nil {
		o.cancel()
	}
}

// L9: a callback may call the engine, which holds no lock while it calls.
// L10: a callback may cancel the scan's context; the scan then ends with
// the results it has.
func TestObserverCallsTheEngine(t *testing.T) {
	a := &fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP, Priority: 1}, result: mod(ProtocolModbus, ConfidenceMedium)}
	b := &fakeFP{info: Info{Protocol: ProtocolS7, Network: TCP, Priority: 2}, result: mod(ProtocolS7, ConfidenceMedium)}
	obs := &reentrant{}
	e := NewEngine(NewRegistry().MustRegister(a, b), EngineConfig{Observer: obs})
	obs.e = e
	rep, err := e.Scan(context.Background(), loopback)
	if err != nil || len(rep.Results) != 2 {
		t.Fatalf("%v, %d results", err, len(rep.Results))
	}
	if len(obs.inner) != 1 || obs.errs[0] != nil || !obs.inner[0].Matched || obs.inner[0].Protocol != ProtocolS7 {
		t.Fatalf("Detect from OnResult: %v %v", obs.inner, obs.errs)
	}
	if b.calls != 2 {
		t.Errorf("S7 fingerprinter called %d times, want once by the scan and once from the callback", b.calls)
	}

	// The same observer cancels the scan after the first result.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.calls, b.calls = 0, 0
	obs.cancel = cancel
	rep, err = e.Scan(ctx, loopback)
	if err != nil || len(rep.Results) != 1 || rep.Results[0].Protocol != ProtocolModbus {
		t.Fatalf("scan cancelled from OnResult: %v, results %v; want the first result only", err, rep.Results)
	}
	if b.calls != 1 { // the detection from inside the callback
		t.Errorf("S7 fingerprinter called %d times after the cancel, want 1", b.calls)
	}
}

// blocking is an Observer whose OnResult for one protocol waits for the
// result of another.
type blocking struct {
	other   chan struct{}
	blocked Protocol
	timeout bool
}

func (*blocking) OnStart(Protocol, Target) {}

func (o *blocking) OnResult(r Result) {
	if r.Protocol != o.blocked {
		close(o.other)
		return
	}
	select {
	case <-o.other:
	case <-time.After(10 * time.Second):
		o.timeout = true
	}
}

// L11: a slow callback delays its own probe only. In a parallel scan the
// other probes run and report while it waits.
func TestSlowObserverDelaysItsOwnProbeOnly(t *testing.T) {
	a := &fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP, Priority: 1}, result: mod(ProtocolModbus, ConfidenceMedium)}
	b := &fakeFP{info: Info{Protocol: ProtocolS7, Network: TCP, Priority: 2}, result: mod(ProtocolS7, ConfidenceMedium)}
	obs := &blocking{other: make(chan struct{}), blocked: ProtocolModbus}
	e := NewEngine(NewRegistry().MustRegister(a, b), EngineConfig{Parallel: true, Observer: obs})
	rep, err := e.Scan(context.Background(), loopback)
	if err != nil || len(rep.Results) != 2 {
		t.Fatalf("%v, %d results", err, len(rep.Results))
	}
	if obs.timeout {
		t.Fatal("the other probe did not report while the first callback waited")
	}
}

// A timeout of a probe matches context.DeadlineExceeded, whichever clock
// ended the operation, and stays a *TimeoutError.
func TestTimeoutErrorIsDeadlineExceeded(t *testing.T) {
	for name, cause := range map[string]error{
		"the socket's deadline":  os.ErrDeadlineExceeded,
		"the context's deadline": context.DeadlineExceeded,
		"another cause":          errors.New("i/o timeout"),
	} {
		var err error = &TimeoutError{Protocol: ProtocolModbus, Addr: "192.0.2.1:502", Op: "read", Err: cause}
		var te *TimeoutError
		if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &te) || !errors.Is(err, cause) {
			t.Errorf("%s: errors.Is(DeadlineExceeded) %v, errors.As(*TimeoutError) %v, errors.Is(cause) %v; want all true",
				name, errors.Is(err, context.DeadlineExceeded), errors.As(err, &te), errors.Is(err, cause))
		}
		if errors.Is(err, context.Canceled) {
			t.Errorf("%s: a timeout matches context.Canceled", name)
		}
	}
	for _, err := range []error{
		ClassifyDial(ProtocolModbus, "a:1", os.ErrDeadlineExceeded),
		ClassifyIO(ProtocolModbus, "a:1", "read", os.ErrDeadlineExceeded),
	} {
		if !errors.Is(err, context.DeadlineExceeded) || !IsTimeout(err) {
			t.Errorf("%v does not match context.DeadlineExceeded", err)
		}
	}
	if err := ClassifyIO(ProtocolModbus, "a:1", "read", errors.New("reset")); errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("%v matches context.DeadlineExceeded", err)
	}
}

// The zero Engine, a nil *Engine and an engine over a nil registry have no
// fingerprinters; Register refuses a nil fingerprinter and a nil registry.
func TestZeroEngineAndNilRegistry(t *testing.T) {
	var nilRegistry *Registry
	for name, e := range map[string]*Engine{
		"zero Engine":              {},
		"nil *Engine":              nil,
		"NewEngine(nil, ...)":      NewEngine(nil, DefaultEngineConfig()),
		"NewEngine(nil *Registry)": NewEngine(nilRegistry, EngineConfig{Parallel: true}),
		"empty registry":           NewEngine(NewRegistry(), EngineConfig{}),
		"zero Registry":            NewEngine(&Registry{}, EngineConfig{}),
	} {
		if _, err := e.Scan(context.Background(), loopback); !errors.Is(err, ErrNoFingerprinters) {
			t.Errorf("%s: Scan = %v, want ErrNoFingerprinters", name, err)
		}
		var nf *ProtocolNotFoundError
		if _, err := e.Detect(context.Background(), loopback, ProtocolModbus); !errors.As(err, &nf) || nf.Protocol != ProtocolModbus {
			t.Errorf("%s: Detect = %v, want a ProtocolNotFoundError", name, err)
		}
		_ = e.Config()
		if _, err := e.Scan(context.Background(), Target{}); err == nil || errors.Is(err, ErrNoFingerprinters) {
			t.Errorf("%s: Scan of an invalid target = %v, want the target's error", name, err)
		}
	}
	if nilRegistry.Get(ProtocolModbus, TCP) != nil || nilRegistry.All() != nil || len(nilRegistry.Protocols()) != 0 || len(nilRegistry.Plan(loopback)) != 0 {
		t.Error("a nil registry holds a fingerprinter")
	}
	fp := &fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP}}
	if err := nilRegistry.Register(fp); err == nil {
		t.Error("Register on a nil registry: nil error")
	}
	r := NewRegistry()
	if err := r.Register(nil); err == nil || len(r.All()) != 0 {
		t.Errorf("Register(nil) = %v with %d registered, want an error and none", err, len(r.All()))
	}
	var zero Registry
	if err := zero.Register(fp); err != nil || zero.Get(ProtocolModbus, TCP) != fp {
		t.Errorf("the zero Registry: Register = %v", err)
	}
}
