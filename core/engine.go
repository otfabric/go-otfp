// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// Observer receives scan progress callbacks, e.g. for audit logs or
// progress bars. Implementations must be safe for concurrent use when
// EngineConfig.Parallel is set, and must not block.
type Observer interface {
	// OnStart is called before a fingerprinter runs.
	OnStart(p Protocol, target Target)
	// OnResult is called after it ran.
	OnResult(r Result)
}

// EngineConfig configures an Engine. The zero value runs every applicable
// fingerprinter sequentially in detect mode, without early stop.
type EngineConfig struct {
	// Mode is passed to each fingerprinter: ModeDetect or ModeIdentify.
	Mode Mode

	// Trace records raw exchanges in each Result.
	Trace bool

	// Protocols, when non-empty, restricts the scan to these protocols.
	Protocols []Protocol

	// Exclude removes protocols from the scan.
	Exclude []Protocol

	// MaxIntrusiveness skips fingerprinters that send more than this.
	// The zero value, Passive, skips the ReadOnly ones (SunSpec); set
	// ReadOnly to run all.
	MaxIntrusiveness Intrusiveness

	// LikelyOnly runs only the fingerprinters whose well-known ports
	// include the target port, falling back to all when none does.
	LikelyOnly bool

	// EarlyStop stops after the first result with Confidence at least
	// HighConfidenceThreshold. Fingerprinters that refine the matched
	// protocol (SunSpec refines Modbus) still run.
	EarlyStop bool

	// HighConfidenceThreshold is the early-stop threshold. Zero means
	// ConfidenceHigh.
	HighConfidenceThreshold Confidence

	// StopOnRefused stops a scan when a TCP connection is refused:
	// nothing listens on the port, so no other TCP fingerprinter can
	// succeed either. It has no effect on UDP targets.
	StopOnRefused bool

	// Parallel runs fingerprinters concurrently. Many field devices accept
	// a single TCP connection only; leave it off for OT networks.
	Parallel bool

	// MaxConcurrency bounds Parallel. Zero or negative is unbounded.
	MaxConcurrency int

	// MinInterval is the minimum delay between starting two
	// fingerprinters, to stay below IDS rate thresholds.
	MinInterval time.Duration

	// Observer receives progress callbacks. Nil disables them.
	Observer Observer

	// Logger receives debug output. Nil is silent.
	Logger Logger
}

// DefaultEngineConfig returns the configuration the otfp package and the
// otprobe CLI use: sequential, early stop at ConfidenceHigh, stop when the
// port refuses connections, read-only probes allowed, detect mode.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		EarlyStop:               true,
		HighConfidenceThreshold: ConfidenceHigh,
		StopOnRefused:           true,
		MaxIntrusiveness:        ReadOnly,
	}
}

// SafeEngineConfig returns a conservative configuration for production OT
// networks: DefaultEngineConfig limited to passive probes, the likely
// protocols of the port first and only, and 250 ms between probes.
func SafeEngineConfig() EngineConfig {
	c := DefaultEngineConfig()
	c.MaxIntrusiveness = Passive
	c.LikelyOnly = true
	c.MinInterval = 250 * time.Millisecond
	return c
}

// Engine runs the fingerprinters of a registry against targets. It is safe
// for concurrent use.
type Engine struct {
	registry *Registry
	config   EngineConfig
}

// NewEngine returns an engine over registry.
func NewEngine(registry *Registry, config EngineConfig) *Engine {
	if config.HighConfidenceThreshold <= 0 {
		config.HighConfidenceThreshold = ConfidenceHigh
	}
	return &Engine{registry: registry, config: config}
}

// Config returns the engine's configuration.
func (e *Engine) Config() EngineConfig { return e.config }

// Report is the outcome of a scan of one target.
type Report struct {
	Target     Target        `json:"target"`
	StartedAt  time.Time     `json:"startedAt"`
	FinishedAt time.Time     `json:"finishedAt"`
	Duration   time.Duration `json:"duration"`
	// Results holds every result, matched ones first, by confidence.
	Results []Result `json:"results"`
	// Best is the most specific, most confident match, or a
	// ProtocolUnknown result when nothing matched.
	Best Result `json:"best"`
}

// Matches returns the matched results, best first.
func (r Report) Matches() []Result {
	var out []Result
	for _, x := range r.Results {
		if x.Matched {
			out = append(out, x)
		}
	}
	return out
}

// Scan validates target and runs the applicable fingerprinters against it.
// It returns an error only when the target is invalid or no fingerprinter
// applies; per-protocol failures are in the results.
func (e *Engine) Scan(ctx context.Context, target Target) (Report, error) {
	if err := target.Validate(); err != nil {
		return Report{}, err
	}
	plan := e.plan(target)
	if len(plan) == 0 {
		return Report{}, ErrNoFingerprinters
	}
	rep := Report{Target: target, StartedAt: time.Now()}
	if e.config.Parallel {
		rep.Results = e.runParallel(ctx, target, plan)
	} else {
		rep.Results = e.runSequential(ctx, target, plan)
	}
	rep.FinishedAt = time.Now()
	rep.Duration = rep.FinishedAt.Sub(rep.StartedAt)
	sortResults(rep.Results)
	rep.Best = best(rep.Results, e.registry)
	return rep, nil
}

// Detect runs one protocol's fingerprinter against target, over
// target.Network.
func (e *Engine) Detect(ctx context.Context, target Target, p Protocol) (Result, error) {
	if err := target.Validate(); err != nil {
		return Result{}, err
	}
	fp := e.registry.Get(p, target.Network)
	if fp == nil {
		return Result{}, &ProtocolNotFoundError{Protocol: p}
	}
	return e.run(ctx, fp, target), nil
}

func (e *Engine) options() Options {
	return Options{Mode: e.config.Mode, Trace: e.config.Trace, Logger: e.config.Logger,
		MaxIntrusiveness: e.config.MaxIntrusiveness}
}

func (e *Engine) plan(target Target) []Fingerprinter {
	include := map[Protocol]bool{}
	for _, p := range e.config.Protocols {
		include[p] = true
	}
	exclude := map[Protocol]bool{}
	for _, p := range e.config.Exclude {
		exclude[p] = true
	}
	var out, likely []Fingerprinter
	for _, fp := range e.registry.Plan(target) {
		info := fp.Info()
		if (len(include) > 0 && !include[info.Protocol]) || exclude[info.Protocol] ||
			info.Intrusiveness > e.config.MaxIntrusiveness {
			continue
		}
		out = append(out, fp)
		if hasPort(info.Ports, target.Port) {
			likely = append(likely, fp)
		}
	}
	if e.config.LikelyOnly && len(likely) > 0 {
		return likely
	}
	return out
}

// run executes one fingerprinter and normalises its result.
func (e *Engine) run(ctx context.Context, fp Fingerprinter, target Target) Result {
	info := fp.Info()
	if e.config.Observer != nil {
		e.config.Observer.OnStart(info.Protocol, target)
	}
	start := time.Now()
	r, err := e.safeDetect(ctx, fp, target)
	if err != nil {
		x := ErrorResult(info.Protocol, err)
		x.Exchanges = r.Exchanges
		r = x
	}
	if r.Protocol == ProtocolUnknown {
		r.Protocol = info.Protocol
	}
	if r.DetectionID == "" {
		r.DetectionID = newDetectionID()
	}
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now()
	}
	r.Duration = time.Since(start)
	if e.config.Logger != nil {
		e.config.Logger.Debugf("otfp: %s %s: %s", target, info.Protocol.Slug(), r)
	}
	if e.config.Observer != nil {
		e.config.Observer.OnResult(r)
	}
	return r
}

// safeDetect turns a panicking fingerprinter into an error result so that
// one broken third-party fingerprinter cannot take a scan down.
func (e *Engine) safeDetect(ctx context.Context, fp Fingerprinter, target Target) (r Result, err error) {
	defer func() {
		if v := recover(); v != nil {
			r, err = Result{}, &DetectError{Protocol: fp.Info().Protocol, Op: "detect", Err: panicError{v}}
		}
	}()
	return fp.Detect(ctx, target, e.options())
}

type panicError struct{ v any }

func (p panicError) Error() string { return "fingerprinter panicked: " + toString(p.v) }

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case error:
		return x.Error()
	}
	return "non-error value"
}

// stopAfter reports whether r ends the scan, and if so which protocol may
// still be refined.
func (e *Engine) stopAfter(r Result, target Target) (stop bool, refine Protocol) {
	if e.config.EarlyStop && r.Matched && r.Confidence >= e.config.HighConfidenceThreshold {
		return true, r.Protocol
	}
	var ce *ConnectionError
	if e.config.StopOnRefused && target.Network == TCP && errors.As(r.Error, &ce) && ce.Refused() {
		return true, ProtocolUnknown
	}
	return false, ProtocolUnknown
}

func (e *Engine) wait(ctx context.Context, i int) bool {
	if e.config.MinInterval <= 0 || i == 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(e.config.MinInterval)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (e *Engine) runSequential(ctx context.Context, target Target, plan []Fingerprinter) []Result {
	var results []Result
	stopped, refine := false, ProtocolUnknown
	n := 0
	for _, fp := range plan {
		info := fp.Info()
		if stopped && (refine == ProtocolUnknown || info.Refines != refine) {
			continue
		}
		if !e.wait(ctx, n) {
			break
		}
		n++
		r := e.run(ctx, fp, target)
		results = append(results, r)
		if !stopped {
			stopped, refine = e.stopAfter(r, target)
		}
	}
	return results
}

func (e *Engine) runParallel(ctx context.Context, target Target, plan []Fingerprinter) []Result {
	var (
		mu       sync.Mutex
		results  []Result
		wg       sync.WaitGroup
		stopped  bool
		refine   = ProtocolUnknown
		running  = map[int]context.CancelFunc{} // by plan index
		infos    = make([]Info, len(plan))
		killedBy = map[int]bool{} // fingerprinters the early stop cancelled
	)
	for i, fp := range plan {
		infos[i] = fp.Info()
	}
	// skip reports whether, after a stop, fingerprinter i must not run:
	// only refinements of the matched protocol continue. Call with mu held.
	skip := func(i int) bool {
		return stopped && (refine == ProtocolUnknown || infos[i].Refines != refine)
	}
	var sem chan struct{}
	if e.config.MaxConcurrency > 0 {
		sem = make(chan struct{}, e.config.MaxConcurrency)
	}
	for i, fp := range plan {
		if !e.wait(ctx, i) {
			break
		}
		if sem != nil {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
			}
			if ctx.Err() != nil {
				break
			}
		}
		mu.Lock()
		if skip(i) {
			mu.Unlock()
			if sem != nil {
				<-sem
			}
			continue
		}
		fctx, cancel := context.WithCancel(ctx)
		running[i] = cancel
		mu.Unlock()

		wg.Add(1)
		go func(i int, fp Fingerprinter) {
			defer wg.Done()
			defer cancel()
			if sem != nil {
				defer func() { <-sem }()
			}
			r := e.run(fctx, fp, target)

			mu.Lock()
			defer mu.Unlock()
			delete(running, i)
			if killedBy[i] && errors.Is(r.Error, context.Canceled) {
				return // cancelled by our own early stop: not a result
			}
			results = append(results, r)
			if stopped {
				return
			}
			if stop, ref := e.stopAfter(r, target); stop {
				stopped, refine = true, ref
				// Cancel what is still running, except refinements of
				// the protocol that just matched.
				for j, c := range running {
					if skip(j) {
						killedBy[j] = true
						c()
					}
				}
			}
		}(i, fp)
	}
	wg.Wait()
	return results
}

func sortResults(rs []Result) {
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].Matched != rs[j].Matched {
			return rs[i].Matched
		}
		return rs[i].Confidence > rs[j].Confidence
	})
}

// best picks the matched result with the highest confidence; among equal
// confidences, a refining protocol (SunSpec) beats the one it refines
// (Modbus).
func best(rs []Result, reg *Registry) Result {
	var b *Result
	for i := range rs {
		r := &rs[i]
		if !r.Matched {
			continue
		}
		switch {
		case b == nil, r.Confidence > b.Confidence:
			b = r
		case r.Confidence == b.Confidence && refines(reg, r.Protocol, b.Protocol):
			b = r
		}
	}
	if b == nil {
		x := NoMatch(ProtocolUnknown)
		x.Details = "no OT protocol detected"
		return x
	}
	return *b
}

func refines(reg *Registry, a, b Protocol) bool {
	for _, fp := range reg.All() {
		if i := fp.Info(); i.Protocol == a && i.Refines == b {
			return true
		}
	}
	return false
}
