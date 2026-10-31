// SPDX-License-Identifier: MIT

package e2e_test

import (
	"context"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

const robustTimeout = 100 * time.Millisecond

// hostile returns, per network, servers that misbehave in the ways a
// fingerprinter must survive.
func hostile(t *testing.T, n core.Network) map[string]core.Target {
	t.Helper()
	if n == core.UDP {
		return map[string]core.Target{
			"silent":  testsrv.UDP(t, testsrv.Script()),
			"garbage": testsrv.UDP(t, func([]byte) ([]byte, bool) { return []byte("\x81\x0b\x00\x04\xff\xff"), false }),
		}
	}
	return map[string]core.Target{
		"silent": testsrv.TCP(t, testsrv.Script()),
		// One byte every 20ms, forever: a framer waiting for "more" must
		// still be bounded by the read deadline.
		"slow-drip": testsrv.Raw(t, func(c net.Conn) {
			for {
				if _, err := c.Write([]byte{0x03}); err != nil {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
		}),
		"garbage": testsrv.TCP(t, func([]byte) ([]byte, bool) { return []byte("\x03\x00\xff\xff garbage \x05\x64\xff"), false }),
		"closer":  testsrv.TCP(t, func([]byte) ([]byte, bool) { return nil, true }),
	}
}

// Every fingerprinter returns in bounded time, and within its contract,
// against every hostile server, in both modes.
func TestHostileServersBounded(t *testing.T) {
	for _, fp := range otfp.Fingerprinters() {
		info := fp.Info()
		for name, target := range hostile(t, info.Network) {
			t.Run(info.Protocol.Slug()+"-"+info.Network.String()+"/"+name, func(t *testing.T) {
				t.Parallel()
				target.Timeout = robustTimeout
				for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
					start := time.Now()
					r, err := fp.Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: core.ReadOnly})
					// The slowest fingerprinters make a handful of
					// sequential exchanges, each bounded by the timeout.
					if d := time.Since(start); d > 40*robustTimeout {
						t.Fatalf("%s: %v", mode, d)
					}
					fuzzkit.Check(t, info.Protocol, r, err)
					if r.Matched {
						t.Fatalf("%s matched a %s server: %v", mode, name, r)
					}
				}
			})
		}
	}
}

// One fingerprinter instance is used by many goroutines at once (the
// engine and callers may share it): run under -race, this finds any shared
// mutable state.
func TestConcurrentUseOfOneInstance(t *testing.T) {
	for _, fp := range otfp.Fingerprinters() {
		info := fp.Info()
		target := hostile(t, info.Network)["garbage"]
		target.Timeout = robustTimeout
		t.Run(info.Protocol.Slug()+"-"+info.Network.String(), func(t *testing.T) {
			t.Parallel()
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					r, err := fp.Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify, Trace: true, MaxIntrusiveness: core.ReadOnly})
					fuzzkit.Check(t, info.Protocol, r, err)
				}()
			}
			wg.Wait()
		})
	}
}

// Cancelling a scan stops every fingerprinter promptly, whatever step it is
// in.
func TestCancellationIsPrompt(t *testing.T) {
	for _, fp := range otfp.Fingerprinters() {
		info := fp.Info()
		target := hostile(t, info.Network)["silent"]
		target.Timeout = 10 * time.Second
		t.Run(info.Protocol.Slug()+"-"+info.Network.String(), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, _ = fp.Detect(ctx, target, core.Options{Mode: core.ModeIdentify, MaxIntrusiveness: core.ReadOnly})
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("cancelled after 100ms, returned after %v", d)
			}
		})
	}
}

// Scans, including cancelled and parallel ones, leave no goroutines behind.
func TestNoGoroutineLeaks(t *testing.T) {
	tcp := hostile(t, core.TCP)
	udp := hostile(t, core.UDP)
	settle()
	before := runtime.NumGoroutine()

	for _, parallel := range []bool{false, true} {
		cfg := core.DefaultEngineConfig()
		cfg.Parallel = parallel
		cfg.Mode = core.ModeIdentify
		cfg.EarlyStop = false
		engine := otfp.NewEngine(cfg)
		for _, set := range []map[string]core.Target{tcp, udp} {
			for _, target := range set {
				target.Timeout = robustTimeout
				_, _ = engine.Scan(context.Background(), target)
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
				_, _ = engine.Scan(ctx, target)
				cancel()
			}
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		settle()
		// The hostile servers' per-connection goroutines end as their
		// clients disconnect; allow a little slack for those in flight.
		if n := runtime.NumGoroutine(); n <= before+2 {
			return
		} else if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			t.Fatalf("goroutines: %d before, %d after\n%s", before, n, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func settle() {
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
}
