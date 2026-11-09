// SPDX-License-Identifier: MIT

package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// A Dialer that refuses every address, as an allowlist would, must stop
// every fingerprinter: a live speaker is never reached, and each result
// carries the dialer's error. A fingerprinter that dialled directly would
// reach the speaker and match.
func TestEngineDialerCoversEveryFingerprinter(t *testing.T) {
	errBlocked := errors.New("blocked by allowlist")
	var mu sync.Mutex
	networks := map[string]int{}
	dial := func(_ context.Context, network, _ string) (net.Conn, error) {
		mu.Lock()
		networks[network]++
		mu.Unlock()
		return nil, errBlocked
	}
	targets := map[string]core.Target{
		"tcp": testsrv.TCP(t, speakers()[core.ProtocolModbus]),
		"udp": testsrv.UDP(t, udpSpeakers()["bacnet"].h),
	}
	for _, parallel := range []bool{false, true} {
		for name, target := range targets {
			t.Run(fmt.Sprintf("%s/parallel=%v", name, parallel), func(t *testing.T) {
				engine := otfp.NewEngine(core.EngineConfig{
					Mode: core.ModeIdentify, MaxIntrusiveness: core.ReadOnly,
					Parallel: parallel, Dialer: dial,
				})
				target.Timeout = 300 * time.Millisecond
				report, err := engine.Scan(context.Background(), target)
				if err != nil {
					t.Fatal(err)
				}
				if len(report.Results) == 0 {
					t.Fatal("no fingerprinter ran")
				}
				for _, r := range report.Results {
					if r.Matched {
						t.Errorf("%s matched through a refusing dialer: %+v", r.Protocol.Slug(), r)
					}
					if !errors.Is(r.Error, errBlocked) {
						t.Errorf("%s: Error = %v, want the dialer's error", r.Protocol.Slug(), r.Error)
					}
				}
			})
		}
	}
	if networks["tcp"] == 0 || networks["udp"] == 0 {
		t.Errorf("dialer saw networks %v, want tcp and udp", networks)
	}
}

// A pass-through Dialer changes nothing: the engine still names the speaker.
func TestEngineDialerPassThroughFindsTheSpeaker(t *testing.T) {
	srv := testsrv.TCP(t, speakers()[core.ProtocolModbus])
	var mu sync.Mutex
	var addrs []string
	engine := otfp.NewEngine(core.EngineConfig{
		Mode: core.ModeIdentify, MaxIntrusiveness: core.ReadOnly,
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			addrs = append(addrs, network+" "+addr)
			mu.Unlock()
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	})
	srv.Timeout = 300 * time.Millisecond
	report, err := engine.Scan(context.Background(), srv)
	if err != nil {
		t.Fatal(err)
	}
	if report.Best.Protocol != core.ProtocolModbus || !report.Best.Matched {
		t.Fatalf("best = %+v, want modbus", report.Best)
	}
	want := "tcp " + srv.Addr()
	for _, a := range addrs {
		if a != want {
			t.Errorf("dialer got %q, want %q", a, want)
		}
	}
	if len(addrs) == 0 {
		t.Error("dialer never called")
	}
}

// Faults on the client's own connection, injected through the Dialer: its
// requests are bit-flipped, duplicated, cut or reset. chaos.Stall is left
// out: it blocks inside Write past the client's deadlines, so on the client
// side it would time the wrapper, not the library; a silent peer is covered
// by the server-side Stall cases (TestHostileServersBounded). Every
// fingerprinter must keep its result contract (fuzzkit.Violation), never
// claim certainty on another protocol's endpoint, and return within its
// timeout. TestEngineClosesEveryDialedConnection covers the leak side.
func TestClientSideFaultsThroughDialer(t *testing.T) {
	var fps []core.Fingerprinter
	for _, fp := range otfp.Fingerprinters() {
		if fp.Info().Network == core.TCP {
			fps = append(fps, fp)
		}
	}
	faults := []chaos.Config{
		{Fault: chaos.Duplicate},
		{Fault: chaos.BitFlip, Seed: 1},
		{Fault: chaos.BitFlip, Seed: 2},
		{Fault: chaos.Truncate, Seed: 3},
		{Fault: chaos.Reset, Seed: 4},
	}
	const timeout = 300 * time.Millisecond
	var wg sync.WaitGroup
	for speaker, h := range speakers() {
		served := testsrv.TCP(t, h)
		served.Timeout = timeout
		for _, cfg := range faults {
			opts := core.Options{Mode: core.ModeIdentify, MaxIntrusiveness: core.ReadOnly,
				Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
					var d net.Dialer
					c, err := d.DialContext(ctx, network, addr)
					if err != nil {
						return nil, err
					}
					return chaos.Wrap(c, cfg), nil
				}}
			for _, fp := range fps {
				p := fp.Info().Protocol
				name := fmt.Sprintf("%s-on-%s/%s/seed%d", p.Slug(), speaker.Slug(), cfg.Fault, cfg.Seed)
				wg.Go(func() {
					start := time.Now()
					r, err := fp.Detect(context.Background(), served, opts)
					if d := time.Since(start); d > 10*timeout {
						t.Errorf("%s: took %v", name, d)
					}
					if msg := fuzzkit.Violation(p, r, err); msg != "" {
						t.Errorf("%s: %s", name, msg)
					}
					if p != speaker && r.Confidence >= core.ConfidenceCertain {
						t.Errorf("%s: certain match on a %s endpoint: %v", name, speaker.Slug(), r)
					}
				})
			}
		}
	}
	wg.Wait()
}

// countingDialer dials for real and counts the connections it hands out
// and those the library closes again.
type countingDialer struct{ opened, closed atomic.Int64 }

type countedConn struct {
	net.Conn
	d    *countingDialer
	once sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() { c.d.closed.Add(1) })
	return c.Conn.Close()
}

func (d *countingDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var nd net.Dialer
	c, err := nd.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	d.opened.Add(1)
	return &countedConn{Conn: c, d: d}, nil
}

// Every connection the Dialer hands out is closed again by the library,
// matched or not, on TCP and UDP, sequential and parallel, and on a
// cancelled scan; nothing leaks goroutines or file descriptors.
func TestEngineClosesEveryDialedConnection(t *testing.T) {
	var targets []core.Target
	for _, h := range speakers() {
		targets = append(targets, testsrv.TCP(t, h))
	}
	for _, sp := range udpSpeakers() {
		targets = append(targets, testsrv.UDP(t, sp.h))
	}
	settle()
	goroutines, fds := runtime.NumGoroutine(), chaos.FDs()

	var d countingDialer
	for _, parallel := range []bool{false, true} {
		cfg := core.DefaultEngineConfig()
		cfg.Mode, cfg.EarlyStop, cfg.Parallel, cfg.Dialer = core.ModeIdentify, false, parallel, d.dial
		engine := otfp.NewEngine(cfg)
		for _, target := range targets {
			target.Timeout = 300 * time.Millisecond
			if _, err := engine.Scan(context.Background(), target); err != nil {
				t.Fatalf("scan %s: %v", target.Addr(), err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			_, _ = engine.Scan(ctx, target)
			cancel()
		}
	}
	if d.opened.Load() == 0 {
		t.Fatal("the dialer opened no connection")
	}
	if o, c := d.opened.Load(), d.closed.Load(); o != c {
		t.Errorf("dialer opened %d connections, the library closed %d", o, c)
	}
	chaos.CheckLeaks(t, goroutines, fds)
}

// A Dialer that stalls until its context ends (a proxy that never answers)
// bounds every fingerprinter by the target timeout: each returns a timeout
// error and no match, and a cancelled scan returns at once.
func TestStalledDialerIsBoundedByTheTimeout(t *testing.T) {
	stall := func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	const timeout = 200 * time.Millisecond
	target := core.Target{Host: "192.0.2.1", Port: 102, Timeout: timeout}
	opts := core.Options{Mode: core.ModeIdentify, MaxIntrusiveness: core.ReadOnly, Dialer: stall}
	var wg sync.WaitGroup
	for _, fp := range otfp.Fingerprinters() {
		p := fp.Info().Protocol
		tg := target
		tg.Network = fp.Info().Network // a fingerprinter skips another network
		wg.Go(func() {
			start := time.Now()
			r, err := fp.Detect(context.Background(), tg, opts)
			if d := time.Since(start); d > 5*timeout {
				t.Errorf("%s: took %v with a %v timeout", p.Slug(), d, timeout)
			}
			if msg := fuzzkit.Violation(p, r, err); msg != "" {
				t.Errorf("%s: %s", p.Slug(), msg)
			}
			if r.Matched {
				t.Errorf("%s: matched through a stalled dialer: %+v", p.Slug(), r)
			}
			if e := cmpErr(r, err); !core.IsTimeout(e) {
				t.Errorf("%s: error %v, want a timeout", p.Slug(), e)
			}
		})
	}
	wg.Wait()

	engine := otfp.NewEngine(core.EngineConfig{Mode: core.ModeIdentify, MaxIntrusiveness: core.ReadOnly, Dialer: stall})
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	target.Timeout = 10 * time.Second
	start := time.Now()
	_, _ = engine.Scan(ctx, target)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("cancelled scan through a stalled dialer took %v", d)
	}
}

// cmpErr is the error a fingerprinter reported: the returned one, else the
// result's.
func cmpErr(r core.Result, err error) error {
	if err != nil {
		return err
	}
	return r.Error
}
