// SPDX-License-Identifier: MIT

package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
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
// timeout. TestNoGoroutineLeaks covers the leak side of the same paths.
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
