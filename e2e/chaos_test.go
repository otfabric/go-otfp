// SPDX-License-Identifier: MIT

package e2e_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// fingerprinters returns the built-in fingerprinters this suite covers.
// MQTT and Sparkplug B are still being written and have their own suites.
func fingerprinters() []core.Fingerprinter {
	var out []core.Fingerprinter
	for _, fp := range otfp.Fingerprinters() {
		switch fp.Info().Protocol {
		case core.ProtocolMQTT, core.ProtocolSparkplugB:
			continue
		}
		out = append(out, fp)
	}
	return out
}

func echo(req []byte) ([]byte, bool) { return req, false }

// An echo service (TCP/UDP 7, a debugging loopback, a misconfigured
// gateway) returns each probe unchanged. The probe carries the
// fingerprinter's own header, transaction identifiers and function codes,
// so a fingerprinter that only checks the echoed fields matches its own
// request: none may.
func TestEchoIsNoProtocol(t *testing.T) {
	targets := map[core.Network]core.Target{
		core.TCP: testsrv.TCP(t, echo),
		core.UDP: testsrv.UDP(t, echo),
	}
	for _, fp := range fingerprinters() {
		info := fp.Info()
		target := targets[info.Network]
		target.Timeout = 300 * time.Millisecond
		t.Run(info.Protocol.Slug()+"-"+info.Network.String(), func(t *testing.T) {
			t.Parallel()
			for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
				r, err := fp.Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: core.ReadOnly})
				fuzzkit.Check(t, info.Protocol, r, err)
				if r.Matched {
					t.Fatalf("%s: an echo service matched: %v", mode, r)
				}
			}
		})
	}
}

// The cross-protocol matrix behind chaos: through fragmented writes every
// speaker is still detected as its own protocol and no other; through a
// flipped bit no other fingerprinter reaches a certain match.
func TestCrossProtocolMatrixUnderChaos(t *testing.T) {
	var fps []core.Fingerprinter
	for _, fp := range fingerprinters() {
		if fp.Info().Network == core.TCP {
			fps = append(fps, fp)
		}
	}
	faults := []chaos.Config{
		{Fault: chaos.OneByte},
		{Fault: chaos.Chunks, Seed: 7},
		{Fault: chaos.BitFlip, Seed: 1},
		{Fault: chaos.BitFlip, Seed: 2},
		{Fault: chaos.BitFlip, Seed: 3},
		{Fault: chaos.BitFlip, Seed: 4, After: 1},
	}
	// One goroutine per case: most cases wait out a foreign fingerprinter's
	// timeout, so running them all at once keeps the matrix to seconds.
	var wg sync.WaitGroup
	for speaker, handler := range speakers() {
		for _, cfg := range faults {
			served := chaos.TCP(t, cfg, handler)
			for _, fp := range fps {
				p := fp.Info().Protocol
				target := served
				target.Timeout = 300 * time.Millisecond
				if cfg.Fault.Complete() && p == speaker {
					// Room for a response written one octet at a time
					// under -race on a loaded runner.
					target.Timeout = chaos.CompleteTimeout
				}
				name := fmt.Sprintf("%s-on-%s/%s/seed%d/after%d", p.Slug(), speaker.Slug(), cfg.Fault, cfg.Seed, cfg.After)
				wg.Go(func() {
					for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
						r, err := fp.Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: core.ReadOnly})
						if msg := fuzzkit.Violation(p, r, err); msg != "" {
							t.Errorf("%s %s: %s", name, mode, msg)
						}
						switch {
						case cfg.Fault.Complete() && p == speaker && !r.Matched:
							t.Errorf("%s %s: did not detect its own protocol: %v (%v)", name, mode, r, err)
						case cfg.Fault.Complete() && p != speaker && r.Matched:
							t.Errorf("%s %s: false positive on a %s device: %v", name, mode, speaker, r)
						case p != speaker && r.Confidence >= core.ConfidenceCertain:
							t.Errorf("%s %s: certain match on a corrupted %s reply: %v", name, mode, speaker, r)
						}
					}
				})
			}
		}
	}
	wg.Wait()
}
