// SPDX-License-Identifier: MIT

package e2e_test

import (
	"bytes"
	"context"
	"regexp"
	"sync"
	"testing"
	"time"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/mbap"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// started records which fingerprinters an engine ran.
type started struct {
	mu  sync.Mutex
	got []core.Protocol
}

func (s *started) OnStart(p core.Protocol, _ core.Target) {
	s.mu.Lock()
	s.got = append(s.got, p)
	s.mu.Unlock()
}
func (s *started) OnResult(core.Result) {}

// The engines never run a fingerprinter above their MaxIntrusiveness: the
// safe configuration runs no read-only one (SunSpec), the default one may.
func TestEngineHonoursMaxIntrusiveness(t *testing.T) {
	intrusiveness := map[core.Protocol]core.Intrusiveness{}
	for _, fp := range otfp.Fingerprinters() {
		intrusiveness[fp.Info().Protocol] = max(intrusiveness[fp.Info().Protocol], fp.Info().Intrusiveness)
	}
	targets := []core.Target{
		testsrv.TCP(t, speakers()[core.ProtocolModbus]), // a Modbus device, where SunSpec would refine
		testsrv.TCP(t, testsrv.Script()),
		testsrv.UDP(t, testsrv.Script()),
	}
	for name, cfg := range map[string]core.EngineConfig{
		"default": core.DefaultEngineConfig(),
		"safe":    core.SafeEngineConfig(),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			obs := &started{}
			cfg.Observer = obs
			cfg.Mode = core.ModeIdentify
			cfg.EarlyStop = false
			cfg.MinInterval = 0
			cfg.LikelyOnly = false // run them all: the filter is the point
			for _, target := range targets {
				target.Timeout = 150 * time.Millisecond
				if _, err := otfp.NewEngine(cfg).Scan(context.Background(), target); err != nil {
					t.Fatal(err)
				}
			}
			ranSunSpec := false
			for _, p := range obs.got {
				if intrusiveness[p] > cfg.MaxIntrusiveness {
					t.Fatalf("%s ran with MaxIntrusiveness %s", p, cfg.MaxIntrusiveness)
				}
				ranSunSpec = ranSunSpec || p == core.ProtocolSunSpec
			}
			if want := cfg.MaxIntrusiveness >= core.ReadOnly; ranSunSpec != want {
				t.Fatalf("SunSpec ran: %v, want %v", ranSunSpec, want)
			}
		})
	}
}

// A passive scan takes none of the read-only steps that passive
// fingerprinters take when read-only probes are allowed: no Modbus FC 03
// fallback, no OpenADR 2.0b registration POST, no CANopen SDO upload.
// Recorded on the wire, through a full identify-mode engine scan.
func TestPassiveScanSendsNoReadOnlyStep(t *testing.T) {
	sdoRead := regexp.MustCompile(`\] (\d+ )?r 0x`)
	// A Modbus stack that closes on FC 43 (digitalpetri, NModbus),
	// which is what triggers the FC 03 fallback.
	modbus := func(req []byte) ([]byte, bool) {
		if len(req) < 8 || req[7] == mbap.FCEncapsulated {
			return nil, true
		}
		return mbap.Request(uint16(req[0])<<8|uint16(req[1]), req[6], 0x03, 0x02, 0, 0), false
	}
	// A CiA 309-3 gateway answering every command with its version.
	gateway := func(req []byte) ([]byte, bool) {
		line := bytes.TrimSpace(req)
		if i := bytes.IndexByte(line, ']'); len(line) > 0 && line[0] == '[' && i > 0 {
			return append(line[:i+1:i+1], []byte(" 0x00000001 0x00000002 0x00000003 0x00000004 1 1 1\r\n")...), false
		}
		return nil, false
	}
	// An HTTP server answering 404 to everything.
	web := func(req []byte) ([]byte, bool) {
		return []byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"), true
	}
	for level, wantReadOnly := range map[core.Intrusiveness]bool{core.Passive: false, core.ReadOnly: true} {
		t.Run(level.String(), func(t *testing.T) {
			t.Parallel()
			var (
				mu              sync.Mutex
				fc03, post, sdo bool
				wg              sync.WaitGroup
			)
			for name, h := range map[string]testsrv.Handler{"modbus": modbus, "gateway": gateway, "web": web} {
				rec := &chaos.Recorder{}
				target := testsrv.TCP(t, rec.Wrap(h))
				target.Timeout = 200 * time.Millisecond
				cfg := core.DefaultEngineConfig()
				cfg.MaxIntrusiveness = level
				cfg.Mode = core.ModeIdentify
				cfg.EarlyStop = false
				cfg.StopOnRefused = false
				wg.Go(func() {
					if _, err := otfp.NewEngine(cfg).Scan(context.Background(), target); err != nil {
						t.Error(err)
					}
					mu.Lock()
					defer mu.Unlock()
					for _, req := range rec.Requests() {
						switch name {
						case "modbus":
							fc03 = fc03 || (len(req) > 7 && req[2] == 0 && req[3] == 0 && req[7] == mbap.FCReadHoldingRegisters)
						case "web":
							post = post || bytes.HasPrefix(req, []byte("POST "))
						case "gateway":
							sdo = sdo || sdoRead.Match(req)
						}
					}
				})
			}
			wg.Wait()
			if fc03 != wantReadOnly || post != wantReadOnly || sdo != wantReadOnly {
				t.Fatalf("FC 03 %v, POST %v, SDO upload %v; want %v", fc03, post, sdo, wantReadOnly)
			}
		})
	}
}
