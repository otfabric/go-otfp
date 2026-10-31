// SPDX-License-Identifier: MIT

package e2e_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// The way an application uses the library: an address string through
// ParseTarget, a whole scan through the public engine, the report's best
// result. The engine must name the protocol the endpoint speaks.
func TestEngineScanFindsTheSpeaker(t *testing.T) {
	engine := otfp.NewEngine(core.EngineConfig{Mode: core.ModeIdentify, MaxIntrusiveness: core.ReadOnly})
	for speaker, handler := range speakers() {
		t.Run(speaker.Slug(), func(t *testing.T) {
			t.Parallel()
			srv := testsrv.TCP(t, handler)
			target, err := core.ParseTarget(fmt.Sprintf("%s:%d", srv.Host, srv.Port))
			if err != nil {
				t.Fatal(err)
			}
			target.Timeout = 300 * time.Millisecond
			report, err := engine.Scan(context.Background(), target)
			if err != nil {
				t.Fatal(err)
			}
			if report.Best.Protocol != speaker || !report.Best.Matched {
				t.Fatalf("best = %+v, want %s", report.Best, speaker)
			}
			for _, r := range report.Matches() {
				if r.Protocol != speaker {
					t.Errorf("false positive: %+v", r)
				}
			}
		})
	}
}

// A closed port is a report without a match, not an error or a hang.
func TestEngineScanOfClosedPort(t *testing.T) {
	target := testsrv.Closed(t)
	target.Timeout = 100 * time.Millisecond
	report, err := otfp.DefaultEngine().Scan(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if report.Best.Matched || report.Best.Protocol != core.ProtocolUnknown {
		t.Fatalf("best = %+v, want no match", report.Best)
	}
	if len(report.Results) == 0 {
		t.Fatal("no fingerprinter ran")
	}
}
