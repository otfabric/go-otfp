// SPDX-License-Identifier: MIT

// Command observe shows the three observability hooks of a scan: an
// Observer for progress, a slog Logger for diagnostics, and Trace for the
// raw bytes of every exchange.
//
//	go run ./examples/observe
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"os"
	"time"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/examples/internal/demo"
)

// progress prints each probe as it starts and ends. Observers must not
// block, and must be safe for concurrent use when the engine is parallel.
type progress struct{}

func (progress) OnStart(p core.Protocol, t core.Target) { fmt.Printf("-> %-10s %s\n", p.Slug(), t) }
func (progress) OnResult(r core.Result) {
	state := "no match"
	switch {
	case r.Matched:
		state = fmt.Sprintf("matched %.2f", r.Confidence)
	case r.Error != nil:
		state = "error: " + r.Error.Error()
	}
	fmt.Printf("<- %-10s %s\n", r.Protocol.Slug(), state)
}

func main() {
	addr, stop := demo.Modbus()
	defer stop()
	target, _ := core.ParseTarget(addr)
	target.Timeout = time.Second

	cfg := core.DefaultEngineConfig()
	cfg.Observer = progress{}
	cfg.Trace = true
	// Debug logging to stderr; at info level the library stays silent.
	cfg.Logger = core.NewSlogLogger(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg.Protocols = []core.Protocol{core.ProtocolMMS, core.ProtocolModbus}

	rep, err := otfp.NewEngine(cfg).Scan(context.Background(), target)
	if err != nil {
		log.Fatal(err)
	}
	for _, r := range rep.Results {
		for _, x := range r.Exchanges {
			fmt.Printf("   %s %s\n     > %s\n     < %s\n", r.Protocol.Slug(), x.Label, hex.EncodeToString(x.Probe), hex.EncodeToString(x.Response))
		}
	}
	fmt.Printf("best: %s (id %s, %s)\n", rep.Best, rep.Best.DetectionID, rep.Duration.Round(time.Millisecond))
}
