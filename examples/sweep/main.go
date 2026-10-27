// SPDX-License-Identifier: MIT

// Command sweep scans several ports of one host with a conservative, OT-safe
// engine: passive probes only, the protocols of each port only, and a pause
// between probes.
//
//	go run ./examples/sweep                       # built-in demo devices
//	go run ./examples/sweep 10.0.0.5 502 102 2404 # real ports
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/examples/internal/demo"
)

func main() {
	var targets []core.Target
	if len(os.Args) > 2 {
		for _, p := range os.Args[2:] {
			port, err := strconv.Atoi(p)
			if err != nil {
				log.Fatalf("port %q: %v", p, err)
			}
			targets = append(targets, core.Target{Host: os.Args[1], Port: port})
		}
	} else {
		for _, start := range []func() (string, func()){demo.Modbus, demo.IEC104} {
			addr, stop := start()
			defer stop()
			t, _ := core.ParseTarget(addr)
			targets = append(targets, t)
		}
	}

	cfg := core.SafeEngineConfig()
	cfg.MinInterval = 50 * time.Millisecond
	cfg.LikelyOnly = false // the demo devices are not on well-known ports
	engine := otfp.NewEngine(cfg)

	for _, t := range targets {
		t.Timeout = time.Second
		rep, err := engine.Scan(context.Background(), t)
		if err != nil {
			log.Fatal(err)
		}
		if rep.Best.Matched {
			fmt.Printf("%-24s %-18s %.2f\n", t, rep.Best.Protocol, rep.Best.Confidence)
		} else {
			fmt.Printf("%-24s %-18s\n", t, "-")
		}
	}
}
