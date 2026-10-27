// SPDX-License-Identifier: MIT

// Command quickstart scans one endpoint with the default engine and prints
// the protocol it speaks.
//
//	go run ./examples/quickstart              # a built-in demo Modbus device
//	go run ./examples/quickstart 10.0.0.5:502 # a real endpoint
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/examples/internal/demo"
)

func main() {
	addr := ""
	if len(os.Args) > 1 {
		addr = os.Args[1]
	} else {
		var stop func()
		addr, stop = demo.Modbus()
		defer stop()
	}

	// "host:port", "udp://host:port" or "tls://host:port".
	target, err := core.ParseTarget(addr)
	if err != nil {
		log.Fatal(err)
	}
	target.Timeout = 2 * time.Second

	report, err := otfp.DefaultEngine().Scan(context.Background(), target)
	if err != nil {
		log.Fatal(err) // an invalid target, or no fingerprinter for its transport
	}
	if !report.Best.Matched {
		fmt.Printf("%s: no OT protocol detected (%d probes)\n", target, len(report.Results))
		return
	}
	best := report.Best
	fmt.Printf("%s speaks %s (confidence %.2f)\n", target, best.Protocol, best.Confidence)
	for _, e := range best.Evidence {
		fmt.Println("  -", e)
	}
}
