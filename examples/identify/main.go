// SPDX-License-Identifier: MIT

// Command identify detects one protocol and reads the device identity over
// that protocol's own read-only identification service.
//
//	go run ./examples/identify                    # a built-in demo Modbus device
//	go run ./examples/identify 10.0.0.5:44818 enip # a real EtherNet/IP adapter
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/examples/internal/demo"
)

func main() {
	addr, protocol := "", "modbus"
	if len(os.Args) > 2 {
		addr, protocol = os.Args[1], os.Args[2]
	} else {
		var stop func()
		addr, stop = demo.Modbus()
		defer stop()
	}
	p, err := core.ParseProtocol(protocol) // a slug, a name or an alias
	if err != nil {
		log.Fatal(err)
	}
	target, err := core.ParseTarget(addr)
	if err != nil {
		log.Fatal(err)
	}
	target.Timeout = 2 * time.Second

	engine := otfp.NewEngine(core.EngineConfig{Mode: core.ModeIdentify})
	r, err := engine.Detect(context.Background(), target, p)
	if err != nil {
		log.Fatal(err) // no fingerprinter for this protocol over the target's network
	}
	switch {
	case r.Error != nil:
		fmt.Println("could not decide:", r.Error) // unreachable or timed out
		return
	case !r.Matched:
		fmt.Printf("not %s (confidence %.2f)\n", p, r.Confidence)
		return
	}
	fmt.Printf("%s, confidence %.2f\n", r.Protocol, r.Confidence)
	if id := r.Identity; id != nil {
		fmt.Println("  vendor: ", id.Vendor)
		fmt.Println("  product:", id.Product)
		fmt.Println("  model:  ", id.Model)
		fmt.Println("  version:", id.Version)
		keys := make([]string, 0, len(id.Attributes))
		for k := range id.Attributes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %s: %s\n", k, id.Attributes[k])
		}
	}
	fmt.Println("  fingerprint:", r.Fingerprint)
}
