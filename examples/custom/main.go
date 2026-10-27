// SPDX-License-Identifier: MIT

// Command custom adds a fingerprinter of its own to the built-in ones: a
// detector for a line-based telemetry service that answers "STATUS" with
// "OK <model> <version>". It shows the Fingerprinter contract: Info
// describes the probe, Detect returns a scored Result, and a nil error with
// a NoMatch result means "not this protocol" while an error means "could
// not decide".
//
//	go run ./examples/custom
package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
)

// telemetry fingerprints the made-up "STATUS" protocol. It reuses the
// CAN protocol identifier only to stay within the built-in enumeration; a
// real extension would fork go-otfp's Protocol list or wrap results.
type telemetry struct{}

func (telemetry) Info() core.Info {
	return core.Info{
		Protocol:      core.ProtocolCAN,
		Network:       core.TCP,
		Ports:         []int{7000},
		Priority:      5,
		Intrusiveness: core.Passive,
		Description:   `"STATUS\n" -> "OK <model> <version>"`,
	}
}

func (t telemetry) Detect(ctx context.Context, target core.Target, opts core.Options) (core.Result, error) {
	p := t.Info().Protocol
	d := net.Dialer{Timeout: target.EffectiveTimeout()}
	conn, err := d.DialContext(ctx, "tcp", target.Addr())
	if err != nil {
		return core.NoMatch(p), core.ClassifyDial(p, target.Addr(), err) // could not decide
	}
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(target.EffectiveTimeout()))

	if _, err := conn.Write([]byte("STATUS\n")); err != nil {
		return core.NoMatch(p), core.ClassifyIO(p, target.Addr(), "write", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return core.NoMatch(p), nil // closed or garbage: simply not this protocol
	}
	fields := strings.Fields(line)
	if len(fields) != 3 || fields[0] != "OK" {
		return core.NoMatch(p), nil
	}
	r := core.Match(p, core.ConfidenceHigh, "STATUS telemetry service").
		WithEvidence(`"STATUS" answered "OK <model> <version>"`)
	if opts.Mode == core.ModeIdentify {
		r = r.WithIdentity(&core.Identity{Model: fields[1], Version: fields[2]})
	}
	return r, nil
}

func main() {
	addr, stop := statusServer()
	defer stop()
	target, _ := core.ParseTarget(addr)
	target.Timeout = time.Second

	// Ours plus the built-in fingerprinters (CAN's slot is taken by ours in
	// this demo); Plan tries ours first on its port, by priority elsewhere.
	reg := core.NewRegistry().MustRegister(telemetry{})
	for _, fp := range otfp.Fingerprinters() {
		if fp.Info().Protocol != core.ProtocolCAN {
			_ = reg.Register(fp)
		}
	}

	engine := core.NewEngine(reg, core.EngineConfig{Mode: core.ModeIdentify, EarlyStop: true})
	rep, err := engine.Scan(context.Background(), target)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s: %s, %s\n", target, rep.Best.Details, rep.Best.Identity)
}

// statusServer runs the made-up service on loopback.
func statusServer() (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close() //nolint:errcheck
				if line, _ := bufio.NewReader(c).ReadString('\n'); line == "STATUS\n" {
					_, _ = c.Write([]byte("OK TX-9 4.1\n"))
				}
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}
