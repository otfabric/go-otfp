// SPDX-License-Identifier: MIT

package otfp_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
)

// Scan an endpoint with the default engine. The engine tries the
// fingerprinters of the target's port first and stops at the first
// confident match.
func ExampleDefaultEngine() {
	addr, stop := exampleModbusDevice()
	defer stop()

	target, _ := core.ParseTarget(addr) // e.g. "10.0.0.5:502"
	report, err := otfp.DefaultEngine().Scan(context.Background(), target)
	if err != nil {
		panic(err) // invalid target, or no fingerprinter for its transport
	}
	fmt.Println(report.Best.Protocol, report.Best.Matched, report.Best.Confidence)
	// Output: Modbus TCP true 1
}

// Read the device identity with one protocol's fingerprinter, in identify
// mode.
func ExampleNewEngine_identify() {
	addr, stop := exampleModbusDevice()
	defer stop()

	target, _ := core.ParseTarget(addr)
	target.Timeout = 2 * time.Second
	engine := otfp.NewEngine(core.EngineConfig{Mode: core.ModeIdentify})

	r, err := engine.Detect(context.Background(), target, core.ProtocolModbus)
	if err != nil {
		panic(err)
	}
	fmt.Println(r.Identity.Vendor, "/", r.Identity.Product, "/", r.Identity.Version)
	fmt.Println(r.Fingerprint.ID)
	// Output:
	// OT Fabric / Demo PLC / 1.2.0
	// modbus.fc43
}

// A conservative scan for production OT networks: passive probes only, the
// port's likely protocols only, and a pause between probes.
func ExampleNewEngine_safe() {
	cfg := core.SafeEngineConfig()
	fmt.Println(cfg.MaxIntrusiveness, cfg.LikelyOnly, cfg.MinInterval, cfg.Parallel)
	// Output: passive true 250ms false
}

// The order in which the engine tries the built-in fingerprinters on port
// 102 (ISO-on-TCP): the port's protocols first.
func ExampleDefaultRegistry() {
	plan := otfp.DefaultRegistry().Plan(core.Target{Host: "10.0.0.5", Port: 102})
	for _, fp := range plan[:3] {
		fmt.Println(fp.Info().Protocol.Slug())
	}
	// Output:
	// mms
	// s7comm
	// iec104
}

// exampleModbusDevice serves Read Device Identification on loopback.
func exampleModbusDevice() (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	objs := []string{"OT Fabric", "DEMO-1", "1.2.0", "", "Demo PLC", "D-100"}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 260)
				for {
					n, err := c.Read(buf)
					if err != nil || n < 11 {
						return
					}
					pdu := []byte{0x2B, 0x0E, buf[9], 0x82, 0, 0, byte(len(objs))}
					for i, v := range objs {
						pdu = append(append(pdu, byte(i), byte(len(v))), v...)
					}
					resp := append([]byte{buf[0], buf[1], 0, 0, 0, 0, buf[6]}, pdu...)
					binary.BigEndian.PutUint16(resp[4:], uint16(1+len(pdu)))
					if _, err := c.Write(resp); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}
