// SPDX-License-Identifier: MIT

package core_test

import (
	"fmt"

	"github.com/otfabric/go-otfp/core"
)

// Targets are written as host:port, optionally with a tcp, udp or tls
// scheme.
func ExampleParseTarget() {
	for _, s := range []string{"10.0.0.5:502", "udp://10.0.0.5:47808", "tls://plc.example:802", "[fe80::1]:102"} {
		t, err := core.ParseTarget(s)
		if err != nil {
			panic(err)
		}
		fmt.Println(t, t.Network, t.TLS != nil)
	}
	// Output:
	// tcp://10.0.0.5:502 tcp false
	// udp://10.0.0.5:47808 udp false
	// tcp+tls://plc.example:802 tcp true
	// tcp://[fe80::1]:102 tcp false
}

// Protocols parse from their slug, their name or a common alias, and
// marshal to the slug.
func ExampleParseProtocol() {
	for _, s := range []string{"modbus", "Siemens S7comm", "ethernetip", "2030.5"} {
		p, _ := core.ParseProtocol(s)
		fmt.Printf("%-16s -> %-10s %s\n", s, p.Slug(), p)
	}
	// Output:
	// modbus           -> modbus     Modbus TCP
	// Siemens S7comm   -> s7comm     Siemens S7comm
	// ethernetip       -> enip       EtherNet/IP
	// 2030.5           -> ieee2030.5 IEEE 2030.5
}

// A result is matched when its confidence reaches MatchThreshold; below it
// it is a hint.
func ExampleMatch() {
	for _, c := range []core.Confidence{core.ConfidenceLow, core.ConfidenceMedium, core.ConfidenceCertain} {
		r := core.Match(core.ProtocolDNP3, c, "")
		fmt.Println(r.Confidence, r.Matched)
	}
	// Output:
	// 0.3 false
	// 0.6 true
	// 1 true
}
