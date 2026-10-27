// SPDX-License-Identifier: MIT

package otfp_test

import (
	"testing"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
)

func TestDefaultRegistry(t *testing.T) {
	r := otfp.DefaultRegistry()
	got := map[core.Protocol]bool{}
	for _, p := range r.Protocols() {
		got[p] = true
	}
	for _, p := range core.AllProtocols() {
		if !got[p] {
			t.Errorf("no fingerprinter for %s", p)
		}
	}
	// EtherNet/IP over both transports.
	if r.Get(core.ProtocolENIP, core.TCP) == nil || r.Get(core.ProtocolENIP, core.UDP) == nil {
		t.Fatal("ENIP should be registered over TCP and UDP")
	}
	if r.Get(core.ProtocolBACnet, core.UDP) == nil {
		t.Fatal("BACnet should be UDP")
	}
}

func TestEngineConstructors(t *testing.T) {
	if otfp.DefaultEngine() == nil || otfp.NewEngine(core.SafeEngineConfig()) == nil {
		t.Fatal("nil engine")
	}
}

func TestFingerprintersFresh(t *testing.T) {
	a := otfp.Fingerprinters()
	b := otfp.Fingerprinters()
	if &a[0] == &b[0] {
		t.Fatal("Fingerprinters should return fresh slices")
	}
	if len(a) != len(core.AllProtocols())+1 { // +1 for ENIP's second transport
		t.Fatalf("%d fingerprinters", len(a))
	}
}
