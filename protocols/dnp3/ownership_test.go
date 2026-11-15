// SPDX-License-Identifier: MIT

package dnp3

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// NewWithConfig keeps a copy of Config.Outstations: changing the caller's
// slice afterwards does not change the addresses probed.
func TestOutstationsAreCopied(t *testing.T) {
	addrs := []uint16{10, 20}
	f := NewWithConfig(Config{Outstations: addrs})
	addrs[0], addrs[1] = 777, 888

	rec := &chaos.Recorder{}
	target := testsrv.TCP(t, rec.Wrap(outstation(10, false)))
	if r, err := f.Detect(context.Background(), target, core.Options{}); err != nil || !r.Matched {
		t.Fatalf("%v %v", r, err)
	}
	var dsts []uint16
	for _, h := range frames(t, rec) {
		dsts = append(dsts, h.Dst)
	}
	if !slices.Equal(dsts, []uint16{selfAddress, 10, 20}) {
		t.Fatalf("frames to %v, want the self address, 10 and 20", dsts)
	}
}

// The fingerprinter frames its reads with its own function: what the Framer
// variable holds does not change a probe. The variable is set to a framer
// that ends every read after one octet, which no frame of the protocol is.
func TestFramerVariableIsNotReadByTheFingerprinter(t *testing.T) {
	saved := Framer
	t.Cleanup(func() { Framer = saved })
	Framer = func([]byte) int { return 1 }
	target := testsrv.TCP(t, outstation(10, true))
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain || r.Identity == nil {
		t.Fatalf("%v %v", r, err)
	}
}

// ParseHeader returns a Header of the caller's: Data is a copy.
func TestHeaderDataIsACopy(t *testing.T) {
	b := Frame(0x44, 1, 10, []byte("user data"))
	h, err := ParseHeader(b)
	if err != nil {
		t.Fatal(err)
	}
	for i := range b {
		b[i] = 0xEE
	}
	if !bytes.Equal(h.Data, []byte("user data")) {
		t.Fatalf("Data %q changed with the input", h.Data)
	}
}
