// SPDX-License-Identifier: MIT

package iec104

import (
	"context"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// The fingerprinter frames its reads with its own function: what the Framer
// variable holds does not change a probe. The variable is set to a framer
// that ends every read after one octet, which no frame of the protocol is.
func TestFramerVariableIsNotReadByTheFingerprinter(t *testing.T) {
	saved := Framer
	t.Cleanup(func() { Framer = saved })
	Framer = func([]byte) int { return 1 }
	target := testsrv.TCP(t, station(1, false))
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v %v", r, err)
	}
}

// Parse borrows: the ASDU of the result is the part of the input after the
// control field, as its doc comment says, not a copy.
func TestParseBorrowsTheASDU(t *testing.T) {
	b := []byte{0x68, 0x0E, 0, 0, 0, 0, 70, 1, 4, 0, 1, 0, 0, 0, 0, 0}
	a, err := Parse(b)
	if err != nil || len(a.ASDU) != 10 || a.ASDU[0] != 70 {
		t.Fatalf("%+v %v", a, err)
	}
	b[6] = 30
	if a.ASDU[0] != 30 {
		t.Fatalf("ASDU[0] = %d after the input changed: Parse is documented to borrow", a.ASDU[0])
	}
}
