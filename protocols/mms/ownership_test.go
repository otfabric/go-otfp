// SPDX-License-Identifier: MIT

package mms

import (
	"bytes"
	"context"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/iso"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// NewWithConfig keeps copies of the transport selectors: changing the
// caller's slices afterwards does not change the connection request.
func TestTSELsAreCopied(t *testing.T) {
	calling, called := []byte{0x00, 0x07}, []byte{0x00, 0x09}
	f := NewWithConfig(Config{CallingTSEL: calling, CalledTSEL: called})
	calling[1], called[1] = 0xAA, 0xBB

	rec := &chaos.Recorder{}
	target := testsrv.TCP(t, rec.Wrap(server()))
	if r, err := f.Detect(context.Background(), target, core.Options{}); err != nil || !r.Matched {
		t.Fatalf("%v %v", r, err)
	}
	reqs := rec.Requests()
	if len(reqs) == 0 || iso.TPDUType(reqs[0]) != iso.TPDUConnectRequest {
		t.Fatalf("first request % x is not a COTP CR", reqs)
	}
	want := []byte{iso.ParamCallingTSAP, 2, 0x00, 0x07, iso.ParamCalledTSAP, 2, 0x00, 0x09}
	if !bytes.Contains(reqs[0], want) {
		t.Fatalf("COTP CR % x, want the selectors of construction (% x)", reqs[0], want)
	}
	// The defaults are the fingerprinter's own as well.
	a, b := New(), New()
	a.calling[1] = 0x55
	if b.calling[1] != 0x01 {
		t.Fatal("two fingerprinters share their default selector")
	}
}
