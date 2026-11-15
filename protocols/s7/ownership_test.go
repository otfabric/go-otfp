// SPDX-License-Identifier: MIT

package s7

import (
	"bytes"
	"context"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/iso"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// NewWithConfig keeps a copy of Config.CalledTSAPs: changing the caller's
// slice afterwards does not change the TSAP of the connection request.
func TestCalledTSAPsAreCopied(t *testing.T) {
	tsaps := []uint16{0x0105}
	f := NewWithConfig(Config{CalledTSAPs: tsaps})
	tsaps[0] = 0x0999

	rec := &chaos.Recorder{}
	target := testsrv.TCP(t, rec.Wrap(plc()))
	if r, err := f.Detect(context.Background(), target, core.Options{}); err != nil || !r.Matched {
		t.Fatalf("%v %v", r, err)
	}
	reqs := rec.Requests()
	if len(reqs) == 0 || iso.TPDUType(reqs[0]) != iso.TPDUConnectRequest {
		t.Fatalf("first request % x is not a COTP CR", reqs)
	}
	if want := []byte{iso.ParamCalledTSAP, 2, 0x01, 0x05}; !bytes.Contains(reqs[0], want) {
		t.Fatalf("COTP CR % x, want the called TSAP of construction (% x)", reqs[0], want)
	}
}
