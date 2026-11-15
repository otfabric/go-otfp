// SPDX-License-Identifier: MIT

package e2e_test

import (
	"context"
	"errors"
	"testing"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
)

// A peer that stays silent is a timeout of the target's own Timeout, with
// no deadline on the scan's context: the error is a *core.TimeoutError and
// matches context.DeadlineExceeded, as a timeout of the context does.
func TestSilentPeerMatchesDeadlineExceeded(t *testing.T) {
	timeouts := 0
	for _, fp := range otfp.Fingerprinters() {
		info := fp.Info()
		target := hostile(t, info.Network)["silent"]
		target.Timeout = robustTimeout
		r, err := fp.Detect(context.Background(), target, core.Options{MaxIntrusiveness: core.ReadOnly})
		e := cmpErr(r, err)
		var te *core.TimeoutError
		if !errors.As(e, &te) {
			continue // a fingerprinter that judges silence as "not this protocol"
		}
		timeouts++
		if !errors.Is(e, context.DeadlineExceeded) {
			t.Errorf("%s over %s: %v does not match context.DeadlineExceeded", info.Protocol.Slug(), info.Network, e)
		}
	}
	if timeouts < 10 {
		t.Errorf("%d fingerprinters report a silent peer as a timeout, want most of them", timeouts)
	}
}
