// SPDX-License-Identifier: MIT

package can

import (
	"bytes"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// The limits of SECURITY.md for SLCAN gateways: a response line is at most
// maxResp octets.
func TestLimits(t *testing.T) {
	notMatched := func(t *testing.T, r core.Result, err error) {
		t.Helper()
		if err != nil || r.Matched {
			t.Errorf("%v (err %v), want no match", r, err)
		}
	}
	const budget = 64<<10 + 16*maxResp
	fuzzkit.Limits(t, New(),
		fuzzkit.Limit{Name: "maxResp octets without a line end", Replies: [][]byte{bytes.Repeat([]byte{'V'}, maxResp)},
			Budget: budget, Want: notMatched},
		fuzzkit.Limit{Name: "64 KiB without a line end", Replies: [][]byte{bytes.Repeat([]byte{'V'}, 64<<10)},
			Budget: budget, Want: notMatched},
	)
}
