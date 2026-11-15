// SPDX-License-Identifier: MIT

package canopen

import (
	"bytes"
	"strings"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// The limits of SECURITY.md for CANopen gateways: a response line is at
// most maxLine octets, and at most maxLines lines are read for one command.
func TestLimits(t *testing.T) {
	notMatched := func(t *testing.T, r core.Result, err error) {
		t.Helper()
		if err != nil || r.Matched {
			t.Errorf("%v (err %v), want no match", r, err)
		}
	}
	const budget = 64<<10 + 8*maxLines*maxLine
	fuzzkit.Limits(t, New(),
		fuzzkit.Limit{Name: "a line of maxLine octets without an end", Replies: [][]byte{bytes.Repeat([]byte{'A'}, maxLine)},
			Budget: budget, Want: notMatched},
		fuzzkit.Limit{Name: "64 KiB without a line end", Replies: [][]byte{bytes.Repeat([]byte{'A'}, 64<<10)},
			Budget: budget, Want: notMatched},
		fuzzkit.Limit{Name: "maxLines+1 lines of other sequence numbers", Replies: [][]byte{[]byte(strings.Repeat("[1] OK\r\n", maxLines+1))},
			Budget: budget, Want: notMatched},
		fuzzkit.Limit{Name: "a thousand lines of other sequence numbers", Replies: [][]byte{[]byte(strings.Repeat("[1] OK\r\n", 1000))},
			Budget: budget, Want: notMatched},
	)
}
