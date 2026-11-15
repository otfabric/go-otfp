// SPDX-License-Identifier: MIT

package sunspec

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
	"github.com/otfabric/go-otfp/internal/mbap"
)

// The limits of SECURITY.md for SunSpec: the model chain is walked for at
// most maxModels models, however long the device's chain is.
func TestLimits(t *testing.T) {
	// The reader numbers its requests from 0x5301; the peer answers the
	// n-th request with the n-th reply.
	tid := uint16(0x5300)
	registers := func(regs ...uint16) []byte {
		tid++
		pdu := []byte{mbap.FCReadHoldingRegisters, byte(2 * len(regs))}
		for _, r := range regs {
			pdu = binary.BigEndian.AppendUint16(pdu, r)
		}
		return mbap.Request(tid, 1, pdu...)
	}
	replies := [][]byte{registers(marker0, marker1)}
	common := make([]uint16, 68)
	common[0], common[1] = commonModel, 66
	replies = append(replies, registers(common...))
	for i := range 2 * maxModels { // a chain that never ends
		replies = append(replies, registers(uint16(100+i), 0))
	}
	fuzzkit.Limits(t, New(), fuzzkit.Limit{
		Name: "a model chain without an end", Mode: core.ModeIdentify, Replies: replies,
		Budget: 64<<10 + maxModels*16*mbap.MaxADU,
		Want: func(t *testing.T, r core.Result, err error) {
			t.Helper()
			if err != nil || !r.Matched || r.Identity == nil {
				t.Fatalf("%v (err %v)", r, err)
			}
			models := strings.Split(r.Identity.Attributes["models"], ",")
			if len(models) != maxModels || models[0] != "1" || models[len(models)-1] == "end" {
				t.Errorf("%d models listed (%v), want the first %d", len(models), models, maxModels)
			}
		},
	})
}
