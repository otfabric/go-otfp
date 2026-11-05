// SPDX-License-Identifier: MIT

package opcua

import (
	"math"
	"testing"
)

func TestInt32LE(t *testing.T) {
	for v, b := range map[int32][]byte{
		0:             {0, 0, 0, 0},
		1:             {1, 0, 0, 0},
		-1:            {0xff, 0xff, 0xff, 0xff},
		-2:            {0xfe, 0xff, 0xff, 0xff},
		math.MaxInt32: {0xff, 0xff, 0xff, 0x7f},
		math.MinInt32: {0, 0, 0, 0x80},
	} {
		if got := int32LE(b); got != v {
			t.Errorf("% x decoded as %d, want %d", b, got, v)
		}
	}
}
