// SPDX-License-Identifier: MIT

package wire

import (
	"math"
	"strconv"
	"testing"
)

func TestLenHelpers(t *testing.T) {
	if Len8(255) != 255 || Len16(math.MaxUint16) != math.MaxUint16 || Len32(1<<20) != 1<<20 {
		t.Fatal("in-range lengths changed")
	}
	for name, f := range map[string]func(){
		"len8 high":  func() { Len8(256) },
		"len8 neg":   func() { Len8(-1) },
		"len16 high": func() { Len16(math.MaxUint16 + 1) },
		"len16 neg":  func() { Len16(-1) },
		"len32 neg":  func() { Len32(-1) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			f()
		}()
	}
	if strconv.IntSize == 64 {
		big := int64(math.MaxUint32) + 1
		func() {
			defer func() {
				if recover() == nil {
					t.Error("len32 high: no panic")
				}
			}()
			Len32(int(big))
		}()
	}
}
