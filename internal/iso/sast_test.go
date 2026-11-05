// SPDX-License-Identifier: MIT

package iso

import (
	"bytes"
	"testing"
)

func TestConnectRequestMaxTSELs(t *testing.T) {
	cr := ConnectRequest(1, bytes.Repeat([]byte{1}, MaxTSELs-1), []byte{2}, 0x0a)
	if cr[4] != 254 || len(cr) != TPKTHeaderLen+255 {
		t.Fatalf("LI %d, %d octets", cr[4], len(cr))
	}
	defer func() {
		if recover() == nil {
			t.Fatal("TSAPs beyond MaxTSELs did not panic")
		}
	}()
	ConnectRequest(1, bytes.Repeat([]byte{1}, MaxTSELs), []byte{2}, 0x0a)
}
