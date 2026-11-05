// SPDX-License-Identifier: MIT

package dnp3

import (
	"bytes"
	"testing"
)

// User data beyond one frame used to wrap the LEN octet: 251 octets gave
// LEN 0x00, a frame no outstation accepts.
func TestFrameMaxData(t *testing.T) {
	f := Frame(0x44, 1, 1024, bytes.Repeat([]byte{0xAA}, maxFrameData))
	if f[2] != 0xFF {
		t.Fatalf("LEN 0x%02x", f[2])
	}
	if h, err := ParseHeader(f); err != nil || len(h.Data) != maxFrameData {
		t.Fatalf("%+v %v", h, err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("oversized user data did not panic")
		}
	}()
	Frame(0x44, 1, 1024, bytes.Repeat([]byte{0xAA}, maxFrameData+1))
}
