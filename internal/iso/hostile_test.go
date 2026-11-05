// SPDX-License-Identifier: MIT

package iso

import "testing"

// Malformed connection confirms and data TPDUs are rejected, not misread.
func TestMalformedTPDUs(t *testing.T) {
	// A CC whose length indicator is too short for the fixed part.
	if _, err := ParseConfirm(TPKT([]byte{0x05, TPDUConnectConfirm, 0, 1, 0, 1})); err == nil {
		t.Fatal("short CC accepted")
	}
	// A CC whose last parameter claims more octets than the TPDU holds.
	if _, err := ParseConfirm(TPKT([]byte{0x09, TPDUConnectConfirm, 0, 1, 0, 1, 0, 0xC0, 0x05, 0x0A})); err == nil {
		t.Fatal("overrunning parameter accepted")
	}
	// A DT TPDU with a length indicator of 1 has no EOT octet.
	if _, ok := Payload(TPKT([]byte{0x01, TPDUData, 0x80, 0x32})); ok {
		t.Fatal("DT without EOT accepted")
	}
}
