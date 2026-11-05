// SPDX-License-Identifier: MIT

package bacnet

import "testing"

// A five-octet vendor identifier used to be truncated to its low 32 bits,
// reporting vendor 5 for 0x0100000005.
func TestIAmVendorNotTruncated(t *testing.T) {
	inst, vendor, ok := parseIAm(unhex("1000c4020004d2" + "2105" + "9100" + "250100000005"))
	if !ok || inst != 1234 || vendor != 0 {
		t.Fatalf("instance %d vendor %d ok %v", inst, vendor, ok)
	}
	if _, vendor, _ := parseIAm(unhex("1000c4020004d2" + "2105" + "9100" + "24ffffffff")); vendor != 0xFFFFFFFF {
		t.Fatalf("32-bit vendor %d", vendor)
	}
}

func TestContextUnsignedWidths(t *testing.T) {
	for v, want := range map[uint32]string{
		0: "1900", 0xFF: "19ff", 0x100: "1a0100", 0xFFFF: "1affff",
		0x10000: "1b010000", 0xFFFFFF: "1bffffff", 0x1000000: "1c01000000", 0xFFFFFFFF: "1cffffffff",
	} {
		if got := contextUnsigned(1, v); string(got) != string(unhex(want)) {
			t.Errorf("%#x: % x, want %s", v, got, want)
		}
	}
}
