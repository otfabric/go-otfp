// SPDX-License-Identifier: MIT

package dnp3

import (
	"bytes"
	"testing"
)

// An unsigned device attribute (data type 2, least significant octet
// first) is rendered when it fits 64 bits; a longer one is not rendered.
func TestUnsignedAttributeBoundaries(t *testing.T) {
	cases := []struct {
		name string
		v    []byte
		want string
	}{
		{"no octets", nil, "0"},
		{"one octet", []byte{0xFF}, "255"},
		{"two octets", []byte{0x00, 0x01}, "256"},
		{"four octets", []byte{0xFF, 0xFF, 0xFF, 0xFF}, "4294967295"},
		{"seven octets", []byte{0, 0, 0, 0, 0, 0, 1}, "281474976710656"},
		{"eight octets, the largest value", bytes.Repeat([]byte{0xFF}, 8), "18446744073709551615"},
		{"nine octets", []byte{0, 0, 0, 0, 0, 0, 0, 0, 1}, ""},
		{"nine octets of zero", make([]byte, 9), ""},
		{"255 octets", bytes.Repeat([]byte{0x01}, 255), ""},
	}
	for _, tc := range cases {
		if got := attrString(2, tc.v); got != tc.want {
			t.Errorf("%s: attrString(2, % x) = %q, want %q", tc.name, tc.v, got, tc.want)
		}
	}

	// In a response the attribute that does not fit is left out and the
	// others are kept.
	obj := func(variation byte, typ byte, v []byte) []byte {
		return append([]byte{0x00, variation, 0x00, 0, 0, typ, byte(len(v))}, v...)
	}
	apdu := []byte{0xC0, 0x81, 0, 0}
	apdu = append(apdu, obj(252, 1, []byte("Vendor"))...)
	apdu = append(apdu, obj(240, 2, []byte{0, 0, 0, 0, 0, 0, 0, 0, 1})...)
	apdu = append(apdu, obj(241, 2, []byte{0x10, 0x27})...)
	attrs, err := ParseAttributes(apdu)
	if err != nil {
		t.Fatal(err)
	}
	if _, has := attrs[240]; has || attrs[252] != "Vendor" || attrs[241] != "10000" || len(attrs) != 2 {
		t.Errorf("attributes %v, want the visible string and the two-octet value", attrs)
	}
}
