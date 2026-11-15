// SPDX-License-Identifier: MIT

package bacnet

import (
	"bytes"
	"testing"

	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// A tag is decoded with the extended forms of ASHRAE 135 clause 20.2.1: a
// tag number octet after the number 15, a length octet after the length 5,
// and a length of two or four octets after the length octets 254 and 255.
// Every length is within what follows the tag.
func TestTagBoundaries(t *testing.T) {
	data := func(head []byte, n int) []byte { return append(head, bytes.Repeat([]byte{'x'}, n)...) }
	type want struct {
		number       byte
		context      bool
		size, length int
	}
	ok := []struct {
		name string
		p    []byte
		want want
	}{
		{"application tag 7, length 0", []byte{0x70}, want{7, false, 1, 0}},
		{"application tag 7, length 1", data([]byte{0x71}, 1), want{7, false, 1, 1}},
		{"application tag 7, length 4", data([]byte{0x74}, 4), want{7, false, 1, 4}},
		{"context tag 2, length 4", data([]byte{0x2C}, 4), want{2, true, 1, 4}},
		{"tag 14 in the initial octet", data([]byte{0xE9}, 1), want{14, true, 1, 1}},
		{"extended tag number 15", data([]byte{0xF9, 15}, 1), want{15, true, 2, 1}},
		{"extended tag number 254", data([]byte{0xF9, 254}, 1), want{254, true, 2, 1}},
		{"extended application tag number 20", data([]byte{0xF2, 20}, 2), want{20, false, 2, 2}},
		{"length octet 5", data([]byte{0x75, 5}, 5), want{7, false, 2, 5}},
		{"length octet 253", data([]byte{0x75, 253}, 253), want{7, false, 2, 253}},
		{"two-octet length 254", data([]byte{0x75, 254, 0x00, 0xFE}, 254), want{7, false, 4, 254}},
		{"two-octet length 301", data([]byte{0x75, 254, 0x01, 0x2D}, 301), want{7, false, 4, 301}},
		{"two-octet length 65535", data([]byte{0x75, 254, 0xFF, 0xFF}, 65535), want{7, false, 4, 65535}},
		{"four-octet length 255", data([]byte{0x75, 255, 0, 0, 0, 0xFF}, 255), want{7, false, 6, 255}},
		{"four-octet length 65536", data([]byte{0x75, 255, 0, 1, 0, 0}, 65536), want{7, false, 6, 65536}},
		{"extended tag number and two-octet length", data([]byte{0xFD, 40, 254, 0x01, 0x00}, 256), want{40, true, 5, 256}},
		{"more follows the contents", data([]byte{0x75, 3}, 10), want{7, false, 2, 3}},
	}
	for _, tc := range ok {
		h, good := parseTag(tc.p)
		got := want{h.number, h.context, h.size, h.length}
		if !good || got != tc.want || h.opening || h.closing {
			t.Errorf("%s: parseTag = %+v, %v; want %+v", tc.name, h, good, tc.want)
		}
	}
	for name, p := range map[string][]byte{
		"opening tag 3":                   {0x3E},
		"closing tag 3":                   {0x3F},
		"opening tag, extended number 20": {0xFE, 20},
		"closing tag, extended number 20": {0xFF, 20},
	} {
		h, good := parseTag(p)
		if !good || h.opening == h.closing || h.length != 0 || h.size != len(p) || !h.context {
			t.Errorf("%s: parseTag = %+v, %v", name, h, good)
		}
	}
	bad := map[string][]byte{
		"empty":                               nil,
		"length 1, contents missing":          {0x71},
		"length 4, three octets present":      data([]byte{0x74}, 3),
		"extended tag number missing":         {0xF9},
		"extended tag number 255":             data([]byte{0xF9, 255}, 1),
		"length octet missing":                {0x75},
		"length octet 5, four octets present": data([]byte{0x75, 5}, 4),
		"two-octet length cut short":          {0x75, 254, 0x01},
		"two-octet length 301, 300 present":   data([]byte{0x75, 254, 0x01, 0x2D}, 300),
		"four-octet length cut short":         {0x75, 255, 0, 0, 1},
		"four-octet length 301, 300 present":  data([]byte{0x75, 255, 0, 0, 0x01, 0x2D}, 300),
		"four-octet length 2^31-1":            data([]byte{0x75, 255, 0x7F, 0xFF, 0xFF, 0xFF}, 64),
		"four-octet length 2^31":              data([]byte{0x75, 255, 0x80, 0x00, 0x00, 0x00}, 64),
		"four-octet length 2^32-1":            data([]byte{0x75, 255, 0xFF, 0xFF, 0xFF, 0xFF}, 64),
	}
	for name, p := range bad {
		if h, good := parseTag(p); good {
			t.Errorf("%s: parseTag = %+v, want it refused", name, h)
		}
		if _, _, good := appTag(p); good {
			t.Errorf("%s: appTag accepted", name)
		}
		if _, good := tagLen(p); good {
			t.Errorf("%s: tagLen accepted", name)
		}
	}
	// A length that is refused is not allocated.
	huge := data([]byte{0x75, 255, 0xFF, 0xFF, 0xFF, 0xFF}, 64)
	if n := fuzzkit.Allocated(func() {
		for range 100 {
			_, _, _ = appTag(huge)
		}
	}) / 100; n > 1024 {
		t.Errorf("%d octets allocated for a tag that declares 4 GiB, budget 1024", n)
	}
}
