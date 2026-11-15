// SPDX-License-Identifier: MIT

package mms

import (
	"bytes"
	"context"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// A BER INTEGER is two's complement and belongs to a declared type: its
// value is decoded with its sign, and contents that are not a value of the
// type are not a value at all.
func TestIntegerBoundaries(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
		bits uint
		want int64
		ok   bool
	}{
		{"empty", nil, 16, 0, false},
		{"zero", []byte{0x00}, 16, 0, true},
		{"one", []byte{0x01}, 16, 1, true},
		{"largest Integer8", []byte{0x7F}, 8, 127, true},
		{"smallest Integer8", []byte{0x80}, 8, -128, true},
		{"minus one in one octet", []byte{0xFF}, 8, -1, true},
		{"one above the largest Integer8", []byte{0x00, 0x80}, 8, 0, false},
		{"one below the smallest Integer8", []byte{0xFF, 0x7F}, 8, 0, false},
		{"128 as an Integer16", []byte{0x00, 0x80}, 16, 128, true},
		{"minus one in two octets", []byte{0xFF, 0xFF}, 16, -1, true},
		{"largest Integer16", []byte{0x7F, 0xFF}, 16, 32767, true},
		{"smallest Integer16", []byte{0x80, 0x00}, 16, -32768, true},
		{"one above the largest Integer16", []byte{0x00, 0x80, 0x00}, 16, 0, false},
		{"one below the smallest Integer16", []byte{0xFF, 0x7F, 0xFF}, 16, 0, false},
		{"65000 as an Integer32", []byte{0x00, 0xFD, 0xE8}, 32, 65000, true},
		{"largest Integer32", []byte{0x7F, 0xFF, 0xFF, 0xFF}, 32, 1<<31 - 1, true},
		{"smallest Integer32", []byte{0x80, 0x00, 0x00, 0x00}, 32, -1 << 31, true},
		{"one above the largest Integer32", []byte{0x00, 0x80, 0x00, 0x00, 0x00}, 32, 0, false},
		{"one below the smallest Integer32", []byte{0xFF, 0x7F, 0xFF, 0xFF, 0xFF}, 32, 0, false},
		{"eight octets that repeat the sign of 5", []byte{0, 0, 0, 0, 0, 0, 0, 5}, 16, 5, true},
		{"eight octets that repeat the sign of -2", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE}, 16, -2, true},
		{"eight octets, the largest value", []byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 32, 0, false},
		{"nine octets of zero", make([]byte, 9), 32, 0, false},
		{"nine octets", []byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0}, 32, 0, false},
		{"sixteen octets", bytes.Repeat([]byte{0xFF}, 16), 32, 0, false},
	}
	for _, tc := range cases {
		if got, ok := integer(tc.b, tc.bits); got != tc.want || ok != tc.ok {
			t.Errorf("%s: integer(% x, %d) = %d, %v; want %d, %v", tc.name, tc.b, tc.bits, got, ok, tc.want, tc.ok)
		}
	}
}

// The integers of the Initiate-Response reach the fingerprint as the values
// the server sent; a field that is not a value of its type is left out of
// the metadata and of the signature.
func TestInitiateResponseIntegers(t *testing.T) {
	// The captured accept carries localDetailCalled 65000 (80 03 00 fd e8),
	// both negotiatedMaxServOutstanding 5 (81 01 05, 82 01 05) and version 1
	// (a4 16 80 01 01). Each case replaces contents of the same length.
	replace := func(old, new string) []byte {
		o, n := unhex(old), unhex(new)
		if len(o) != len(n) || bytes.Count(goMMSAccept, o) != 1 {
			t.Fatalf("replacement %q -> %q", old, new)
		}
		return bytes.Replace(goMMSAccept, o, n, 1)
	}
	cases := []struct {
		name   string
		accept []byte
		meta   map[string]string // "" means absent
		sig    string
	}{
		{"as captured", goMMSAccept,
			map[string]string{"localDetailCalled": "65000", "maxServOutstandingCalling": "5", "maxServOutstandingCalled": "5", "version": "1"},
			"session=accept;initiate=response;v=1"},
		{"negative Integer32", replace("80 03 00 fd e8", "80 03 ff ff fe"),
			map[string]string{"localDetailCalled": "-2"}, "session=accept;initiate=response;v=1"},
		{"largest three-octet value", replace("80 03 00 fd e8", "80 03 7f ff ff"),
			map[string]string{"localDetailCalled": "8388607"}, "session=accept;initiate=response;v=1"},
		{"negative Integer16", replace("81 01 05 82 01 05", "81 01 ff 82 01 80"),
			map[string]string{"maxServOutstandingCalling": "-1", "maxServOutstandingCalled": "-128"}, "session=accept;initiate=response;v=1"},
		{"version 127", replace("a4 16 80 01 01", "a4 16 80 01 7f"),
			map[string]string{"version": "127"}, "session=accept;initiate=response;v=127"},
		{"negative version", replace("a4 16 80 01 01", "a4 16 80 01 ff"),
			map[string]string{"version": "-1"}, "session=accept;initiate=response;v=-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := testsrv.TCP(t, testsrv.Script(goMMSConfirm, tc.accept, goMMSConclude))
			r, err := New().Detect(context.Background(), target, core.Options{})
			fuzzkit.Check(t, proto, r, err)
			if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain {
				t.Fatalf("%v %v", r, err)
			}
			for k, want := range tc.meta {
				if got := r.Fingerprint.Metadata[k]; got != want {
					t.Errorf("metadata %s = %q, want %q", k, got, want)
				}
			}
			if r.Fingerprint.Signature != tc.sig {
				t.Errorf("signature %q, want %q", r.Fingerprint.Signature, tc.sig)
			}
		})
	}

	// Contents longer than the type, built into a response of their own:
	// the field is absent from the result.
	initiateResponse := func(version []byte) []byte {
		detail := tlv(0xa4, tlv(0x80, version))
		ir := tlv(tagInitiateResponse, append(tlv(0x80, make([]byte, 9)), append(tlv(0x81, []byte{0, 0, 0, 0, 0, 0, 0, 0, 5}), detail...)...))
		aare := tlv(0x61, append(tlv(0xa2, []byte{0x02, 0x01, 0x00}), ir...))
		return append([]byte{spduAccept, byte(2 + len(aare)), 0xc1, byte(len(aare))}, aare...)
	}
	for name, version := range map[string][]byte{
		"nine octets":                   {0, 0, 0, 0, 0, 0, 0, 0, 1},
		"three octets beyond Integer16": {0x01, 0x00, 0x00},
	} {
		b := fpx.New(proto)
		if !New().judgeAssociation(b, initiateResponse(version)) {
			t.Fatalf("%s: the association is not accepted", name)
		}
		r := b.Result("mms.initiate", "MMS server", nil)
		if _, has := r.Fingerprint.Metadata["version"]; has || r.Fingerprint.Signature != "session=accept;initiate=response" {
			t.Errorf("%s: metadata %v, signature %q; want no version", name, r.Fingerprint.Metadata, r.Fingerprint.Signature)
		}
		if _, has := r.Fingerprint.Metadata["localDetailCalled"]; has {
			t.Errorf("%s: localDetailCalled of nine octets is in the metadata: %v", name, r.Fingerprint.Metadata)
		}
		if _, has := r.Fingerprint.Metadata["maxServOutstandingCalling"]; has {
			t.Errorf("%s: maxServOutstandingCalling of nine octets is in the metadata: %v", name, r.Fingerprint.Metadata)
		}
	}
}
