// SPDX-License-Identifier: MIT

package knx

import (
	"testing"
	"unicode/utf8"

	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// fuzzSeeds are DESCRIPTION_RESPONSEs captured from the reference servers
// and synthetic edge cases.
func fuzzSeeds() [][]byte {
	return [][]byte{
		unhex(calimeroResp),
		unhex(knxdResp),
		frame(svcDescRes, plainInfo(), dib(dibSuppSvc, famCore, 2, famSecurity, 1), dib(dibSecuredSvc, famTunnelling, 1),
			dib(dibTunnelInfo, 0, 254, 0x11, 0x0A, 0, 5), dib(dibExtDevInfo, 1, 0, 0, 254, 0x09, 0x1A), dib(dibMfrData, 0, 0x83)),
		frame(svcDescRes, plainInfo(), []byte{0, 2}),
		descriptionRequest(hostUDP, nil, 0),
		{},
	}
}

// FuzzDetect runs the UDP and TCP fingerprinters end to end against a
// server replying with fuzzed bytes, seeded with replies captured from
// reference servers, and checks the Fingerprinter contract on every result
// (see fuzzkit).
func FuzzDetect(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(fuzzkit.Join(s, s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzkit.Detect(t, New(), data)
		fuzzkit.Detect(t, NewTCP(), data)
	})
}

// FuzzDecode runs the DESCRIPTION_RESPONSE parser on arbitrary bytes: it
// must not panic, and what it accepts must be a well-formed response.
func FuzzDecode(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := parse(data)
		if err != nil {
			return
		}
		if len(data) < headerLen+deviceInfoLen+2 || data[headerLen] != deviceInfoLen || data[headerLen+1] != dibDeviceInfo {
			t.Fatalf("accepted a response without a DEVICE_INFO DIB: %x", data)
		}
		if d.families == nil {
			t.Fatal("accepted a response without service families")
		}
		for _, s := range []string{d.name, d.familyList(), d.variant(), d.familySig()} {
			if !utf8.ValidString(s) {
				t.Fatalf("invalid UTF-8 %q", s)
			}
		}
		for _, r := range d.name {
			if r < 0x20 || (r >= 0x7F && r <= 0x9F) {
				t.Fatalf("control character in name %q", d.name)
			}
		}
	})
}
