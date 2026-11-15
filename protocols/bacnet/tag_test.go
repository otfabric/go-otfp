// SPDX-License-Identifier: MIT

package bacnet

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// longName answers like the captured device, with an object name of n
// characters in the form its length needs.
func longName(n int) testsrv.Handler {
	name := strings.Repeat("N", n)
	return func(req []byte) ([]byte, bool) {
		if stripInvoke(req) != "810a001101040005020c0c020004d2194d" { // ReadProperty of Object_Name
			return device()(req)
		}
		value := append([]byte{0x00}, name...) // character set 0, then the text
		var tag []byte
		switch {
		case len(value) <= 4:
			tag = []byte{0x70 | byte(len(value))}
		case len(value) <= 253:
			tag = []byte{0x75, byte(len(value))}
		case len(value) <= 65535:
			tag = binary.BigEndian.AppendUint16([]byte{0x75, 254}, uint16(len(value)))
		}
		apdu := []byte{0x30, req[8], 0x0C, 0x0C, 0x02, 0x00, 0x04, 0xD2, 0x19, 0x4D, 0x3E}
		apdu = append(append(append(apdu, tag...), value...), 0x3F)
		return bvlc(bvlcUnicastNPDU, append([]byte{npduVersion, 0x00}, apdu...)), false
	}
}

// An object name is read whole in every form of its length: within the
// initial octet, with a length octet, and with a length of two octets.
func TestObjectNameLengthForms(t *testing.T) {
	for _, n := range []int{1, 3, 4, 252, 253, 300, 500} {
		target := testsrv.UDP(t, longName(n))
		r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
		fuzzkit.Check(t, proto, r, err)
		if err != nil || !r.Matched || r.Identity == nil {
			t.Fatalf("name of %d characters: %v %v", n, r, err)
		}
		if got := r.Identity.Name; got != strings.Repeat("N", n) {
			t.Errorf("name of %d characters: %d characters decoded, starting %.12q", n, len(got), got)
		}
		if r.Identity.Vendor != "BACnet Stack at SourceForge" {
			t.Errorf("name of %d characters: vendor %q", n, r.Identity.Vendor)
		}
	}
}

// An I-Am whose vendor identifier uses a length octet is decoded like one
// that does not.
func TestIAmVendorWithLengthOctet(t *testing.T) {
	// device 1234, max APDU 1476 (22 05 c4), segmentation 3 (91 03), vendor 260.
	short := unhex("1000c4020004d2" + "2205c4" + "9103" + "220104")
	long := unhex("1000c4020004d2" + "2205c4" + "9103" + "25020104")
	for name, apdu := range map[string][]byte{"length in the initial octet": short, "length octet": long} {
		if inst, vendor, ok := parseIAm(apdu); !ok || inst != 1234 || vendor != 260 {
			t.Errorf("%s: instance %d, vendor %d, %v; want 1234, 260", name, inst, vendor, ok)
		}
	}
	// A vendor identifier wider than 32 bits is not reported.
	wide := unhex("1000c4020004d2" + "2205c4" + "9103" + "2505" + "0100000000")
	if _, vendor, ok := parseIAm(wide); !ok || vendor != 0 {
		t.Errorf("vendor of five octets: %d, %v; want none", vendor, ok)
	}
}
