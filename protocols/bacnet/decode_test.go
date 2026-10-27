// SPDX-License-Identifier: MIT

package bacnet

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

func bv(fn byte, rest string) []byte {
	body := unhex(strings.ReplaceAll(rest, " ", ""))
	return bvlc(fn, body)
}

// Every BVLC/NPDU/APDU shape parse must accept or reject.
func TestParseShapes(t *testing.T) {
	ok := map[string][]byte{
		"result":          unhex("810000060000"),
		"forwarded":       bv(0x04, "c0a80001bac0 0100 300c0c"),
		"routed dst+src":  bv(bvlcUnicastNPDU, "01 28 0001 01 07 ff 0002 01 05 300c0c"),
		"simple ack":      bv(bvlcUnicastNPDU, "0100 2001 0f"),
		"unconfirmed iam": bv(bvlcBroadcastNPDU, "0100 1000 c4020004d2"),
		"error":           bv(bvlcUnicastNPDU, "0100 50010c"),
	}
	for name, dg := range ok {
		if _, err := parse(dg); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string][]byte{
		"not bvlc":         []byte("hello world"),
		"length":           unhex("810a0009010030"),
		"short forwarded":  bv(0x04, "c0a8"),
		"other function":   bv(0x05, "0100"),
		"npdu version":     bv(bvlcUnicastNPDU, "0200 30"),
		"network message":  bv(bvlcUnicastNPDU, "0180 00"),
		"truncated dadr":   bv(bvlcUnicastNPDU, "0120 0001"),
		"missing hops":     bv(bvlcUnicastNPDU, "0120 000101 07"),
		"truncated sadr":   bv(bvlcUnicastNPDU, "0108 0002 09 01"),
		"empty apdu":       bv(bvlcUnicastNPDU, "0100"),
		"short complexack": bv(bvlcUnicastNPDU, "0100 3001"),
		"short unconf":     bv(bvlcUnicastNPDU, "0100 10"),
		"short error":      bv(bvlcUnicastNPDU, "0100 50"),
		"short simple ack": bv(bvlcUnicastNPDU, "0100 2001"),
		"request":          bv(bvlcUnicastNPDU, "0100 0005010c"),
	}
	for name, dg := range bad {
		if _, err := parse(dg); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if skip, ok := skipAddr([]byte{0, 1}); ok || skip != nil {
		t.Error("skipAddr short")
	}
}

// Every prefix of every captured reply goes through the decoders: no panic,
// and every early return is exercised.
func TestTruncationSweep(t *testing.T) {
	for _, h := range frames {
		full := unhex(h)
		for i := 0; i <= len(full); i++ {
			dg := full[:i]
			a, err := parse(dg)
			_, _, _ = parseIAm(dg)
			if err == nil {
				_, _ = readPropertyDeviceInstance(a)
				_, _, _ = readPropertyValue(a)
				_ = propertyOf(a)
			}
			_, _, _ = appTag(dg)
			_, _ = tagLen(dg)
			_, _, _, _ = firstContextTag(dg, 1)
		}
	}
}

func TestTagHelpers(t *testing.T) {
	// Extended length (5 = length in the next octet).
	ext := append([]byte{0x1D, 3}, 'a', 'b', 'c')
	if tag, val, rest, ok := firstContextTag(ext, 1); !ok || tag != 1 || string(val) != "abc" || len(rest) != 0 {
		t.Fatalf("extended context tag: %v %q %v", tag, val, ok)
	}
	if _, _, _, ok := firstContextTag(append([]byte{0x0D, 3}, 'x', 'y', 'z', 0x19, 0x4B), 1); !ok {
		t.Fatal("skip an extended tag to the wanted one")
	}
	for _, b := range [][]byte{{0x1D}, {0x1D, 9, 1}, {0x19}, {0x22, 1}} {
		if _, _, _, ok := firstContextTag(b, 1); ok {
			t.Errorf("% x accepted", b)
		}
	}
	if n, ok := tagLen([]byte{0x3E}); !ok || n != 1 {
		t.Fatal("opening tag")
	}
	if n, ok := tagLen([]byte{0x75, 2, 0, 'x'}); !ok || n != 4 {
		t.Fatalf("extended tagLen %d", n)
	}
	for _, b := range [][]byte{nil, {0x75}, {0x75, 9}, {0x24, 1}} {
		if _, ok := tagLen(b); ok {
			t.Errorf("tagLen % x", b)
		}
	}
	if n, ok := unsignedTag([]byte{1, 0}); !ok || n != 256 {
		t.Fatal("unsigned")
	}
	if _, ok := unsignedTag(nil); ok {
		t.Fatal("empty unsigned")
	}
	if charString([]byte{0}) != "" || charString([]byte{0, 'o', 'k'}) != "ok" {
		t.Fatal("charString")
	}
	for v, want := range map[uint32]string{0x12: "1912", 0x1234: "1a1234", 0x123456: "1b123456", 0x12345678: "1c12345678"} {
		if got := hex.EncodeToString(contextUnsigned(1, v)); got != want {
			t.Errorf("contextUnsigned(%#x) = %s, want %s", v, got, want)
		}
	}
	for k, want := range map[byte]string{apduComplexACK: "ComplexACK", apduSimpleACK: "SimpleACK", apduError: "Error", 0x90: "APDU 0x90"} {
		if apduName(k) != want {
			t.Errorf("apduName(%#x)", k)
		}
	}
	if propertyOf(apdu{}) != 0xFFFFFFFF {
		t.Fatal("propertyOf without tag 1")
	}
}

// Replies the judge scores below "certain".
func TestJudgeBranches(t *testing.T) {
	for name, c := range map[string]struct {
		dg   []byte
		conf core.Confidence
	}{
		"simple ack":  {bv(bvlcUnicastNPDU, "0100 2001 0c"), core.ConfidenceHigh},
		"bvlc result": {unhex("810000060030"), core.ConfidenceHigh},
	} {
		t.Run(name, func(t *testing.T) {
			target := testsrv.UDP(t, testsrv.Script(c.dg))
			r, err := New().Detect(context.Background(), target, core.Options{})
			if err != nil || r.Confidence != c.conf {
				t.Fatalf("%v %v", r, err)
			}
		})
	}
	// Our own Who-Is reflected back (a broadcast loop) is ignored.
	target := testsrv.UDP(t, func(req []byte) ([]byte, bool) { return req, false })
	target.Timeout = 200_000_000
	if r, _ := New().Detect(context.Background(), target, core.Options{}); r.Matched {
		t.Fatalf("matched its own echo: %v", r)
	}
	// A host that cannot be resolved fails at dial.
	if _, err := New().Detect(context.Background(), core.Target{Host: "nonexistent.invalid", Port: 47808, Network: core.UDP, Timeout: 200_000_000}, core.Options{}); err == nil {
		t.Fatal("dial of an unresolvable host should fail")
	}
}

func TestIAmVariants(t *testing.T) {
	// Without the vendor field: instance only.
	if inst, vendor, ok := parseIAm(unhex("1000c4020004d2")); !ok || inst != 1234 || vendor != 0 {
		t.Fatalf("%d %d %v", inst, vendor, ok)
	}
	if _, _, ok := parseIAm(unhex("1000c402")); ok {
		t.Fatal("short object id accepted")
	}
	if _, _, ok := parseIAm(unhex("1001c4020004d2")); ok {
		t.Fatal("not I-Am accepted")
	}
}
