// SPDX-License-Identifier: MIT

package enip

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

func TestIdentityItemErrors(t *testing.T) {
	item := func(typ uint16, body []byte) []byte {
		b := binary.LittleEndian.AppendUint16(nil, 1)
		b = binary.LittleEndian.AppendUint16(b, typ)
		b = binary.LittleEndian.AppendUint16(b, uint16(len(body)))
		return append(b, body...)
	}
	long := make([]byte, 2+16+15)
	long[2+16+14] = 200 // product name longer than the item
	for name, body := range map[string][]byte{
		"empty":     nil,
		"no items":  {0, 0},
		"truncated": {1, 0, 0x0c},
		"other":     item(0x0001, make([]byte, 40)),
		"overrun":   append(binary.LittleEndian.AppendUint16(binary.LittleEndian.AppendUint16([]byte{1, 0}, 0x0c), 99), 1),
		"short":     item(itemCIPIdentity, make([]byte, 10)),
		"name":      item(itemCIPIdentity, long),
	} {
		if _, err := parseIdentityItem(body); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if framer(make([]byte, 24)) != 24 {
		t.Fatal("framer")
	}
	h := make([]byte, 24)
	binary.LittleEndian.PutUint16(h[2:], 0xFFF0)
	if framer(h) != -1 {
		t.Fatal("framer oversized")
	}
}

func TestIdentityFlags(t *testing.T) {
	body := unhex(openerBody)
	body[2+4+18+6] |= 0x80                                 // major revision with the compatibility bit
	binary.LittleEndian.PutUint16(body[2+4+18+8:], 0x0060) // status word
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) {
		var ctx [8]byte
		copy(ctx[:], req[12:20])
		if binary.LittleEndian.Uint16(req) == cmdListIdentity {
			return encap(cmdListIdentity, 0, ctx, body), false
		}
		return nil, true // RegisterSession refused by closing
	})
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
	if err != nil || !r.Matched || r.Identity.Attributes["revisionCompatibility"] != "set" || r.Identity.Attributes["status"] != "0x0060" {
		t.Fatalf("%v %v %+v", r, err, r.Identity)
	}
	// A valid encapsulation whose item does not decode: high, not certain.
	bad := testsrv.TCP(t, func(req []byte) ([]byte, bool) {
		var ctx [8]byte
		copy(ctx[:], req[12:20])
		return encap(cmdListIdentity, 0, ctx, []byte{0, 0}), false
	})
	if r, _ := New().Detect(context.Background(), bad, core.Options{}); r.Confidence != core.ConfidenceHigh {
		t.Fatalf("%v", r)
	}
	if _, err := New().Detect(context.Background(), testsrv.Closed(t), core.Options{}); err == nil {
		t.Fatal("closed")
	}
	silent := testsrv.TCP(t, testsrv.Script())
	silent.Timeout = 200 * time.Millisecond
	if _, err := New().Detect(context.Background(), silent, core.Options{}); err == nil {
		t.Fatal("silent")
	}
}
