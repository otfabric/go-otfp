// SPDX-License-Identifier: MIT

package profinet

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// reply builds a DCE/RPC v4 reply of type typ with body, echoing the
// probe's activity.
func reply(typ byte, body []byte) testsrv.Handler {
	return func(req []byte) ([]byte, bool) {
		h := make([]byte, headerLen)
		h[0], h[1], h[4] = rpcVersion, typ, drepLittle
		copy(h[40:56], req[40:56])
		binary.LittleEndian.PutUint16(h[74:], uint16(len(body)))
		return append(h, body...), false
	}
}

func ndr(status uint32, blocks []byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, status)
	for _, v := range []uint32{uint32(len(blocks)), 16696, 0, uint32(len(blocks))} {
		b = binary.LittleEndian.AppendUint32(b, v)
	}
	return append(b, blocks...)
}

func TestReplyKinds(t *testing.T) {
	cases := map[string]struct {
		h    testsrv.Handler
		conf core.Confidence
		mode core.Mode
	}{
		"ping":       {reply(typePing, nil), core.ConfidenceHigh, core.ModeDetect},
		"pnio error": {reply(typeResponse, ndr(0xDE80B000, nil)), core.ConfidenceCertain, core.ModeIdentify},
		"short ndr":  {reply(typeResponse, []byte{0, 0}), core.ConfidenceCertain, core.ModeIdentify},
		"no im0":     {reply(typeResponse, ndr(0, []byte{0x00, 0x21, 0x00, 0x02, 0x01, 0x00})), core.ConfidenceCertain, core.ModeIdentify},
		"rpc v5":     {func([]byte) ([]byte, bool) { return append([]byte{4}, make([]byte, 20)...), false }, core.ConfidenceLow, core.ModeDetect},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			target := testsrv.UDP(t, c.h)
			target.Timeout = 300 * time.Millisecond
			r, _ := New().Detect(context.Background(), target, core.Options{Mode: c.mode})
			if r.Confidence != c.conf || r.Identity != nil {
				t.Fatalf("%v %+v", r, r.Identity)
			}
		})
	}
	// Silence after a reply that was not ours: no answer, no error kept.
	if _, err := New().Detect(context.Background(), core.Target{Host: "nonexistent.invalid", Port: 34964, Network: core.UDP, Timeout: time.Second}, core.Options{}); err == nil {
		t.Fatal("unresolvable host")
	}
}

func TestDecoders(t *testing.T) {
	if _, _, err := parseHeader(append([]byte{5}, make([]byte, 79)...)); err == nil {
		t.Fatal("RPC version 5")
	}
	h := make([]byte, headerLen)
	h[0], h[4] = rpcVersion, drepLittle
	binary.LittleEndian.PutUint16(h[74:], 50)
	if _, _, err := parseHeader(h); err == nil {
		t.Fatal("body length overruns")
	}
	// Big-endian drep.
	h[4] = 0
	binary.BigEndian.PutUint16(h[74:], 0)
	if _, _, err := parseHeader(h); err != nil {
		t.Fatalf("big-endian header: %v", err)
	}
	// An actual count larger than the blocks is cut to what arrived.
	if b, err := ndrBlocks(ndr(0, []byte{1, 2})[:22]); err != nil || len(b) != 2 {
		t.Fatalf("%v %v", b, err)
	}
	for _, blocks := range [][]byte{{0x00, 0x20, 0x00, 0x50}, {0x00, 0x20, 0x00, 0x02, 0x01, 0x00}} {
		if _, ok := findIM0(blocks); ok {
			t.Errorf("% x decoded", blocks)
		}
	}
	// An I&M0 with a non-printable prefix and a profile ID.
	body := []byte{0x01, 0x00, 0xF0, 0x00}
	body = append(body, make([]byte, 36)...)
	body = append(body, 0, 1, 0x00, 2, 3, 4, 0, 0, 0xF6, 0x00)
	im, ok := decodeIM0(body)
	if !ok || im.software != "V2.3.4" || im.profileID != 0xF600 {
		t.Fatalf("%+v %v", im, ok)
	}
	for c, want := range map[byte]byte{'A': 10, 'f': 15, '7': 7, 'z': 0} {
		if fromHex(c) != want {
			t.Errorf("fromHex(%c)", c)
		}
	}
	for typ, want := range map[byte]string{typeRequest: "request", typePing: "ping", 9: "type 9"} {
		if rpcTypeName(typ) != want {
			t.Errorf("rpcTypeName(%d)", typ)
		}
	}
}
