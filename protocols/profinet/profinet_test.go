// SPDX-License-Identifier: MIT

package profinet

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// A ReadImplicit response of the go-profinet device (vendor 0xF000, order
// "OTF-DEV-1", serial "0001", software V1.0.0), with a placeholder activity
// UUID that the handler rewrites to echo the probe.
const im0Response = "0402000010000000000000000000000000000000000000000100a0de976cd111827100a02442df7d5fd5b9e64df034536c14766ecf1d7c2fbdf5df6a01000000000000000500ffffffff900000000000000000007c00000038410000000000007c0000008009003c010000000000000000000000000000000000000000000000000000010000aff00000003c000000000000000000000000000000000000000000000000002000380100f0004f54462d4445562d312020202020202020202020303030312020202020202020202020200001560100000000000000000101001e"

// echoActivity returns resp with the probe's activity UUID (bytes 40..56)
// copied in, as a real device echoes it.
func echoActivity(resp []byte) testsrv.Handler {
	return func(req []byte) ([]byte, bool) {
		out := append([]byte(nil), resp...)
		if len(req) >= 56 && len(out) >= 56 {
			copy(out[40:56], req[40:56])
		}
		return out, false
	}
}

func TestDetectIdentify(t *testing.T) {
	target := testsrv.UDP(t, echoActivity(unhex(im0Response)))
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify, Trace: true})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v %v", r, err)
	}
	id := r.Identity
	if id.VendorID != "0xF000" || id.Product != "OTF-DEV-1" || id.Serial != "0001" || id.Version != "V1.0.0" ||
		id.Attributes["hardwareRevision"] != "1" {
		t.Fatalf("identity %+v", id)
	}
	if r.Fingerprint.Signature != "type=response" {
		t.Fatalf("signature %q", r.Fingerprint.Signature)
	}
}

func TestProbeIsReadImplicit(t *testing.T) {
	var act uuidT
	for i := range act {
		act[i] = byte(i + 1)
	}
	p := readImplicit(act, indexIM0)
	h, body, err := parseHeader(p)
	if err != nil {
		// parseHeader rejects a request? No: it parses any v4 header.
		t.Fatalf("parse: %v", err)
	}
	if p[0] != rpcVersion || p[1] != typeRequest || h.opnum != opReadImplicit || h.activity != act {
		t.Fatalf("probe header %x", p[:8])
	}
	if len(body) == 0 {
		t.Fatal("empty NDR body")
	}
}

func TestFaultAndRejectMatch(t *testing.T) {
	base := unhex(im0Response)
	for name, typ := range map[string]byte{"fault": typeFault, "reject": typeReject, "nocall": typeNoCall} {
		t.Run(name, func(t *testing.T) {
			resp := append([]byte(nil), base[:headerLen]...)
			resp[1] = typ
			// No body for these types.
			resp[74], resp[75] = 0, 0
			target := testsrv.UDP(t, echoActivity(resp))
			r, err := New().Detect(context.Background(), target, core.Options{})
			if err != nil || !r.Matched {
				t.Fatalf("%v %v", r, err)
			}
		})
	}
}

func TestActivityNotEchoed(t *testing.T) {
	// A DCE/RPC reply for another activity is not our answer: it is
	// discarded, and with nothing else arriving the probe times out.
	resp := unhex(im0Response) // keeps its own placeholder activity
	target := testsrv.UDP(t, testsrv.Script(resp))
	target.Timeout = 300 * time.Millisecond
	r, err := New().Detect(context.Background(), target, core.Options{Trace: true})
	var te *core.TimeoutError
	if r.Matched || !errors.As(err, &te) {
		t.Fatalf("%v %v", r, err)
	}
	discarded := false
	for _, x := range r.Exchanges {
		discarded = discarded || x.Label == "discarded"
	}
	if !discarded {
		t.Fatal("the stray reply should be traced as discarded")
	}
}

func TestNotPROFINET(t *testing.T) {
	target := testsrv.UDP(t, testsrv.Script([]byte("not rpc at all")))
	target.Timeout = 300 * time.Millisecond
	r, _ := New().Detect(context.Background(), target, core.Options{})
	if r.Matched {
		t.Fatalf("%v", r)
	}
	silent := testsrv.UDP(t, testsrv.Script())
	silent.Timeout = 200 * time.Millisecond
	_, err := New().Detect(context.Background(), silent, core.Options{})
	if err == nil {
		t.Fatal("want timeout")
	}
	if New().Info().Network != core.UDP || New().Info().Ports[0] != 34964 {
		t.Fatal("info")
	}
}

func TestUUIDEncoding(t *testing.T) {
	// The device interface UUID in little-endian DCE representation.
	got := hex.EncodeToString(encodeUUIDLE(deviceInterface))
	if got != "0100a0de976cd111827100a02442df7d" {
		t.Fatalf("uuid LE %s", got)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(unhex(im0Response))
	f.Fuzz(func(t *testing.T, b []byte) {
		if h, body, err := parseHeader(b); err == nil && h.typ == typeResponse {
			if blocks, err := ndrBlocks(body); err == nil {
				_, _ = findIM0(blocks)
			}
		}
	})
}
