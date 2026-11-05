// SPDX-License-Identifier: MIT

package mms

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/iso"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// server is a stateless go-mms speaker: it answers each request by its
// kind, so it serves any number of connections.
func server() testsrv.Handler {
	identify := iso.Data(presentationData(identifyRequest))
	conclude := iso.Data(presentationData(concludeRequest))
	return func(req []byte) ([]byte, bool) {
		switch {
		case iso.TPDUType(req) == iso.TPDUConnectRequest:
			return goMMSConfirm, false
		case bytes.Equal(req, identify):
			return goMMSIdentify, false
		case bytes.Equal(req, conclude):
			return goMMSConclude, true
		}
		if user, ok := iso.Payload(req); ok && len(user) > 0 && user[0] == 0x0d {
			return goMMSAccept, false
		}
		return nil, true
	}
}

func TestChaos(t *testing.T) {
	chaos.Suite{
		FP:  New(),
		TCP: func(t testing.TB, cfg chaos.Config) core.Target { return chaos.TCP(t, cfg, server()) },
	}.Run(t)
}

// mmsPDU returns the MMS PDU (tag and contents) carried by a request's
// session user data: the Initiate-Request inside the CONNECT's AARQ, or
// the PDU of the presentation data value of a DATA TPDU.
func mmsPDU(t *testing.T, user []byte) (byte, []byte) {
	t.Helper()
	if user[0] == 0x0d { // session CONNECT
		v, ok := find(user, 0xa8)
		if !ok {
			t.Fatalf("CONNECT without an Initiate-Request: % x", user)
		}
		return 0xa8, v
	}
	if !bytes.HasPrefix(user, dataHeader) {
		t.Fatalf("session SPDU 0x%02x is neither CONNECT nor DATA", user[0])
	}
	pdv, ok := find(user[len(dataHeader):], 0x61, 0x30)
	if !ok {
		t.Fatalf("no presentation data value: % x", user)
	}
	// The PDV: presentation context identifier 3, then [0] single ASN.1
	// type holding the MMS PDU.
	_, val, rest, ok := next(pdv)
	if !ok || len(val) != 1 || val[0] != 3 {
		t.Fatalf("presentation context % x", pdv)
	}
	tag, single, _, ok := next(rest)
	if !ok || tag != 0xa0 {
		t.Fatalf("PDV encoding % x", rest)
	}
	tag, v, _, ok := next(single)
	if !ok {
		t.Fatalf("MMS PDU % x", single)
	}
	return tag, v
}

// The safety contract: COTP CR, a session CONNECT carrying the AARQ and
// an MMS Initiate-Request, the Identify service ([2], 0x82) as the only
// confirmed request, and Conclude-Request. Never Read, Write, the name
// lists, variable definitions, deletions, file services or any other.
func TestSafetyContract(t *testing.T) {
	for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
		for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
			rec := &chaos.Recorder{}
			target := testsrv.TCP(t, rec.Wrap(server()))
			r, err := New().Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: level})
			if err != nil || !r.Matched {
				t.Fatalf("%s/%s: %v %v", mode, level, r, err)
			}
			kinds := map[string]int{}
			for _, chunk := range rec.Requests() {
				for len(chunk) > 0 {
					n := iso.Framer(chunk)
					if n <= 0 || n > len(chunk) {
						t.Fatalf("not a TPKT frame: % x", chunk)
					}
					frame := chunk[:n]
					chunk = chunk[n:]
					if iso.TPDUType(frame) == iso.TPDUConnectRequest {
						kinds["cr"]++
						continue
					}
					user, ok := iso.Payload(frame)
					if !ok || len(user) == 0 {
						t.Fatalf("TPDU % x is neither a CR nor data", frame)
					}
					switch tag, v := mmsPDU(t, user); tag {
					case 0xa8:
						kinds["initiate"]++
					case 0x8b:
						kinds["conclude"]++
					case 0xa0: // confirmed-request: invokeID, then the service
						_, _, svc, ok := next(v)
						if !ok || len(svc) < 2 || svc[0] != 0x82 || svc[1] != 0 {
							t.Fatalf("%s/%s: confirmed request % x is not Identify", mode, level, v)
						}
						kinds["identify"]++
					default:
						t.Fatalf("%s/%s: MMS PDU 0x%02x sent", mode, level, tag)
					}
				}
			}
			want := map[string]int{"cr": 1, "initiate": 1, "conclude": 1}
			if mode == core.ModeIdentify {
				want["identify"] = 1
			}
			for k, n := range want {
				if kinds[k] != n {
					t.Fatalf("%s/%s: requests %v, want %v", mode, level, kinds, want)
				}
			}
			if len(kinds) != len(want) {
				t.Fatalf("%s/%s: requests %v, want %v", mode, level, kinds, want)
			}
		}
	}
}

// find searches constructed TLVs recursively, along a path and for the
// path's first tag at once, to a depth of 16. A hostile reply of nested
// TLVs whose tags repeat the path cannot make that blow up: the routes to a
// node grow with the path length (3), not exponentially with the depth.
// Measured at about 1 ms for 8 KiB; the bound is generous for -race.
func TestFindBoundedOnNestedTLVs(t *testing.T) {
	filler := bytes.Repeat([]byte{0x30, 0x00}, 3900) // constructed, never the target
	for _, shape := range [][]byte{
		bytes.Repeat([]byte{0x61}, 15),
		bytes.Repeat([]byte{0x61, 0x30}, 7),
		append(bytes.Repeat([]byte{0x61}, 7), bytes.Repeat([]byte{0x30}, 7)...),
	} {
		b := filler
		for i := len(shape) - 1; i >= 0; i-- {
			b = tlv(shape[i], b)
		}
		start := time.Now()
		if _, ok := find(b, 0x61, 0x30, 0xa0); ok {
			t.Fatal("found a tag that is not there")
		}
		if d := time.Since(start); d > time.Second {
			t.Fatalf("find on %d octets of nested % x took %v", len(b), shape[:2], d)
		}
	}
}
