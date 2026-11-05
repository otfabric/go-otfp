// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// server is a stateless go-opcua speaker: ACK to HEL, the captured
// OpenSecureChannel and GetEndpoints replies to OPN and MSG.
func server(req []byte) ([]byte, bool) {
	if len(req) < 8 {
		return nil, true
	}
	switch string(req[:3]) {
	case msgHELLO:
		return ackFrame, false
	case msgOPN:
		return opnReply, false
	case msgMSG:
		return epReply, false
	}
	return nil, true
}

func TestChaos(t *testing.T) {
	chaos.Suite{
		FP:  New(),
		TCP: func(t testing.TB, cfg chaos.Config) core.Target { return chaos.TCP(t, cfg, server) },
	}.Run(t)
}

// skipRequestHeader skips a RequestHeader as requestHeader encodes it: a
// two-octet null authentication token, timestamp, handle, diagnostics,
// audit entry id, timeout hint and a null additional header.
func skipRequestHeader(t *testing.T, p []byte) []byte {
	t.Helper()
	if len(p) < 2+8+4+4 || p[0] != 0 || p[1] != 0 {
		t.Fatalf("request header % x", p)
	}
	_, p, ok := getBytes(p[2+8+4+4:])
	if !ok || len(p) < 4+3 {
		t.Fatalf("request header audit id / timeout")
	}
	return p[4+3:]
}

// The safety contract: HEL, then in identify mode an OpenSecureChannel
// request of type Issue in security mode None with the None policy, and a
// GetEndpoints request (node 428) on that channel. Never CreateSession,
// ActivateSession, Read, Write, Call, Browse or any other service.
func TestSafetyContract(t *testing.T) {
	for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
		for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
			rec := &chaos.Recorder{}
			target := testsrv.TCP(t, rec.Wrap(server))
			r, err := New().Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: level})
			if err != nil || !r.Matched {
				t.Fatalf("%s/%s: %v %v", mode, level, r, err)
			}
			kinds := map[string]int{}
			for _, chunk := range rec.Requests() {
				for len(chunk) > 0 {
					n := framer(chunk)
					if n <= 0 || n > len(chunk) {
						t.Fatalf("not a UACP message: % x", chunk)
					}
					typ, _, body, err := parseMessage(chunk[:n])
					chunk = chunk[n:]
					if err != nil {
						t.Fatal(err)
					}
					kinds[typ]++
					switch typ {
					case msgHELLO:
					case msgOPN:
						p := body[4:] // secure channel id
						policy, p, ok := getString(p)
						if !ok || policy != policyNone {
							t.Fatalf("OPN policy %q", policy)
						}
						for range 2 { // sender certificate, receiver thumbprint
							if _, p, ok = getBytes(p); !ok {
								t.Fatal("OPN security header")
							}
						}
						p = p[8:] // sequence header
						if id, rest, ok := serviceID(p); !ok || id != 446 {
							t.Fatalf("OPN carries service %d, not OpenSecureChannel", id)
						} else {
							p = skipRequestHeader(t, rest)
						}
						if len(p) < 12 || binary.LittleEndian.Uint32(p[4:]) != 0 || binary.LittleEndian.Uint32(p[8:]) != 1 {
							t.Fatalf("OpenSecureChannel % x is not Issue in mode None", p)
						}
					case msgMSG:
						if id, _, ok := serviceID(body[16:]); !ok || id != idGetEndpointsRequest {
							t.Fatalf("%s/%s: MSG carries service %d, not GetEndpoints", mode, level, id)
						}
					default:
						t.Fatalf("%s/%s: %s message sent", mode, level, typ)
					}
				}
			}
			want := map[string]int{msgHELLO: 1}
			if mode == core.ModeIdentify {
				want[msgOPN], want[msgMSG] = 1, 1
			}
			if len(kinds) != len(want) {
				t.Fatalf("%s/%s: messages %v, want %v", mode, level, kinds, want)
			}
			for k, n := range want {
				if kinds[k] != n {
					t.Fatalf("%s/%s: messages %v, want %v", mode, level, kinds, want)
				}
			}
		}
	}
}

// The parent session's echo fix: an echo service returns our HEL, which a
// server never sends.
func TestEchoedHelloIsNotOPCUA(t *testing.T) {
	echo := func(req []byte) ([]byte, bool) { return req, false }
	for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
		r, err := New().Detect(context.Background(), testsrv.TCP(t, echo), core.Options{Mode: mode})
		if err != nil || r.Matched || r.Confidence != core.ConfidenceLow {
			t.Fatalf("%s: %v %v", mode, r, err)
		}
	}
}
