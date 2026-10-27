// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"encoding/hex"
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

// Response frames captured from a go-opcua server (application "otfp-probe",
// product URI urn:github.com:otfabric:opcua:server, policy None).
var (
	ackFrame = unhex("41434b461c00000000000000ffff0000ffff00000000100000020000")
	opnReply = unhex("4f504e4687000000bfad820b2f000000687474703a2f2f6f7063666f756e646174696f6e2e6f72672f55412f5365637572697479506f6c696379234e6f6e65ffffffffffffffff28000000010000000100c10152c0d620ac65dd010100000000000000000000000000000000000000bfad820b4c60b0465cc0d620ac65dd0180ee360000000000")
	epReply  = unhex("4d53474671010000bfad820b4c60b04629000000020000000100af01b2ced620ac65dd010200000000000000000000000000000001000000190000006f70632e7463703a2f2f3132372e302e302e313a36303332360d00000075726e3a6f7466703a746573742400000075726e3a6769746875622e636f6d3a6f746661627269633a6f706375613a736572766572020a0000006f7466702d70726f626500000000ffffffffffffffff01000000190000006f70632e7463703a2f2f3132372e302e302e313a3630333236ffffffff010000002f000000687474703a2f2f6f7063666f756e646174696f6e2e6f72672f55412f5365637572697479506f6c696379234e6f6e65010000000e000000616e6f6e796d6f75735f6e6f6e6500000000ffffffffffffffffffffffff41000000687474703a2f2f6f7063666f756e646174696f6e2e6f72672f55412d50726f66696c652f5472616e73706f72742f75617463702d756173632d756162696e61727901")
)

func TestDetect(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script(ackFrame))
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain || r.Variant != "opc.tcp" {
		t.Fatalf("%v %v", r, err)
	}
	if r.Fingerprint.Metadata["maxChunkCount"] != "512" {
		t.Fatalf("metadata %v", r.Fingerprint.Metadata)
	}
}

func TestIdentify(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script(ackFrame, opnReply, epReply))
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify, Trace: true})
	if err != nil || !r.Matched {
		t.Fatalf("%v %v", r, err)
	}
	id := r.Identity
	if id.Name != "otfp-probe" || id.Attributes["applicationUri"] != "urn:otfp:test" ||
		id.Attributes["productUri"] != "urn:github.com:otfabric:opcua:server" || id.Attributes["securityPolicies"] != "None" {
		t.Fatalf("identity %+v", id)
	}
	if len(r.Exchanges) != 3 {
		t.Fatalf("%d exchanges", len(r.Exchanges))
	}
}

func TestErrIsOPCUA(t *testing.T) {
	// ERR body: BadTcpEndpointUrlInvalid (0x80830000) + null reason.
	eb := message(msgERR, append(unhex("00008380"), unhex("ffffffff")...))
	target := testsrv.TCP(t, testsrv.Script(eb))
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v %v", r, err)
	}
	if r.Fingerprint.Signature != "err=0x80830000" {
		t.Fatalf("signature %q", r.Fingerprint.Signature)
	}
}

func TestHelloProbe(t *testing.T) {
	h := hello("opc.tcp://127.0.0.1:4840")
	typ, chunk, body, err := parseMessage(h)
	if err != nil || typ != msgHELLO || chunk != chunkF || len(body) != 20+4+len("opc.tcp://127.0.0.1:4840") {
		t.Fatalf("hello %x %v", h, err)
	}
}

func TestNotOPCUA(t *testing.T) {
	for name, resp := range map[string][]byte{
		"http":   []byte("HTTP/1.1 200 OK\r\n\r\n"),
		"modbus": {0, 1, 0, 0, 0, 2, 1, 0x83},
	} {
		t.Run(name, func(t *testing.T) {
			target := testsrv.TCP(t, testsrv.Script(resp))
			target.Timeout = 300 * time.Millisecond
			r, _ := New().Detect(context.Background(), target, core.Options{})
			if r.Matched {
				t.Fatalf("%v", r)
			}
		})
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(epReply)
	f.Add(opnReply)
	f.Fuzz(func(t *testing.T, b []byte) {
		if typ, _, body, err := parseMessage(b); err == nil {
			if typ == msgOPN {
				_, _, _ = openChannelResult(b)
			}
			_, _ = parseEndpoints(b)
			_ = body
		}
	})
}
