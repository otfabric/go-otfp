// SPDX-License-Identifier: MIT

package mms

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// Frames of a go-mms v1.0.7 server (Vendor OTFabric, Model otfp-test,
// Revision 1.0), captured from its exchange with the go-mms client.
var (
	goMMSConfirm  = unhex("03 00 00 0b 06 d0 00 01 00 02 00")
	goMMSAccept   = unhex("03 00 00 85 02 f0 80 0e 7c 05 06 13 01 00 16 01 02 14 02 00 02 c1 6e 31 6c a0 03 80 01 01 a2 65 a5 12 30 07 80 01 00 81 02 51 01 30 07 80 01 00 81 02 51 01 61 4f 30 4d 02 01 01 a0 48 61 46 a1 07 06 05 28 ca 22 02 03 a2 03 02 01 00 a3 05 a1 03 02 01 00 be 2f 28 2d 02 01 03 a0 28 a9 26 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 80 01 01 81 03 05 f1 00 82 0c 03 ee 1c 00 00 04 08 00 00 79 ef 18")
	goMMSIdentify = unhex("03 00 00 35 02 f0 80 01 00 01 00 61 28 30 26 02 01 03 a0 21 a1 1f 02 01 01 a2 1a 80 08 4f 54 46 61 62 72 69 63 81 09 6f 74 66 70 2d 74 65 73 74 82 03 31 2e 30")
	goMMSConclude = unhex("03 00 00 16 02 f0 80 01 00 01 00 61 09 30 07 02 01 03 a0 02 8c 00")
	// The request of the go-mms client, for comparison with ours.
	goMMSInitiate    = unhex("03 00 00 8a 02 f0 80 0d 81 05 06 13 01 00 16 01 02 14 02 00 02 c1 73 31 71 a0 03 80 01 01 a2 6a a4 23 30 0f 02 01 01 06 04 52 01 00 01 30 04 06 02 51 01 30 10 02 01 03 06 05 28 ca 22 02 01 30 04 06 02 51 01 61 43 30 41 02 01 01 a0 3c 60 3a a1 07 06 05 28 ca 22 02 03 be 2f 28 2d 02 01 03 a0 28 a8 26 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 16 80 01 01 81 03 05 f1 00 82 0c 03 ee 1c 00 00 04 08 00 00 79 ef 18")
	goMMSIdentifyReq = unhex("03 00 00 1b 02 f0 80 01 00 01 00 61 0e 30 0c 02 01 03 a0 07 a0 05 02 01 01 82 00")
)

func TestProbesMatchReferenceClient(t *testing.T) {
	if got := presentationData(identifyRequest); !bytes.Equal(append(unhex("03 00 00 1b 02 f0 80"), got...), goMMSIdentifyReq) {
		t.Fatalf("identify request % x", got)
	}
	if !bytes.Equal(append(unhex("03 00 00 8a 02 f0 80"), initiate...), goMMSInitiate) {
		t.Fatal("initiate differs from the go-mms client's")
	}
}

func TestDetectIdentify(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script(goMMSConfirm, goMMSAccept, goMMSIdentify, goMMSConclude))
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify, Trace: true})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v %v", r, err)
	}
	if r.Identity == nil || r.Identity.Vendor != "OTFabric" || r.Identity.Model != "otfp-test" || r.Identity.Version != "1.0" {
		t.Fatalf("identity %+v", r.Identity)
	}
	if r.Fingerprint.Signature != "session=accept;initiate=response;v=1" || r.Fingerprint.Metadata["localDetailCalled"] != "65000" {
		t.Fatalf("fingerprint %+v", r.Fingerprint)
	}
	if len(r.Exchanges) != 4 {
		t.Fatalf("%d exchanges", len(r.Exchanges))
	}
}

func TestCOTPOnlyIsAHint(t *testing.T) {
	// An S7 PLC: confirms the CR, then answers the session CONNECT with
	// nothing.
	target := testsrv.TCP(t, testsrv.Script(goMMSConfirm))
	target.Timeout = 300 * time.Millisecond
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || r.Matched || r.Confidence != core.ConfidenceLow {
		t.Fatalf("%v %v", r, err)
	}
}

func TestRefusals(t *testing.T) {
	dr := unhex("03 00 00 0b 06 80 00 01 00 02 00")
	refuse := unhex("03 00 00 09 02 f0 80 0c 00")
	aareReject := bytes.Replace(goMMSAccept, unhex("a2 03 02 01 00"), unhex("a2 03 02 01 01"), 1)
	cases := map[string]struct {
		resps   [][]byte
		matched bool
	}{
		"cotp dr":     {[][]byte{dr}, false},
		"refuse":      {[][]byte{goMMSConfirm, refuse}, true},
		"aare reject": {[][]byte{goMMSConfirm, aareReject}, true},
		"not iso":     {[][]byte{[]byte("HTTP/1.1 400\r\n\r\n")}, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			target := testsrv.TCP(t, testsrv.Script(c.resps...))
			r, err := New().Detect(context.Background(), target, core.Options{})
			if err != nil || r.Matched != c.matched {
				t.Fatalf("%v %v", r, err)
			}
		})
	}
}

func FuzzAssociation(f *testing.F) {
	f.Add(goMMSAccept[7:])
	f.Add(goMMSIdentify[7:])
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) == 0 {
			return
		}
		fp := New()
		_ = fp.judgeAssociation(fpx.New(core.ProtocolMMS), b)
		_, _ = find(b, 0x61, 0x30, 0xa0)
	})
}
