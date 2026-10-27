// SPDX-License-Identifier: MIT

package enip

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// ListIdentity reply of the OpENer opener-sample fixture, with the probe's
// sender context (zeroed here; the handler copies the real one back).
const openerBody = "01 00 0c 00 2b 00 01 00 00 02 af 12 ac 11 00 02 00 00 00 00 00 00 00 00 01 00 0c 00 e9 fd 02 03 00 00 15 cd 5b 07 09 4f 70 45 4e 65 72 20 50 43 00"

// opener replies to ListIdentity (and RegisterSession) as OpENer does,
// echoing the sender context.
func opener() testsrv.Handler {
	body := unhex(openerBody)
	return func(req []byte) ([]byte, bool) {
		if len(req) < headerLen {
			return nil, true
		}
		cmd := binary.LittleEndian.Uint16(req)
		var ctx [8]byte
		copy(ctx[:], req[12:20])
		switch cmd {
		case cmdListIdentity:
			return encap(cmdListIdentity, 0, ctx, body), false
		case cmdRegisterSession:
			return encap(cmdRegisterSession, 1, ctx, []byte{1, 0, 0, 0}), false
		}
		return nil, true
	}
}

func TestDetectTCP(t *testing.T) {
	target := testsrv.TCP(t, opener())
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify, Trace: true})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v %v", r, err)
	}
	id := r.Identity
	if id.Vendor != "Rockwell Automation/Allen-Bradley" || id.Product != "OpENer PC" || id.Version != "2.3" ||
		id.Serial != "0x075BCD15" || id.Attributes["deviceType"] != "Communications Adapter" || id.Attributes["productCode"] != "65001" {
		t.Fatalf("identity %+v", id)
	}
	if r.Fingerprint.Signature != "vendor=1;devtype=0x0c;product=65001;rev=2.3;session=ok" {
		t.Fatalf("signature %q", r.Fingerprint.Signature)
	}
}

func TestDetectUDP(t *testing.T) {
	target := testsrv.UDP(t, opener())
	r, err := NewUDP().Detect(context.Background(), target, core.Options{})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v %v", r, err)
	}
	// No RegisterSession over UDP.
	if r.Fingerprint.Metadata["vendorId"] != "1" {
		t.Fatalf("metadata %v", r.Fingerprint.Metadata)
	}
}

func TestNetworkMismatch(t *testing.T) {
	if New().Info().Network != core.TCP || NewUDP().Info().Network != core.UDP {
		t.Fatal("network")
	}
	// A UDP target handed to the TCP fingerprinter is skipped.
	r, err := New().Detect(context.Background(), core.Target{Host: "127.0.0.1", Port: 1, Network: core.UDP}, core.Options{})
	if err != nil || r.Matched {
		t.Fatalf("%v %v", r, err)
	}
}

func TestErrorStatus(t *testing.T) {
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) {
		var ctx [8]byte
		copy(ctx[:], req[12:20])
		b := encap(cmdListIdentity, 0, ctx, nil)
		binary.LittleEndian.PutUint32(b[8:], 0x0001)
		return b, false
	})
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || r.Confidence != core.ConfidenceHigh || !r.Matched {
		t.Fatalf("%v %v", r, err)
	}
}

func TestNotENIP(t *testing.T) {
	for name, resp := range map[string][]byte{
		"ssh":       []byte("SSH-2.0\r\n"),
		"bad len":   unhex("63 00 ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"),
		"wrong cmd": encap(0x0099, 0, [8]byte{}, nil),
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

func TestCatalog(t *testing.T) {
	if vendorName(1) != "Rockwell Automation/Allen-Bradley" || vendorName(0xFFFF) != "" {
		t.Fatal("vendorName")
	}
	if deviceTypeName(0x0C) != "Communications Adapter" || deviceTypeName(0x0E) != "Programmable Logic Controller" {
		t.Fatal("deviceTypeName")
	}
	if deviceTypeName(0x9999) != "device type 0x9999" {
		t.Fatalf("fallback %q", deviceTypeName(0x9999))
	}
}

func FuzzParse(f *testing.F) {
	f.Add(unhex(openerBody))
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, _, err := parseEncap(b); err == nil {
			_, _ = parseIdentityItem(b[min(len(b), headerLen):])
		}
		_, _ = parseIdentityItem(b)
	})
}
