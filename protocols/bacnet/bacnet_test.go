// SPDX-License-Identifier: MIT

package bacnet

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

// Request/response pairs captured from the bacnet-interop bacnet-stack
// device (instance 1234, vendor 260 "BACnet Stack at SourceForge").
var frames = map[string]string{
	"810a001101040005010c0c023fffff194b": "810a0017010030010c0c020004d2194b3ec4020004d23f", // wildcard object id -> device 1234
	"810a001101040005020c0c020004d2194d": "810a0022010030020c0c020004d2194d3e750e00496e7465726f704465766963653f",
	"810a001101040005020c0c020004d21979": "810a0030010030020c0c020004d219793e751c004241436e657420537461636b20617420536f75726365466f7267653f",
	"810a001101040005020c0c020004d21978": "810a0015010030020c0c020004d219783e2201043f",
	"810a001101040005020c0c020004d21946": "810a0017010030020c0c020004d219463e7400474e553f",
	"810a001101040005020c0c020004d2192c": "810a001a010030020c0c020004d2192c3e750600312e362e313f",
	"810a001101040005020c0c020004d2190c": "810a0017010030020c0c020004d2190c3e7400312e303f",
}

func device() testsrv.Handler {
	return func(req []byte) ([]byte, bool) {
		if r, ok := frames[hex.EncodeToString(req)]; ok {
			return unhex(r), false
		}
		return nil, false
	}
}

func TestDetectIdentify(t *testing.T) {
	target := testsrv.UDP(t, device())
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify, Trace: true})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v %v", r, err)
	}
	id := r.Identity
	if id.Name != "InteropDevice" || id.Vendor != "BACnet Stack at SourceForge" || id.VendorID != "260" ||
		id.Model != "GNU" || id.Version != "1.6.1" || id.Attributes["deviceInstance"] != "1234" ||
		id.Attributes["applicationSoftwareVersion"] != "1.0" {
		t.Fatalf("identity %+v", id)
	}
	if r.Fingerprint.Signature != "apdu=complex-ack" {
		t.Fatalf("signature %q", r.Fingerprint.Signature)
	}
}

func TestProbeBytes(t *testing.T) {
	if got := hex.EncodeToString(readProperty(1, wildcardInstance, propObjectIdentifier)); got != "810a001101040005010c0c023fffff194b" {
		t.Fatalf("wildcard read %s", got)
	}
	// Reference unicast Who-Is from go-bacnet: 81 0a 00 08 01 00 10 08.
	if got := hex.EncodeToString(whoIs()); got != "810a000801001008" {
		t.Fatalf("who-is %s", got)
	}
}

func TestRejectAndAbort(t *testing.T) {
	cases := map[string]string{
		"reject": "810a00090100600100",
		"abort":  "810a00090100700100",
		"error":  "810a000a010050019106",
	}
	for name, resp := range cases {
		t.Run(name, func(t *testing.T) {
			target := testsrv.UDP(t, testsrv.Script(unhex(resp)))
			r, err := New().Detect(context.Background(), target, core.Options{})
			if err != nil || !r.Matched || r.Confidence != core.ConfidenceHigh {
				t.Fatalf("%v %v", r, err)
			}
		})
	}
}

func TestIAmFallback(t *testing.T) {
	// A device that stays silent to the wildcard read but answers Who-Is
	// with an I-Am (device 1234, vendor 15).
	iamBytes := unhex("810b001401001000c4020004d22205c49103210f")
	target := testsrv.UDP(t, func(req []byte) ([]byte, bool) {
		if req[7] == svcWhoIs {
			return iamBytes, false
		}
		return nil, false
	})
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || !r.Matched || r.Fingerprint.Signature != "apdu=i-am" {
		t.Fatalf("%v %v", r, err)
	}
	if r.Identity == nil || r.Identity.Attributes["vendorId"] != "15" {
		t.Fatalf("identity %+v", r.Identity)
	}
}

func TestNotBACnet(t *testing.T) {
	target := testsrv.UDP(t, testsrv.Script([]byte("random")))
	target.Timeout = 300 * time.Millisecond
	r, _ := New().Detect(context.Background(), target, core.Options{})
	if r.Matched {
		t.Fatalf("%v", r)
	}
	silent := testsrv.UDP(t, testsrv.Script())
	silent.Timeout = 200 * time.Millisecond
	_, err := New().Detect(context.Background(), silent, core.Options{})
	if err == nil {
		t.Fatal("want timeout on silence")
	}
	if New().Info().Network != core.UDP {
		t.Fatal("network")
	}
}

func FuzzParse(f *testing.F) {
	for req, resp := range frames {
		f.Add(unhex(resp))
		_ = req
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if a, err := parse(b); err == nil {
			_, _, _ = readPropertyValue(a)
			_, _, _ = parseIAm(a.apdu)
		}
	})
}
