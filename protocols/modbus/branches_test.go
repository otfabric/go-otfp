// SPDX-License-Identifier: MIT

package modbus

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/mbap"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

func TestDeviceIDEdges(t *testing.T) {
	if _, err := parseDeviceID([]byte{0x0E}); err == nil {
		t.Fatal("short")
	}
	if _, err := parseDeviceID([]byte{0x0D, 1, 1, 0, 0, 0}); err == nil {
		t.Fatal("MEI type")
	}
	// Extended objects: printable, and binary rendered in hex.
	var id core.Identity
	fillIdentity(&id, map[byte]string{0x80: "Line 2", 0x81: "\x00\x01"})
	if id.Attributes["object0x80"] != "Line 2" || id.Attributes["object0x81"] != "0001" {
		t.Fatalf("%+v", id.Attributes)
	}
}

// A device answering for another unit, paging that ends early, a malformed
// identification and an MBAP header with a bad length.
func TestDetectEdges(t *testing.T) {
	page := 0
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) {
		tid := binary.BigEndian.Uint16(req)
		page++
		switch page {
		case 1: // unit 9 answers, announces more objects
			return mbap.Request(tid, 9, 0x2B, 0x0E, 0x02, 0x82, 0xFF, 0x01, 1, 0, 1, 'A'), false
		default: // the next page is an exception: stop paging
			return mbap.Request(tid, 9, 0xAB, 0x02), false
		}
	})
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
	if err != nil || !r.Matched || r.Identity.Vendor != "A" || r.Fingerprint.Metadata["unitId"] != "9" {
		t.Fatalf("%v %v", r, err)
	}
	for name, resp := range map[string][]byte{
		"malformed id": mbap.Request(probeTID, 1, 0x2B, 0x0D, 1, 1, 0, 0, 0),
		"bad length":   {0x4F, 0x54, 0, 0, 0, 0x30, 1, 0x2B},
	} {
		t.Run(name, func(t *testing.T) {
			target := testsrv.TCP(t, testsrv.Script(resp))
			target.Timeout = 200 * time.Millisecond
			r, _ := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
			if name == "malformed id" && (!r.Matched || r.Identity != nil) {
				t.Fatalf("%v", r)
			}
			if name == "bad length" && r.Matched {
				t.Fatalf("%v", r)
			}
		})
	}
}

// The FC 03 fallback can fail too: silent, or closed.
func TestFallbackFailures(t *testing.T) {
	for name, h := range map[string]testsrv.Handler{
		"silent": func(req []byte) ([]byte, bool) {
			if req[7] == 0x2B {
				return nil, true
			}
			return nil, false
		},
		"closed": func([]byte) ([]byte, bool) { return nil, true },
	} {
		t.Run(name, func(t *testing.T) {
			target := testsrv.TCP(t, h)
			target.Timeout = 200 * time.Millisecond
			r, err := New().Detect(context.Background(), target, core.Options{MaxIntrusiveness: core.ReadOnly})
			if r.Matched || (name == "silent" && err == nil) || (name == "closed" && err != nil) {
				t.Fatalf("%v %v", r, err)
			}
		})
	}
}
