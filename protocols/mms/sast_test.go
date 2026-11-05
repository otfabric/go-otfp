// SPDX-License-Identifier: MIT

package mms

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/iso"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// TSELs longer than a COTP CR carries used to wrap the length octets and
// put a malformed CR on the wire; now Detect refuses them before dialling.
func TestDetectRejectsOversizedTSELs(t *testing.T) {
	target := testsrv.Closed(t)
	f := NewWithConfig(Config{CallingTSEL: bytes.Repeat([]byte{1}, 256), CalledTSEL: []byte{0, 1}})
	r, err := f.Detect(context.Background(), target, core.Options{})
	var de *core.DetectError
	if r.Matched || err == nil || !errors.As(err, &de) || de.Op != "cotp-cr" {
		t.Fatalf("%v %v", r, err)
	}
	// The largest TSELs that fit still reach the network.
	f = NewWithConfig(Config{CallingTSEL: bytes.Repeat([]byte{1}, iso.MaxTSELs-2), CalledTSEL: []byte{0, 1}})
	if _, err := f.Detect(context.Background(), target, core.Options{}); err == nil || errors.As(err, &de) && de.Op == "cotp-cr" {
		t.Fatalf("closed port: %v", err)
	}
}

// BER lengths of 64 KiB and more used to lose their high octets.
func TestBERLongLengths(t *testing.T) {
	for n, want := range map[int]int{0x7f: 2, 0x80: 3, 0xff: 3, 0x100: 4, 0xffff: 4, 0x10000: 5} {
		enc := tlv(0x04, bytes.Repeat([]byte{'x'}, n))
		if hdr := len(enc) - n; hdr != want {
			t.Errorf("length %#x: %d header octets, want %d", n, hdr, want)
		}
		if tag, val, rest, ok := next(enc); !ok || tag != 0x04 || len(val) != n || len(rest) != 0 {
			t.Errorf("length %#x does not decode", n)
		}
	}
	if enc := tlv(0x04, bytes.Repeat([]byte{'x'}, 0x10000)); !bytes.Equal(enc[:5], []byte{0x04, 0x83, 0x01, 0x00, 0x00}) {
		t.Fatalf("% x", enc[:5])
	}
}
