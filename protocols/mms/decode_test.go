// SPDX-License-Identifier: MIT

package mms

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/iso"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// Every prefix of the captured association and Identify replies goes
// through the decoders.
func TestTruncationSweep(t *testing.T) {
	for _, frame := range [][]byte{goMMSAccept, goMMSIdentify} {
		user := frame[7:]
		for i := 0; i <= len(user); i++ {
			p := user[:i]
			if len(p) > 0 {
				_ = New().judgeAssociation(fpx.New(proto), p)
			}
			_, _ = sessionUserData(p)
			_, _ = find(p, 0x61, 0x30, 0xa0)
			_, _, _, _ = next(p)
		}
	}
}

func TestBER(t *testing.T) {
	// Long-form lengths, both ways.
	for _, n := range []int{5, 200, 1000} {
		enc := tlv(0x04, bytes.Repeat([]byte{'x'}, n))
		tag, val, rest, ok := next(enc)
		if !ok || tag != 0x04 || len(val) != n || len(rest) != 0 {
			t.Fatalf("length %d: %v %d %v", n, tag, len(val), ok)
		}
	}
	// A high tag number (0x1f, then continuation octets).
	if tag, val, _, ok := next([]byte{0xbf, 0x81, 0x02, 0x01, 'z'}); !ok || tag != 0xbf || string(val) != "z" {
		t.Fatalf("high tag: %x %q %v", tag, val, ok)
	}
	for _, b := range [][]byte{
		{0x30},                // no length
		{0x30, 0x85, 1, 2, 3}, // length of length too long
		{0x30, 0x80},          // indefinite length
		{0x30, 0x82, 0x01},    // truncated long length
		{0x30, 0x05, 1},       // value overruns
		{0xbf, 0x81},          // truncated high tag
		{0xbf, 0x81, 0x82},    // high tag without length
	} {
		if _, _, _, ok := next(b); ok {
			t.Errorf("% x accepted", b)
		}
	}
	if _, ok := find([]byte{0x04, 0x09, 0x04, 0x01, 'a'}, 0x04); !ok { // 04 09 overruns: skip on
		t.Fatal("find skips non-BER octets")
	}
	if _, ok := findDepth([]byte{0x30, 0x00}, []byte{0x30}, 1, maxDepth+1, new(int)); ok {
		t.Fatal("depth bound")
	}
	if n, ok := integer([]byte{1, 0}, 16); !ok || n != 256 {
		t.Fatal("integer")
	}
}

func TestSPDUParams(t *testing.T) {
	// A parameter with the two-octet (0xFF) length form.
	long := append([]byte{0xc1, 0xff, 0x00, 0x03}, 'a', 'b', 'c')
	if code, val, rest, ok := spduParam(long); !ok || code != 0xc1 || string(val) != "abc" || len(rest) != 0 {
		t.Fatalf("long parameter: %x %q %v", code, val, ok)
	}
	for _, b := range [][]byte{{0xc1}, {0xc1, 0xff, 0}, {0xc1, 5, 1}} {
		if _, _, _, ok := spduParam(b); ok {
			t.Errorf("% x accepted", b)
		}
	}
	if _, ok := sessionUserData([]byte{0x0e, 0x03, 0x05, 0x01, 0x00}); ok {
		t.Fatal("ACCEPT without user data")
	}
}

func dt(user ...byte) []byte { return iso.Data(user) }

func TestAssociationVerdicts(t *testing.T) {
	initErr := bytes.Replace(goMMSAccept, []byte{0xa9, 0x26}, []byte{0xaa, 0x26}, 1)
	noMMS := bytes.Replace(goMMSAccept, []byte{0xa9, 0x26}, []byte{0x04, 0x26}, 1)
	cases := map[string]struct {
		resps   [][]byte
		matched bool
		conf    core.Confidence
	}{
		"abort":        {[][]byte{goMMSConfirm, dt(0x19, 0x00)}, true, core.ConfidenceMedium},
		"s7 answer":    {[][]byte{goMMSConfirm, dt(0x32, 0x03, 0x00)}, false, core.ConfidenceLow},
		"no user data": {[][]byte{goMMSConfirm, dt(0x0e, 0x03, 0x05, 0x01, 0x00)}, true, core.ConfidenceMedium},
		"no session":   {[][]byte{goMMSConfirm, iso.TPKT([]byte{0x02, 0xf0, 0x80})}, false, core.ConfidenceLow},
		"initiate err": {[][]byte{goMMSConfirm, initErr}, true, core.ConfidenceHigh},
		"aare only":    {[][]byte{goMMSConfirm, noMMS}, true, core.ConfidenceHigh},
		"malformed cc": {[][]byte{iso.TPKT([]byte{0x02, 0xd0, 0x00})}, false, 0},
		"no answer":    {[][]byte{goMMSConfirm}, false, core.ConfidenceLow},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			target := testsrv.TCP(t, testsrv.Script(c.resps...))
			target.Timeout = 200 * time.Millisecond
			r, err := New().Detect(context.Background(), target, core.Options{})
			if err != nil || r.Matched != c.matched || r.Confidence != c.conf {
				t.Fatalf("%v %v", r, err)
			}
		})
	}
}

func TestIdentifyVerdicts(t *testing.T) {
	refused := dt(append([]byte{0x01, 0x00, 0x01, 0x00}, tlv(0x61, tlv(0x30, append([]byte{0x02, 0x01, 0x03}, tlv(0xa0, tlv(tagConfirmedError, []byte{0x02, 0x01, 0x01}))...)))...)...)
	notConfirmed := dt(append([]byte{0x01, 0x00, 0x01, 0x00}, tlv(0x61, tlv(0x30, append([]byte{0x02, 0x01, 0x03}, tlv(0xa0, tlv(0xa3, nil))...)))...)...)
	noIDR := dt(append([]byte{0x01, 0x00, 0x01, 0x00}, tlv(0x61, tlv(0x30, append([]byte{0x02, 0x01, 0x03}, tlv(0xa0, tlv(tagConfirmedResponse, []byte{0x02, 0x01, 0x01}))...)))...)...)
	for name, reply := range map[string][]byte{
		"refused":     refused,
		"other pdu":   notConfirmed,
		"no identify": noIDR,
		"not data":    iso.TPKT([]byte{0x06, 0x80, 0, 0, 0, 0, 0}),
		"no pdu":      dt(0x01, 0x00, 0x01, 0x00),
	} {
		t.Run(name, func(t *testing.T) {
			target := testsrv.TCP(t, testsrv.Script(goMMSConfirm, goMMSAccept, reply))
			target.Timeout = 200 * time.Millisecond
			r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
			if err != nil || !r.Matched || r.Identity != nil {
				t.Fatalf("%v %v %+v", r, err, r.Identity)
			}
		})
	}
	// Identify unanswered.
	target := testsrv.TCP(t, testsrv.Script(goMMSConfirm, goMMSAccept))
	target.Timeout = 200 * time.Millisecond
	if r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify}); err != nil || !r.Matched {
		t.Fatalf("%v %v", r, err)
	}
	if _, err := New().Detect(context.Background(), testsrv.Closed(t), core.Options{}); err == nil {
		t.Fatal("closed port")
	}
	if NewWithConfig(Config{CalledTSEL: []byte{0, 2}}).called[1] != 2 {
		t.Fatal("config")
	}
}

// A high tag number takes at most maxTagOctets subsequent octets.
func TestHighTagOctetsBounded(t *testing.T) {
	if tag, val, _, ok := next([]byte{0xbf, 0x81, 0x81, 0x81, 0x02, 0x01, 'z'}); !ok || tag != 0xbf || string(val) != "z" {
		t.Fatalf("four tag octets: %x %q %v", tag, val, ok)
	}
	if _, _, _, ok := next([]byte{0xbf, 0x81, 0x81, 0x81, 0x81, 0x02, 0x01, 'z'}); ok {
		t.Fatal("five tag octets accepted")
	}
	if _, _, _, ok := next(bytes.Repeat([]byte{0xff}, 64)); ok {
		t.Fatal("a run of 0xff accepted")
	}
}

// A reply of 16 nested constructed TLVs (8 x 0x61 around 8 x 0x30, the
// path's own tags) around a run of 0xff octets, as large as one frame
// carries: find decodes at most maxDepth+1 times per octet, whatever the
// path, rather than once per route to each node.
func TestFindStepsLinear(t *testing.T) {
	b := bytes.Repeat([]byte{0xff}, maxFrame-71)
	for range 8 {
		b = tlv(0x30, b)
	}
	for range 8 {
		b = tlv(0x61, b)
	}
	for _, path := range [][]byte{{0x61, 0x30, 0xa0}, {0x61}, {0xa1}, {0x61, 0x30, 0x61, 0x30}} {
		_, _, steps := findSteps(b, path)
		if limit := (maxDepth + 1) * len(b); steps > limit {
			t.Errorf("path % x: %d steps on %d octets, more than %d", path, steps, len(b), limit)
		}
	}
	// The captured Identify response is still found along the path.
	if v, ok, _ := findSteps(goMMSIdentify[7:], []byte{0x61, 0x30, 0xa0}); !ok || len(v) == 0 {
		t.Fatal("captured Identify response not found")
	}
	if _, ok, steps := findSteps(b, make([]byte, 9)); ok || steps != 0 {
		t.Fatal("a path of nine tags searched")
	}
}

// cancelOn is a Logger that cancels the scan once it sees a label.
type cancelOn struct {
	core.Logger
	label  string
	cancel context.CancelFunc
}

func (c cancelOn) Debugf(format string, args ...any) {
	if len(args) > 2 && args[2] == c.label {
		c.cancel()
	}
}

// A scan that ends while the Identify response is decoded reports the
// cancellation, not a verdict.
func TestIdentifyAfterCancel(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script(goMMSConfirm, goMMSAccept, goMMSIdentify, goMMSConclude))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := cancelOn{Logger: core.NopLogger(), label: "identify", cancel: cancel}
	_, err := New().Detect(ctx, target, core.Options{Mode: core.ModeIdentify, Logger: log})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
}
