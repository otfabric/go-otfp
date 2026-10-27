// SPDX-License-Identifier: MIT

package opcua

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// resize rewrites the UACP message size of a truncated frame so that the
// decoders, not parseMessage, meet the truncation.
func resize(b []byte) []byte {
	b = append([]byte(nil), b...)
	if len(b) >= 8 {
		binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	}
	return b
}

// Every prefix of the captured OPN and GetEndpoints replies: no panic, and
// each early return of the decoders is taken.
func TestTruncationSweep(t *testing.T) {
	for _, frame := range [][]byte{opnReply, epReply, ackFrame} {
		for i := 0; i <= len(frame); i++ {
			f := resize(frame[:i])
			_, _, _ = openChannelResult(f)
			_, _ = parseEndpoints(f)
			_, _, _, _ = parseMessage(f)
			if i >= 8 {
				_ = framer(f)
			}
		}
	}
	// And every prefix of one endpoint description.
	_, _, body, _ := parseMessage(epReply)
	payload, _ := stripSecurityHeader(msgMSG, body)
	_, rest, _ := serviceID(payload)
	p := skipResponseHeader(rest)
	for i := 0; i <= len(p)-4; i++ {
		_, _, _ = decodeEndpoint(p[4 : 4+i])
	}
}

// serviceFault builds a ServiceFault reply with the given status.
func serviceFault(status uint32, full bool) []byte {
	b := make([]byte, 16) // channel, token, sequence, request
	b = append(b, fourByteNodeID(idServiceFault)...)
	b = binary.LittleEndian.AppendUint64(b, 0)
	b = binary.LittleEndian.AppendUint32(b, 1)
	if full {
		b = binary.LittleEndian.AppendUint32(b, status)
	}
	return message(msgMSG, b)
}

func TestParseEndpointsErrors(t *testing.T) {
	cases := map[string][]byte{
		"not uacp":      []byte("HTTP/1.1 200 OK\r\n\r\n"),
		"short":         message(msgMSG, []byte{1, 2, 3}),
		"no service id": message(msgMSG, make([]byte, 18)),
		"fault":         serviceFault(0x80230000, true),
		"short fault":   serviceFault(0, false),
		"other service": message(msgMSG, append(make([]byte, 16), fourByteNodeID(999)...)),
		"bad header":    message(msgMSG, append(append(make([]byte, 16), fourByteNodeID(idGetEndpointsResponse)...), make([]byte, 16)...)),
	}
	for name, f := range cases {
		if _, err := parseEndpoints(f); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := parseEndpoints(serviceFault(0x80230000, true)); err == nil || err.Error() != "service fault 0x80230000" {
		t.Errorf("fault status: %v", err)
	}
}

// responseHeader encodes a ResponseHeader with the given diagnostics mask
// and string table.
func responseHeader(diag byte, table ...string) []byte {
	b := binary.LittleEndian.AppendUint64(nil, 0)
	b = binary.LittleEndian.AppendUint32(b, 1)
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = append(b, diag)
	if table == nil {
		b = binary.LittleEndian.AppendUint32(b, 0xFFFFFFFF)
	} else {
		b = binary.LittleEndian.AppendUint32(b, uint32(len(table)))
		for _, s := range table {
			b = str(b, s)
		}
	}
	return append(b, 0, 0, 0)
}

func TestSkipResponseHeader(t *testing.T) {
	if p := skipResponseHeader(responseHeader(0, "a", "bc")); p == nil || len(p) != 0 {
		t.Fatalf("string table: %v", p)
	}
	if skipResponseHeader(responseHeader(1)) != nil {
		t.Fatal("diagnostics present must not be skipped blindly")
	}
	h := responseHeader(0, "abc")
	if skipResponseHeader(h[:len(h)-5]) != nil {
		t.Fatal("truncated string table")
	}
}

func TestEndpointCounts(t *testing.T) {
	head := append(append(make([]byte, 16), fourByteNodeID(idGetEndpointsResponse)...), responseHeader(0)...)
	bad := message(msgMSG, binary.LittleEndian.AppendUint32(append([]byte(nil), head...), 1000))
	if _, err := parseEndpoints(bad); err == nil {
		t.Fatal("endpoint count 1000 accepted")
	}
	// Two endpoints announced, the second truncated: keep the first.
	_, _, body, _ := parseMessage(epReply)
	payload, _ := stripSecurityHeader(msgMSG, body)
	_, rest, _ := serviceID(payload)
	ep := skipResponseHeader(rest)[4:] // one endpoint description
	two := append(binary.LittleEndian.AppendUint32(append([]byte(nil), head...), 2), ep...)
	two = append(two, ep[:10]...)
	eps, err := parseEndpoints(message(msgMSG, two))
	if err != nil || len(eps) != 1 {
		t.Fatalf("%d endpoints, %v", len(eps), err)
	}
}

// Detect over each kind of server answer.
func TestDetectBranches(t *testing.T) {
	errOPN := message(msgERR, []byte{0, 0, 0x7e, 0x80, 0xff, 0xff, 0xff, 0xff})
	cases := map[string]struct {
		replies [][]byte
		mode    core.Mode
		matched bool
		conf    core.Confidence
	}{
		"short ack":        {[][]byte{message(msgACK, []byte{0, 0})}, core.ModeDetect, true, core.ConfidenceHigh},
		"other type":       {[][]byte{message(msgOPN, make([]byte, 20))}, core.ModeDetect, true, core.ConfidenceHigh},
		"opn silent":       {[][]byte{ackFrame}, core.ModeIdentify, true, core.ConfidenceCertain},
		"opn refused":      {[][]byte{ackFrame, errOPN}, core.ModeIdentify, true, core.ConfidenceCertain},
		"endpoints silent": {[][]byte{ackFrame, opnReply}, core.ModeIdentify, true, core.ConfidenceCertain},
		"endpoints fault":  {[][]byte{ackFrame, opnReply, serviceFault(0x80230000, true)}, core.ModeIdentify, true, core.ConfidenceCertain},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			target := testsrv.TCP(t, testsrv.Script(c.replies...))
			target.Timeout = 200 * time.Millisecond
			r, err := New().Detect(context.Background(), target, core.Options{Mode: c.mode})
			if err != nil || r.Matched != c.matched || r.Confidence != c.conf {
				t.Fatalf("%v %v", r, err)
			}
			if c.mode == core.ModeIdentify && r.Identity != nil {
				t.Fatalf("identity from a failed identify: %+v", r.Identity)
			}
		})
	}
	if _, err := New().Detect(context.Background(), testsrv.Closed(t), core.Options{}); err == nil {
		t.Fatal("closed port")
	}
}

func TestHelpers(t *testing.T) {
	if shortPolicy("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256") != "Basic256Sha256" || shortPolicy("plain") != "plain" {
		t.Fatal("shortPolicy")
	}
	if join([]string{"None", "Basic256"}) != "None,Basic256" {
		t.Fatal("join")
	}
	if code, reason := parseError([]byte{1}); code != 0 || reason != "" {
		t.Fatal("short ERR body")
	}
	for _, h := range [][]byte{[]byte("XYZF\x10\x00\x00\x00"), []byte("ACKX\x10\x00\x00\x00"), []byte("ACKF\x04\x00\x00\x00")} {
		if framer(h) != -1 {
			t.Errorf("framer accepted %q", h)
		}
	}
	// A LocalizedText with locale and text, and with neither.
	lt := str(append([]byte{0x03}, str(nil, "en")...), "Name")
	if text, rest, ok := getLocalizedText(lt); !ok || text != "Name" || len(rest) != 0 {
		t.Fatalf("localized text %q %v", text, ok)
	}
	if text, _, ok := getLocalizedText([]byte{0x00}); !ok || text != "" {
		t.Fatal("empty localized text")
	}
	for _, b := range [][]byte{nil, {0x01, 5, 0, 0, 0}, {0x02, 5, 0, 0, 0}} {
		if _, _, ok := getLocalizedText(b); ok {
			t.Errorf("% x accepted", b)
		}
	}
	// User token policies: a null array, and a truncated one.
	if _, ok := skipUserTokenPolicies([]byte{0xff, 0xff, 0xff, 0xff}); !ok {
		t.Fatal("null token array")
	}
	if _, ok := skipStringArray([]byte{0xff, 0xff, 0xff, 0xff}); !ok {
		t.Fatal("null string array")
	}
	for _, b := range [][]byte{{1}, {1, 0, 0, 0}, {1, 0, 0, 0, 0, 0, 0, 0}} {
		if _, ok := skipUserTokenPolicies(b); ok {
			t.Errorf("token policies % x", b)
		}
	}
	if _, ok := skipStringArray([]byte{2, 0, 0, 0, 0, 0, 0, 0}); ok {
		t.Fatal("string array truncated after one element")
	}
	if _, ok := stripSecurityHeader("XXX", nil); ok {
		t.Fatal("unknown message type")
	}
}
