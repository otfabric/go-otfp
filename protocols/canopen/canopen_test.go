// SPDX-License-Identifier: MIT

package canopen

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// gateway is a fake CiA 309-3 gateway: info answers "info version"
// (without the sequence), objects answers "r <index> <sub>" keyed by
// "[<node> ]r 0xIIII S".
type gateway struct {
	info    string
	objects map[string]string
	mu      sync.Mutex
	got     []string
}

func (g *gateway) handle(req []byte) ([]byte, bool) {
	line := strings.TrimSpace(string(req))
	g.mu.Lock()
	g.got = append(g.got, line)
	g.mu.Unlock()
	end := strings.IndexByte(line, ']')
	if !strings.HasPrefix(line, "[") || end < 0 {
		return []byte("[0] ERROR:101 #Syntax error.\r\n"), false
	}
	seq, cmd := line[:end+1], strings.TrimSpace(line[end+1:])
	body := g.info
	if cmd != "info version" {
		// strip the datatype
		v, ok := g.objects[cmd[:strings.LastIndexByte(cmd, ' ')]]
		if !ok {
			v = "ERROR:0x06020000 #Object does not exist."
		}
		body = v
	}
	if body == "" {
		return nil, false
	}
	return []byte(seq + " " + body + "\r\n"), false
}

func (g *gateway) requests() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.got...)
}

// canopennode is what canopend v4.1 answers for the canopen-interop test
// device on node 32 (captured on vcan).
func canopennode() *gateway {
	return &gateway{
		info: "ERROR:100 #Request not supported.",
		objects: map[string]string{
			"32 r 0x1018 1": "0",
			"32 r 0x1018 2": "1129269553",
			"32 r 0x1018 3": "65536",
			"32 r 0x1018 4": "1",
			"32 r 0x1000 0": "983441",
			"32 r 0x1008 0": `"otfabric canopen-interop device"`,
			"r 0x1018 1":    "ERROR:105 #No default node set.",
		},
	}
}

var identify = core.Options{Mode: core.ModeIdentify, Trace: true, MaxIntrusiveness: core.ReadOnly}

func TestCANopenNodeIdentify(t *testing.T) {
	g := canopennode()
	target := testsrv.TCP(t, g.handle)
	r, err := NewWithConfig(Config{Node: 32}).Detect(context.Background(), target, identify)
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceHigh {
		t.Fatalf("%v %v", r, err)
	}
	if r.Fingerprint.Signature != "info=ERROR:100" {
		t.Fatalf("signature %q", r.Fingerprint.Signature)
	}
	id := r.Identity
	if id.VendorID != "0x00000000" || id.Serial != "0x00000001" || id.Product != "otfabric canopen-interop device" {
		t.Fatalf("identity %+v", id)
	}
	for k, want := range map[string]string{
		"productCode": "0x434F4931", "revision": "0x00010000", "deviceType": "0x000F0191",
		"profile": "CiA 401", "node": "32",
	} {
		if id.Attributes[k] != want {
			t.Errorf("%s = %q, want %q", k, id.Attributes[k], want)
		}
	}
	if len(r.Exchanges) != 1+len(identityObjects) {
		t.Fatalf("%d exchanges", len(r.Exchanges))
	}
	for _, req := range g.requests()[1:] {
		if !strings.Contains(req, " 32 r 0x") {
			t.Fatalf("request %q is not an SDO upload from node 32", req)
		}
	}
}

func TestDetectModeSendsOneRequest(t *testing.T) {
	g := canopennode()
	target := testsrv.TCP(t, g.handle)
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || !r.Matched {
		t.Fatalf("%v %v", r, err)
	}
	if got := g.requests(); len(got) != 1 || !strings.HasSuffix(got[0], "] info version") {
		t.Fatalf("requests %q", got)
	}
	if !r.Identity.IsZero() {
		t.Fatalf("identity in detect mode %+v", r.Identity)
	}
}

func TestIdentifyNeedsReadOnly(t *testing.T) {
	g := canopennode()
	target := testsrv.TCP(t, g.handle)
	r, err := NewWithConfig(Config{Node: 32}).Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
	if err != nil || !r.Matched || len(g.requests()) != 1 {
		t.Fatalf("%v %v %q", r, err, g.requests())
	}
	if !strings.Contains(strings.Join(r.Evidence, ";"), "need read-only") {
		t.Fatalf("evidence %q", r.Evidence)
	}
}

func TestNoDefaultNode(t *testing.T) {
	g := canopennode()
	target := testsrv.TCP(t, g.handle)
	r, err := New().Detect(context.Background(), target, identify)
	if err != nil || !r.Matched || !r.Identity.IsZero() {
		t.Fatalf("%v %v", r, err)
	}
	if len(g.requests()) != 2 || !strings.Contains(strings.Join(r.Evidence, ";"), "ERROR:105") {
		t.Fatalf("requests %q evidence %q", g.requests(), r.Evidence)
	}
}

func TestVersionRecord(t *testing.T) {
	g := &gateway{
		info: "0x0000031A 0x00001234 0x00010002 12345678 1 1 3",
		objects: map[string]string{
			"r 0x1018 1": "0x0000031A",    // x32 form
			"r 0x1018 2": "34 12 00 00",   // octets
			"r 0x1018 3": "OK",            // odd, skipped
			"r 0x1018 4": "not-a-number",  // skipped
			"r 0x1000 0": "0",             // no profile
			"r 0x1008 0": `"say ""hi"" "`, // escaped quote
			"r 0x100A 0": "FW1.2",         // unquoted word
		},
	}
	target := testsrv.TCP(t, g.handle)
	r, err := New().Detect(context.Background(), target, identify)
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v %v", r, err)
	}
	id := r.Identity
	if id.VendorID != "0x0000031A" || id.Serial != "0x00BC614E" || id.Version != "FW1.2" || id.Product != `say "hi"` {
		t.Fatalf("identity %+v", id)
	}
	if id.Attributes["productCode"] != "0x00001234" || id.Attributes["gatewayProductCode"] != "0x00001234" ||
		id.Attributes["implementationClass"] != "3" || id.Attributes["node"] != "default" {
		t.Fatalf("attributes %v", id.Attributes)
	}
	if _, ok := id.Attributes["profile"]; ok {
		t.Fatal("profile of device type 0")
	}
	if r.Fingerprint.Signature != "vendor=0x0000031A;product=0x00001234;revision=0x00010002" {
		t.Fatalf("signature %q", r.Fingerprint.Signature)
	}
}

func TestOKAndSDOAbortOnFirstRead(t *testing.T) {
	g := &gateway{info: "OK", objects: map[string]string{"5 r 0x1018 1": "ERROR:0x05040000 #SDO protocol timed out."}}
	target := testsrv.TCP(t, g.handle)
	r, err := NewWithConfig(Config{Node: 5}).Detect(context.Background(), target, identify)
	if err != nil || !r.Matched || r.Fingerprint.Signature != "info=OK" {
		t.Fatalf("%v %v", r, err)
	}
	if len(g.requests()) != 2 || !strings.Contains(strings.Join(r.Evidence, ";"), "SDO abort 0x05040000") {
		t.Fatalf("requests %q evidence %q", g.requests(), r.Evidence)
	}
}

func TestGatewayErrorMidIdentify(t *testing.T) {
	g := &gateway{info: "ERROR:100", objects: map[string]string{
		"7 r 0x1018 1": "1", "7 r 0x1018 2": "ERROR:102 #internal state", "7 r 0x1018 3": "3",
	}}
	target := testsrv.TCP(t, g.handle)
	r, err := NewWithConfig(Config{Node: 7}).Detect(context.Background(), target, identify)
	if err != nil || !r.Matched || r.Identity.VendorID != "0x00000001" || len(g.requests()) != 3 {
		t.Fatalf("%v %v %q", r, err, g.requests())
	}
}

func TestIdentifyStopsWhenGatewayCloses(t *testing.T) {
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) {
		line := strings.TrimSpace(string(req))
		seq := line[:strings.IndexByte(line, ']')+1]
		if strings.HasSuffix(line, "info version") {
			return []byte(seq + " ERROR:100\r\n"), false
		}
		return nil, true
	})
	r, err := New().Detect(context.Background(), target, identify)
	if err != nil || !r.Matched || !strings.Contains(strings.Join(r.Evidence, ";"), "identity read stopped") {
		t.Fatalf("%v %v", r, err)
	}
}

func TestStaleResponsesSkipped(t *testing.T) {
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) {
		line := strings.TrimSpace(string(req))
		seq := line[:strings.IndexByte(line, ']')+1]
		return []byte("\r\n[21] ERROR:101 #Syntax error.\r\n" + seq + " ERROR:100 #Request not supported.\r\n"), false
	})
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || !r.Matched || !strings.Contains(strings.Join(r.Evidence, ";"), "earlier client") {
		t.Fatalf("%v %v", r, err)
	}
}

func TestWrongSequenceIsAHint(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script([]byte("[1] ERROR:100\r\n")))
	target.Timeout = 300 * time.Millisecond
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || r.Matched || r.Confidence != core.ConfidenceLow {
		t.Fatalf("%v %v", r, err)
	}
	// Only foreign lines, up to the bound.
	target = testsrv.TCP(t, testsrv.Script([]byte(strings.Repeat("[1] OK\r\n", maxLines+1))))
	r, err = New().Detect(context.Background(), target, core.Options{})
	if err != nil || r.Matched || r.Confidence != core.ConfidenceLow {
		t.Fatalf("%v %v", r, err)
	}
}

func TestEchoIsNotAGateway(t *testing.T) {
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) { return req, false })
	r, err := New().Detect(context.Background(), target, identify)
	if err != nil || r.Matched || r.Confidence != 0 {
		t.Fatalf("%v %v", r, err)
	}
}

func TestRejectsTextAndBinary(t *testing.T) {
	for name, banner := range map[string]string{
		"http":     "HTTP/1.1 400 Bad Request\r\n",
		"ssh":      "SSH-2.0-OpenSSH_9.6\r\n",
		"smtp":     "220 mail.example ESMTP ready\r\n",
		"pop3":     "+OK ready\r\n",
		"telnet":   "\xff\xfd\x18\xff\xfd\x20\r\n",
		"prose":    "CANopen gateway ready\r\n",
		"slcan":    "\a",
		"bad code": "[%s] ERROR:42\r\n",
		"no space": "[%s]OK\r\n",
		"nul":      "[%s] OK\x00\r\n",
		"ctrl":     "[%s] \x1b[31mOK\r\n",
		"high":     "[%s] \xc3\xa9\r\n",
		"value":    "[%s] 1 2 3\r\n",
		"oversize": "[%s] " + strings.Repeat("A", maxLine) + "\r\n",
		"partial":  "[%s] ERROR:1",
		"empty":    "[%s]  \r\n",
	} {
		t.Run(name, func(t *testing.T) {
			target := testsrv.TCP(t, func(req []byte) ([]byte, bool) {
				line := strings.TrimSpace(string(req))
				seq := line[1:strings.IndexByte(line, ']')]
				return []byte(strings.ReplaceAll(banner, "%s", seq)), false
			})
			target.Timeout = 300 * time.Millisecond
			r, _ := New().Detect(context.Background(), target, core.Options{})
			if r.Matched {
				t.Fatalf("%v", r)
			}
		})
	}
}

func TestSlowPartialLine(t *testing.T) {
	target := testsrv.Raw(t, func(c net.Conn) {
		buf := make([]byte, 256)
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		line := strings.TrimSpace(string(buf[:n]))
		seq := line[:strings.IndexByte(line, ']')+1]
		_, _ = c.Write([]byte(seq + " ERR"))
		time.Sleep(100 * time.Millisecond)
		_, _ = c.Write([]byte("OR:100 #Request not supported.\r\n"))
		time.Sleep(time.Second)
	})
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || !r.Matched {
		t.Fatalf("%v %v", r, err)
	}
}

func TestSilentAndClosed(t *testing.T) {
	silent := testsrv.Raw(t, func(c net.Conn) { time.Sleep(time.Second) })
	silent.Timeout = 200 * time.Millisecond
	if r, err := New().Detect(context.Background(), silent, core.Options{}); err == nil || r.Matched {
		t.Fatalf("silent: %v %v", r, err)
	}
	hangup := testsrv.TCP(t, func([]byte) ([]byte, bool) { return nil, true })
	if r, err := New().Detect(context.Background(), hangup, core.Options{}); err != nil || r.Matched {
		t.Fatalf("hangup: %v %v", r, err)
	}
	if _, err := New().Detect(context.Background(), testsrv.Closed(t), core.Options{}); err == nil {
		t.Fatal("closed port: no error")
	}
}

func TestInfoAndConfig(t *testing.T) {
	if i := New().Info(); i.Protocol != core.ProtocolCANopen || i.Intrusiveness != core.Passive || i.Network != core.TCP {
		t.Fatalf("%+v", i)
	}
	for in, want := range map[int]int{0: 0, -1: 0, 1: 1, 127: 127, 128: 0} {
		if got := NewWithConfig(Config{Node: in}).node; got != want {
			t.Errorf("node %d -> %d, want %d", in, got, want)
		}
	}
}

func TestSequence(t *testing.T) {
	for range 100 {
		if s := newSeq(); s < 1000 || s > 0x7FFFFFFF {
			t.Fatalf("seq %d", s)
		}
	}
	if nextSeq(0x7FFFFFFF) != 1000 || nextSeq(5) != 6 {
		t.Fatal("nextSeq")
	}
}

func TestParsers(t *testing.T) {
	for in, ok := range map[string]bool{
		"[1] OK": true, "[4294967295] OK": true, "[4294967296] OK": false, "[] OK": false,
		"[-1] OK": false, "[1x] OK": false, "1] OK": false, "[1]": false, "[1] ": false,
		"[12345678901] OK": false, "[1]\tERROR:100": true, "[1] ERROR:0x05040000": true,
		"[1] ERROR:0X0504000G": false, "[1] ERROR:099": false, "[1] ERROR:100x": false,
		"[1] ERROR:100 trailing": false, "[1] ERROR:100 #desc": true, "[1] ERROR:100   ": true,
		"[1] ERROR:": false, "[1] value": true,
	} {
		if _, got := parseResponse([]byte(in)); got != ok {
			t.Errorf("parseResponse(%q) = %v, want %v", in, got, ok)
		}
	}
	for in, want := range map[string]uint32{
		"0": 0, "4294967295": 0xFFFFFFFF, "0xFFFFFFFF": 0xFFFFFFFF, "0Xab": 0xAB,
		"01": 1, "01 02": 0x0201, "FF FF FF FF": 0xFFFFFFFF,
	} {
		if got, ok := parseU32(in); !ok || got != want {
			t.Errorf("parseU32(%q) = %#x %v, want %#x", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "4294967296", "0x100000000", "0x", "0xZZ", "-1", "1 2", "01 02 03 04 05", "0g"} {
		if v, ok := parseU32(in); ok {
			t.Errorf("parseU32(%q) = %#x, want failure", in, v)
		}
	}
	if _, ok := parseVersion("1 2 3 4 5 6 x"); ok {
		t.Error("parseVersion non-number")
	}
	if _, ok := parseVersion("1 2 3"); ok {
		t.Error("parseVersion short")
	}
	for in, want := range map[string]string{
		`"a b"`: "a b", "word": "word", `""""`: `"`, `"` + strings.Repeat("x", 100) + `"`: strings.Repeat("x", maxString),
	} {
		if got, ok := parseVisibleString(in); !ok || got != want {
			t.Errorf("parseVisibleString(%q) = %q %v", in, got, ok)
		}
	}
	for _, in := range []string{`""`, `two words`, `"open`, `" "`} {
		if got, ok := parseVisibleString(in); ok {
			t.Errorf("parseVisibleString(%q) = %q, want failure", in, got)
		}
	}
	if hexVal('g') != 0 || hexVal('a') != 10 || hexVal('F') != 15 {
		t.Error("hexVal")
	}
	if _, ok := trimLine(nil); ok {
		t.Error("trimLine nil")
	}
	if l, ok := trimLine([]byte("\n")); !ok || len(l) != 0 {
		t.Error("trimLine LF")
	}
}

func FuzzResponse(f *testing.F) {
	for _, s := range []string{
		"[1234567] ERROR:100 #Request not supported.\r\n", "[11] 983441\r\n",
		"[13] \"otfabric canopen-interop device\"\r\n", "[14] ERROR:0x06020000 #Object does not exist.\r\n",
		"[2] 0x0000031A 0x00001234 0x00010002 12345678 1 1 3\r\n", "[3] 34 12 00 00\r\n", "HTTP/1.1 200 OK\r\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = lineFramer(b)
		line, ok := trimLine(b)
		if !ok {
			return
		}
		r, ok := parseResponse(line)
		if !ok {
			return
		}
		_, _ = parseU32(r.value)
		_, _ = parseVersion(r.value)
		_, _ = parseVisibleString(r.value)
	})
}
