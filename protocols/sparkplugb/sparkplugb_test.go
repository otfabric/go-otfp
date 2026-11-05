// SPDX-License-Identifier: MIT

package sparkplugb

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

var (
	detect   = core.Options{Trace: true, MaxIntrusiveness: core.ReadOnly}
	identify = core.Options{Mode: core.ModeIdentify, Trace: true, MaxIntrusiveness: core.ReadOnly}
)

const state3 = `{"online":true,"timestamp":1700000000000}`

func runFP(t *testing.T, fp *Fingerprinter, target core.Target, opts core.Options) core.Result {
	t.Helper()
	r, err := fp.Detect(context.Background(), target, opts)
	fuzzkit.Check(t, proto, r, err)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return r
}

func short() *Fingerprinter { return &Fingerprinter{Window: 300 * time.Millisecond} }

func hasEvidence(r core.Result, sub string) bool {
	for _, e := range r.Evidence {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}

func TestInfo(t *testing.T) {
	i := New().Info()
	if i.Protocol != core.ProtocolSparkplugB || i.Refines != core.ProtocolMQTT || i.Intrusiveness != core.ReadOnly || i.Network != core.TCP {
		t.Fatalf("%+v", i)
	}
}

func TestDetectState3StopsEarly(t *testing.T) {
	b := &broker{connack: accept, msgs: [][]byte{pub("spBv1.0/STATE/scada", []byte(state3), true)}}
	start := time.Now()
	r := runFP(t, New(), b.target(t), detect)
	if !r.Matched || r.Confidence != core.ConfidenceCertain || r.Variant != "Sparkplug B 3.0" {
		t.Fatalf("%v %v", r, r.Evidence)
	}
	if time.Since(start) > 900*time.Millisecond {
		t.Fatalf("detection did not stop at the first certain message: %v", time.Since(start))
	}
	if r.Fingerprint.Signature != "namespace=spBv1.0;state=3.0" {
		t.Fatalf("%q", r.Fingerprint.Signature)
	}
	if r.Identity != nil && len(r.Identity.Attributes) > 0 {
		t.Fatalf("identity in detect mode: %+v", r.Identity)
	}
	got := b.wait(4)
	if string(got) != string([]byte{1, 8, 10, 14}) || b.pubs != 0 {
		t.Fatalf("packets %v, publishes %d", got, b.pubs)
	}
}

func TestIdentifyEverything(t *testing.T) {
	nbirth := birth(3, "Inputs/Temperature", "Node Control/Rebirth", "bad,name;")
	b := &broker{connack: accept, msgs: [][]byte{
		pub("spBv1.0/STATE/scada", []byte(state3), true),
		pub("spBv1.0/STATE/backup", []byte(`{"online":false,"timestamp":5}`), true),
		pub("STATE/legacy", []byte("ONLINE"), true),
		pub("STATE/other", []byte("hello"), true), // not Sparkplug
		pub("plain/topic", []byte("x"), false),
		pub("spBv1.0/plant/NBIRTH/edge1", nbirth, false),
		pub("spBv1.0/plant/DBIRTH/edge1/pump", birth(3, "Speed"), false),
		pub("spBv1.0/plant/NDATA/edge1", birth(3), false),
	}}
	r := runFP(t, short(), b.target(t), identify)
	if !r.Matched || r.Confidence != core.ConfidenceCertain || r.Variant != "Sparkplug B 3.0" {
		t.Fatalf("%v %v", r, r.Evidence)
	}
	want := map[string]string{
		"sparkplugVersion": "2.x,3.0",
		"messages":         "6",
		"messageTypes":     "STATE,NBIRTH,DBIRTH,NDATA",
		"groups":           "plant",
		"edgeNodes":        "plant/edge1",
		"devices":          "plant/edge1/pump",
		"hostApplications": "scada=online,backup=offline,legacy=online",
		"births":           "plant/edge1 metrics=4 bdSeq=3",
		"metricNames":      "bdSeq,Inputs/Temperature,Node Control/Rebirth,badname",
	}
	for k, v := range want {
		if got := r.Identity.Attributes[k]; got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if r.Fingerprint.Signature != "namespace=spBv1.0;state=2.x,3.0" {
		t.Fatalf("%q", r.Fingerprint.Signature)
	}
	if b.pubs != 0 {
		t.Fatal("published")
	}
}

func TestState2Only(t *testing.T) {
	b := &broker{connack: accept, msgs: [][]byte{pub("STATE/scada", []byte("OFFLINE"), true)}}
	r := runFP(t, short(), b.target(t), identify)
	if !r.Matched || r.Confidence != core.ConfidenceHigh || r.Variant != "Sparkplug B 2.x" {
		t.Fatalf("%v %v", r, r.Evidence)
	}
	if r.Fingerprint.Signature != "state=2.x" || r.Identity.Attributes["hostApplications"] != "scada=offline" {
		t.Fatalf("%q %+v", r.Fingerprint.Signature, r.Identity)
	}
}

func TestMediumEvidence(t *testing.T) {
	for name, m := range map[string][]byte{
		"state-json":   pub("spBv1.0/STATE/h", []byte(`{"online":"yes"}`), true),
		"bad-protobuf": pub("spBv1.0/g/NDATA/e", []byte{0xFF}, false),
		"no-timestamp": pub("spBv1.0/g/NDATA/e", pbUint(3, 1), false),
	} {
		t.Run(name, func(t *testing.T) {
			b := &broker{connack: accept, msgs: [][]byte{m}}
			r := runFP(t, short(), b.target(t), detect)
			if !r.Matched || r.Confidence != core.ConfidenceMedium || r.Variant != "Sparkplug B" {
				t.Fatalf("%v %v", r, r.Evidence)
			}
		})
	}
}

func TestNoSparkplugTraffic(t *testing.T) {
	b := &broker{connack: accept, msgs: [][]byte{pub("home/temp", []byte("21"), true), {0xD0, 0x00}, pub("STATE/x", []byte("hi"), false)}}
	r := runFP(t, short(), b.target(t), identify)
	if r.Matched || r.Confidence != 0 || r.Details != "no Sparkplug B traffic on the broker" {
		t.Fatalf("%v %v", r, r.Evidence)
	}
	if string(b.wait(4)) != string([]byte{1, 8, 10, 14}) {
		t.Fatalf("%v", b.wait(4))
	}
}

func TestSubscriptionsRefused(t *testing.T) {
	b := &broker{connack: accept, codes: []byte{0x80, 0x87, 0x80, 0x80}, msgs: [][]byte{pub("spBv1.0/STATE/h", []byte(state3), true)}}
	r := runFP(t, short(), b.target(t), identify)
	if r.Matched || !hasEvidence(r, "refused every Sparkplug B subscription") {
		t.Fatalf("%v %v", r, r.Evidence)
	}
	if got := b.wait(3); string(got) != string([]byte{1, 8, 14}) {
		t.Fatalf("unsubscribed after a refusal: %v", got)
	}
}

func TestBadSubackIgnored(t *testing.T) {
	b := &broker{connack: accept, codes: []byte{0}, msgs: [][]byte{pub("spBv1.0/STATE/h", []byte(state3), true)}}
	r := runFP(t, short(), b.target(t), detect)
	if !r.Matched {
		t.Fatalf("%v", r)
	}
}

func TestConnectionRefused(t *testing.T) {
	b := &broker{connack: func(byte) []byte { return []byte{0x20, 0x02, 0x00, 0x05} }}
	r := runFP(t, short(), b.target(t), identify)
	if r.Matched || !hasEvidence(r, "not authorized") || !strings.Contains(r.Details, "not checked") {
		t.Fatalf("%v %v", r, r.Evidence)
	}
}

func TestVersionRefusedRetriesV5(t *testing.T) {
	b := &broker{}
	b.connack = func(l byte) []byte {
		if l == 5 {
			return []byte{0x20, 0x03, 0x00, 0x00, 0x00}
		}
		return []byte{0x20, 0x03, 0x00, 0x84, 0x00}
	}
	pub5 := pkt(0x31, append(append(str("spBv1.0/STATE/h"), 0x00), state3...))
	b.msgs = [][]byte{pub5}
	r := runFP(t, short(), b.target(t), detect)
	if !r.Matched || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v %v", r, r.Evidence)
	}
}

func TestNotMQTT(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script([]byte("HTTP/1.1 400 Bad Request\r\n\r\n")))
	target.Timeout = 300 * time.Millisecond
	r := runFP(t, short(), target, detect)
	if r.Matched || r.Details != "not an MQTT broker" {
		t.Fatalf("%v", r)
	}
	closer := &broker{}
	if r := runFP(t, short(), closer.target(t), detect); r.Matched {
		t.Fatalf("%v", r)
	}
}

func TestSilentAndClosed(t *testing.T) {
	target := testsrv.Raw(t, func(c net.Conn) { _, _ = c.Read(make([]byte, 64)); time.Sleep(time.Second) })
	target.Timeout = 200 * time.Millisecond
	r, err := short().Detect(context.Background(), target, detect)
	fuzzkit.Check(t, proto, r, err)
	var te *core.TimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("%v %v", r, err)
	}
	r, err = short().Detect(context.Background(), testsrv.Closed(t), detect)
	fuzzkit.Check(t, proto, r, err)
	if err == nil {
		t.Fatal("want a connection error")
	}
}

func TestOversizedMessage(t *testing.T) {
	big := pub("spBv1.0/g/NBIRTH/e", make([]byte, MaxPacket), false)
	b := &broker{connack: accept, msgs: [][]byte{big}}
	r := runFP(t, short(), b.target(t), detect)
	if !r.Matched || r.Confidence != core.ConfidenceMedium || !hasEvidence(r, "larger than") {
		t.Fatalf("%v %v", r, r.Evidence)
	}
	junk := &broker{connack: accept, msgs: [][]byte{{0x30, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}}}
	if r := runFP(t, short(), junk.target(t), detect); r.Matched {
		t.Fatalf("%v", r)
	}
}

func TestHugeMetricCount(t *testing.T) {
	names := make([]string, 5000)
	for i := range names {
		names[i] = fmt.Sprintf("m%d", i)
	}
	b := &broker{connack: accept, msgs: [][]byte{pub("spBv1.0/g/NBIRTH/e", birth(1, names...), false)}}
	r := runFP(t, short(), b.target(t), identify)
	if got := r.Identity.Attributes["births"]; got != "g/e metrics=5001 bdSeq=1" {
		t.Fatalf("%q", got)
	}
	if n := strings.Count(r.Identity.Attributes["metricNames"], ",") + 1; n != MaxNames {
		t.Fatalf("%d names kept", n)
	}
}

func TestBounds(t *testing.T) {
	var msgs [][]byte
	for i := range 40 {
		msgs = append(msgs, pub(fmt.Sprintf("spBv1.0/g%d/NDATA/e", i), birth(0), false))
	}
	b := &broker{connack: accept, msgs: msgs}
	fp := &Fingerprinter{Window: 500 * time.Millisecond, MaxMessages: 20}
	r := runFP(t, fp, b.target(t), identify)
	if r.Identity.Attributes["messages"] != "20" || !strings.HasSuffix(r.Identity.Attributes["groups"], "(+4 more)") {
		t.Fatalf("%+v", r.Identity.Attributes)
	}
}

func TestWindowAndCancel(t *testing.T) {
	b := &broker{connack: accept, delay: 2 * time.Second, msgs: [][]byte{pub("spBv1.0/STATE/h", []byte(state3), true)}}
	target := b.target(t)
	target.Timeout = 200 * time.Millisecond
	start := time.Now()
	r := runFP(t, New(), target, identify) // the window is capped by the timeout
	if r.Matched || time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("%v after %v", r, time.Since(start))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := (&Fingerprinter{ClientID: "fixed"}).Detect(ctx, b.target(t), identify)
	if err == nil || r.Matched {
		t.Fatalf("%v %v", r, err)
	}
}

func TestCancelDuringWindow(t *testing.T) {
	b := &broker{connack: accept, delay: 3 * time.Second, msgs: [][]byte{pub("spBv1.0/STATE/h", []byte(state3), true)}}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	target := b.target(t)
	target.Timeout = 5 * time.Second
	start := time.Now()
	r, err := (&Fingerprinter{Window: 5 * time.Second}).Detect(ctx, target, identify)
	fuzzkit.Check(t, proto, r, err)
	if time.Since(start) > 2*time.Second || r.Matched {
		t.Fatalf("%v %v after %v", r, err, time.Since(start))
	}
}
