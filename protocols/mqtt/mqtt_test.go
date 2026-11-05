// SPDX-License-Identifier: MIT

package mqtt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

var (
	detect   = core.Options{Trace: true}
	identify = core.Options{Mode: core.ModeIdentify, Trace: true, MaxIntrusiveness: core.ReadOnly}
)

func run(t *testing.T, target core.Target, opts core.Options) core.Result {
	t.Helper()
	r, err := New().Detect(context.Background(), target, opts)
	fuzzkit.Check(t, proto, r, err)
	if err != nil {
		t.Fatalf("unexpected error: %v (%v)", err, r)
	}
	return r
}

func hasEvidence(r core.Result, sub string) bool {
	for _, e := range r.Evidence {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}

// sysVersion is the retained $SYS/broker/version of the reference broker,
// as captured from the pinned Eclipse image (testdata).
func sysVersion(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/sys-broker-version.txt")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestInfo(t *testing.T) {
	i := New().Info()
	if i.Protocol != core.ProtocolMQTT || i.Network != core.TCP || i.Intrusiveness != core.Passive || len(i.Ports) != 2 {
		t.Fatalf("%+v", i)
	}
	if !WellKnown(1883) || !WellKnown(8883) || WellKnown(1884) {
		t.Fatal("WellKnown")
	}
}

func TestDetectAccepted(t *testing.T) {
	f := &fake{connack: always(connack4(0, 0)), ping: true}
	r := run(t, f.target(t), detect)
	if !r.Matched || r.Confidence != core.ConfidenceCertain || r.Variant != "MQTT 3.1.1" {
		t.Fatalf("%v %v", r, r.Evidence)
	}
	if r.Fingerprint.Signature != "connack=0;level=3.1.1;ping=resp" {
		t.Fatalf("signature %q", r.Fingerprint.Signature)
	}
	if got := f.wait(3); string(got) != string([]byte{TypeConnect, TypePingreq, TypeDisconnect}) {
		t.Fatalf("packets %v", got)
	}
	if len(r.Exchanges) == 0 {
		t.Fatal("no trace")
	}
}

func TestDetectNoPingresp(t *testing.T) {
	f := &fake{connack: always(connack4(0, 0))}
	target := f.target(t)
	target.Timeout = 300 * time.Millisecond
	r := run(t, target, detect)
	if !r.Matched || r.Confidence != core.ConfidenceHigh {
		t.Fatalf("%v", r)
	}
}

func TestDetectRefusals(t *testing.T) {
	for rc, want := range map[byte]string{1: "unacceptable protocol version", 2: "identifier rejected", 3: "server unavailable", 4: "bad user name", 5: "not authorized"} {
		f := &fake{connack: always(connack4(0, rc))}
		r := run(t, f.target(t), detect)
		if !r.Matched || r.Confidence != core.ConfidenceHigh || !strings.Contains(r.Details, want) {
			t.Fatalf("rc %d: %v", rc, r)
		}
		if (rc == 4 || rc == 5) != hasEvidence(r, "requires authentication") {
			t.Fatalf("rc %d: evidence %v", rc, r.Evidence)
		}
		if rc == 1 && r.Variant != "" {
			t.Fatalf("version refusal variant %q", r.Variant)
		}
	}
}

func TestDetectV5OnlyBrokerRefusesV4(t *testing.T) {
	f := &fake{connack: always(connack5(0, 0x84))}
	r := run(t, f.target(t), detect)
	if !r.Matched || r.Confidence != core.ConfidenceHigh || r.Variant != "MQTT 5.0" {
		t.Fatalf("%v %v", r, r.Evidence)
	}
}

func TestDetectRejectsLookAlikes(t *testing.T) {
	cases := map[string][]byte{
		"http":         []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"),
		"ssh":          []byte("SSH-2.0-OpenSSH_9.6\r\n"),
		"random":       {0x7a, 0x01, 0x99, 0x00, 0x13},
		"remlen-3":     {0x20, 0x03, 0x00, 0x00},
		"remlen-1":     {0x20, 0x01, 0x00},
		"remlen-0":     {0x20, 0x00},
		"bad-flags":    {0x21, 0x02, 0x00, 0x00},
		"reserved-ack": {0x20, 0x02, 0x02, 0x00},
		"sp-refused":   {0x20, 0x02, 0x01, 0x05},
		"rc-6":         {0x20, 0x02, 0x00, 0x06},
		"v5-success":   connack5(0, 0x00),
		"varint-5":     {0x20, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F},
		"huge":         {0x30, 0xFF, 0xFF, 0xFF, 0x7F},
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			target := testsrv.TCP(t, testsrv.Script(reply))
			target.Timeout = 300 * time.Millisecond
			r := run(t, target, detect)
			if r.Matched {
				t.Fatalf("%v %v", r, r.Evidence)
			}
		})
	}
}

func TestDetectEcho(t *testing.T) {
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) { return req, false })
	target.Timeout = 300 * time.Millisecond
	r := run(t, target, detect)
	if r.Matched || r.Confidence != 0 {
		t.Fatalf("%v %v", r, r.Evidence)
	}
}

func TestDetectPublishBeforeConnack(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script(append(publish(4, "a/b", []byte("x"), 0), connack4(0, 0)...)))
	r := run(t, target, detect)
	if r.Matched || r.Confidence != core.ConfidenceLow || !hasEvidence(r, "PUBLISH before CONNACK") {
		t.Fatalf("%v %v", r, r.Evidence)
	}
}

func TestDetectBadConnackHint(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script([]byte{0x20, 0x02, 0x00, 0x09}))
	r := run(t, target, detect)
	if r.Matched || r.Confidence != core.ConfidenceLow {
		t.Fatalf("%v %v", r, r.Evidence)
	}
}

func TestDetectExtraBytes(t *testing.T) {
	// A CONNACK followed by junk: the CONNACK stands, the junk fails the
	// PINGRESP cross-check.
	f := &fake{connack: always(append(connack4(0, 0), 0xFF, 0x00))}
	target := f.target(t)
	target.Timeout = 300 * time.Millisecond
	r := run(t, target, detect)
	if !r.Matched || r.Confidence != core.ConfidenceHigh {
		t.Fatalf("%v %v", r, r.Evidence)
	}
}

func TestDetectSlowPartialWrites(t *testing.T) {
	target := testsrv.Raw(t, func(c net.Conn) {
		buf := make([]byte, 256)
		if _, err := c.Read(buf); err != nil {
			return
		}
		for _, b := range connack4(0, 0) {
			if _, err := c.Write([]byte{b}); err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		if _, err := c.Read(buf); err != nil {
			return
		}
		_, _ = c.Write([]byte{0xD0})
		time.Sleep(20 * time.Millisecond)
		_, _ = c.Write([]byte{0x00})
		_, _ = c.Read(buf)
	})
	r := run(t, target, detect)
	if r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v %v", r, r.Evidence)
	}
}

func TestDetectSilent(t *testing.T) {
	target := testsrv.Raw(t, func(c net.Conn) { _, _ = c.Read(make([]byte, 64)); time.Sleep(time.Second) })
	target.Timeout = 200 * time.Millisecond
	r, err := New().Detect(context.Background(), target, detect)
	fuzzkit.Check(t, proto, r, err)
	var te *core.TimeoutError
	if !errors.As(err, &te) || r.Matched {
		t.Fatalf("%v %v", r, err)
	}
}

func TestDetectClosedPort(t *testing.T) {
	r, err := New().Detect(context.Background(), testsrv.Closed(t), detect)
	fuzzkit.Check(t, proto, r, err)
	if err == nil {
		t.Fatal("want a connection error")
	}
}

func TestDetectClosesWithoutReply(t *testing.T) {
	// Not a well-known port, detect mode: one attempt, NoMatch.
	f := &fake{}
	r := run(t, f.target(t), detect)
	if r.Matched || len(f.wait(1)) != 1 {
		t.Fatalf("%v %v", r, f.types())
	}
}

func TestDetectCancelled(t *testing.T) {
	f := &fake{connack: always(connack4(0, 0)), ping: true}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := New().Detect(ctx, f.target(t), detect)
	if err == nil || r.Matched {
		t.Fatalf("%v %v", r, err)
	}
}

// v5Props are the CONNACK properties of a broker.
var v5Props = []byte{
	0x12, 0x00, 0x04, 'a', 'b', '\x01', 'c', // assigned client id with a control byte
	0x13, 0x00, 0x3C, // server keep alive 60
	0x27, 0x00, 0x1E, 0x84, 0x80, // maximum packet size
	0x21, 0x00, 0x14, // receive maximum 20
	0x25, 0x01, 0x28, 0x01, 0x2A, 0x00, // retain, wildcard, shared
	0x22, 0x00, 0x0A, // topic alias maximum
	0x1A, 0x00, 0x02, 'r', '/', // response information
	0x1C, 0x00, 0x03, 'b', ':', '1', // server reference
	0x1F, 0x00, 0x02, 'o', 'k', // reason string
	0x26, 0x00, 0x01, 'k', 0x00, 0x01, 'v', // user property
	0x16, 0x00, 0x01, 0xFF, // authentication data
	0x15, 0x00, 0x01, 'm', // authentication method
}

func TestIdentifyV5(t *testing.T) {
	f := &fake{connack: always(connack5(0, 0, v5Props...)), ping: true, unsuback: true,
		after: publish(5, "$SYS/broker/version", sysVersion(t), 0x01)}
	r := run(t, f.target(t), identify)
	if !r.Matched || r.Confidence != core.ConfidenceCertain || r.Variant != "MQTT 5.0" {
		t.Fatalf("%v %v", r, r.Evidence)
	}
	id := r.Identity
	if product, _, _ := strings.Cut(string(sysVersion(t)), " "); id.Product != product || id.Version != "2.1.2" {
		t.Fatalf("identity %+v", id)
	}
	want := map[string]string{
		"protocolVersion": "5.0", "sessionPresent": "false", "returnCode": "0 (success)",
		"assignedClientId": "abc", "serverKeepAlive": "60", "maximumPacketSize": "2000000",
		"receiveMaximum": "20", "retainAvailable": "1", "wildcardSubscriptionAvailable": "1",
		"sharedSubscriptionAvailable": "0", "topicAliasMaximum": "10", "responseInformation": "r/",
		"serverReference": "b:1", "reasonString": "ok", "authenticationMethod": "m",
		"brokerVersion": string(sysVersion(t)),
	}
	for k, v := range want {
		if id.Attributes[k] != v {
			t.Errorf("%s = %q, want %q", k, id.Attributes[k], v)
		}
	}
	if got := f.wait(5); string(got) != string([]byte{TypeConnect, TypePingreq, TypeSubscribe, TypeUnsubscribe, TypeDisconnect}) {
		t.Fatalf("packets %v", got)
	}
}

func TestIdentifyEMQXVersion(t *testing.T) {
	f := &fake{connack: always(connack5(0, 0)), ping: true,
		after: publish(5, "$SYS/brokers/emqx@127.0.0.1/version", []byte("5.8.0"), 0)}
	r := run(t, f.target(t), identify)
	if r.Identity.Product != "EMQX" || r.Identity.Version != "5.8.0" {
		t.Fatalf("%+v", r.Identity)
	}
}

func TestIdentifyPlainVersion(t *testing.T) {
	f := &fake{connack: always(connack5(0, 0)), ping: true,
		after: append(publish(5, "other/topic", []byte("x"), 0), publish(5, "$SYS/broker/version", []byte("1.0"), 0x02)...)}
	r := run(t, f.target(t), identify)
	if r.Identity.Product != "" || r.Identity.Version != "1.0" {
		t.Fatalf("%+v", r.Identity)
	}
}

func TestIdentifySysRefused(t *testing.T) {
	f := &fake{connack: always(connack5(1, 0)), ping: true, suback: func(l byte, id uint16, n int) []byte {
		return suback(l, id, 0x87, 0x80)
	}}
	r := run(t, f.target(t), identify)
	if !hasEvidence(r, "$SYS subscription refused") || r.Identity.Attributes["sessionPresent"] != "true" {
		t.Fatalf("%v %+v", r.Evidence, r.Identity)
	}
}

func TestIdentifySysBadSuback(t *testing.T) {
	f := &fake{connack: always(connack5(0, 0)), ping: true, suback: func(l byte, id uint16, n int) []byte {
		return suback(l, id+1, 0, 0) // wrong packet identifier
	}}
	target := f.target(t)
	target.Timeout = 300 * time.Millisecond
	r := run(t, target, identify)
	if hasEvidence(r, "SUBACK") {
		t.Fatalf("%v", r.Evidence)
	}
}

func TestIdentifySysSilentAndMalformed(t *testing.T) {
	f := &fake{connack: always(connack5(0, 0)), ping: true, silentSub: true}
	target := f.target(t)
	target.Timeout = 200 * time.Millisecond
	if r := run(t, target, identify); r.Identity.Attributes["brokerVersion"] != "" {
		t.Fatalf("%+v", r.Identity)
	}
	g := &fake{connack: always(connack5(0, 0)), ping: true, after: []byte{0x00, 0x00}}
	if r := run(t, g.target(t), identify); r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v", r)
	}
}

func TestIdentifyWithoutReadOnly(t *testing.T) {
	f := &fake{connack: always(connack5(0, 0)), ping: true}
	r := run(t, f.target(t), core.Options{Mode: core.ModeIdentify})
	if !r.Matched {
		t.Fatalf("%v", r)
	}
	for _, typ := range f.types() {
		if typ == TypeSubscribe {
			t.Fatal("subscribed without read-only")
		}
	}
}

func TestIdentifyFallsBackTo311(t *testing.T) {
	// A 3.1.1 broker refuses MQTT 5 with return code 1, then accepts 3.1.1.
	f := &fake{connack: byLevel(connack4(0, 1), connack4(0, 0)), ping: true, unsuback: true}
	r := run(t, f.target(t), identify)
	if !r.Matched || r.Confidence != core.ConfidenceCertain || r.Variant != "MQTT 3.1.1" {
		t.Fatalf("%v %v", r, r.Evidence)
	}
	if r.Identity.Attributes["mqtt50"] != "refused: unacceptable protocol version" || r.Identity.Attributes["protocolVersion"] != "3.1.1" {
		t.Fatalf("%+v", r.Identity)
	}
	if !hasEvidence(r, "MQTT 5.0 refused") {
		t.Fatalf("%v", r.Evidence)
	}
}

func TestIdentifyFallbackFails(t *testing.T) {
	// MQTT 5 refused, then 3.1.1 closed: the refusal is the result.
	f := &fake{connack: byLevel(connack4(0, 1), nil)}
	r := run(t, f.target(t), identify)
	if !r.Matched || r.Confidence != core.ConfidenceHigh || r.Identity.Attributes["protocolVersion"] != "3.1.1" {
		t.Fatalf("%v %+v", r, r.Identity)
	}
}

func TestIdentifyClosedOnV5(t *testing.T) {
	f := &fake{connack: byLevel(nil, connack4(0, 0)), ping: true}
	r := run(t, f.target(t), identify)
	if !r.Matched || r.Variant != "MQTT 3.1.1" || !hasEvidence(r, "closed on an MQTT 5.0 CONNECT") {
		t.Fatalf("%v %v", r, r.Evidence)
	}
}

func TestIdentifyClosedTwice(t *testing.T) {
	f := &fake{}
	r := run(t, f.target(t), identify)
	if r.Matched || len(f.wait(2)) != 2 {
		t.Fatalf("%v %v", r, f.types())
	}
}

func TestIdentifyRetryDialFails(t *testing.T) {
	// The first connection closes; the listener is gone for the second.
	var ln net.Listener
	var err error
	if ln, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = ln.Close()
		_, _ = c.Read(make([]byte, 64))
		_ = c.Close()
	}()
	addr := ln.Addr().(*net.TCPAddr)
	target := core.Target{Host: "127.0.0.1", Port: addr.Port, Timeout: 500 * time.Millisecond}
	r, err := New().Detect(context.Background(), target, identify)
	fuzzkit.Check(t, proto, r, err)
	if err == nil {
		t.Fatalf("want a dial error: %v", r)
	}
}

func TestIdentifyAuthRefusedV5(t *testing.T) {
	f := &fake{connack: always(connack5(0, 0x87, 0x1F, 0x00, 0x03, 'n', 'o', '!'))}
	r := run(t, f.target(t), identify)
	if !r.Matched || !hasEvidence(r, "requires authentication") || r.Identity.Attributes["reasonString"] != "no!" {
		t.Fatalf("%v %v %+v", r, r.Evidence, r.Identity)
	}
}

func TestClientIDAndOverride(t *testing.T) {
	a, b := ClientID(), ClientID()
	if a == b || len(a) != 20 || !strings.HasPrefix(a, "otfp") {
		t.Fatalf("%q %q", a, b)
	}
	var got string
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) {
		got = string(req)
		return connack4(0, 5), true
	})
	fp := &Fingerprinter{ClientID: "fixed-id", Window: time.Millisecond}
	if _, err := fp.Detect(context.Background(), target, detect); err != nil || !strings.HasSuffix(got, "fixed-id") {
		t.Fatalf("%v %q", err, got)
	}
}

func TestTLS(t *testing.T) {
	cert := selfSigned(t)
	f := &fake{connack: always(connack4(0, 0)), ping: true}
	target := testsrv.Raw(t, func(c net.Conn) {
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		if tc.Handshake() != nil {
			return
		}
		f.serve(tc)
	})
	target.TLS = &tls.Config{InsecureSkipVerify: true} // a test server with a throwaway certificate
	r := run(t, target, detect)
	if r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v", r)
	}
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "broker"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
