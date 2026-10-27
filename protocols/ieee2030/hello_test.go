// SPDX-License-Identifier: MIT

package ieee2030

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

func hsMsg(typ byte, body []byte) []byte {
	return append([]byte{typ, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func record(typ byte, body []byte) []byte {
	return append([]byte{typ, 0x03, 0x03, byte(len(body) >> 8), byte(len(body))}, body...)
}

// ccm8Flight is the TLS 1.2 flight of a server that chose CCM_8, presented
// an ECDSA certificate and requested one: an IEEE 2030.5 server such as
// GridAPPS-D, which no Go TLS client can complete a handshake with.
func ccm8Flight(t *testing.T, certRequest bool) []byte {
	t.Helper()
	sh := append([]byte{0x03, 0x03}, make([]byte, 32)...)
	sh = append(sh, 0)                                // session id
	sh = binary.BigEndian.AppendUint16(sh, suiteCCM8) // cipher suite
	sh = append(sh, 0)                                // compression
	der := ecdsaCert(t).Certificate[0]
	certs := append([]byte{byte(len(der) >> 16), byte(len(der) >> 8), byte(len(der))}, der...)
	cert := append([]byte{byte(len(certs) >> 16), byte(len(certs) >> 8), byte(len(certs))}, certs...)
	hs := append(hsMsg(hsServerHello, sh), hsMsg(hsCertificate, cert)...)
	if certRequest {
		hs = append(hs, hsMsg(hsCertRequest, []byte{1, 0x40, 0, 2, 4, 3, 0, 0})...)
	}
	return append(hs, hsMsg(hsHelloDone, nil)...)
}

func TestCCM8Server(t *testing.T) {
	hs := ccm8Flight(t, true)
	// The flight split over two records, the second message across them.
	cut := 60
	target := testsrv.TCP(t, testsrv.Script(append(record(recHandshake, hs[:cut]), record(recHandshake, hs[cut:])...)))
	r, err := New().Detect(context.Background(), target, core.Options{Trace: true})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceHigh || r.Fingerprint.Signature != "tls=ccm8" {
		t.Fatalf("%v %v %v", r, err, r.Fingerprint)
	}
	if r.Fingerprint.Metadata["cipherSuite"] != "0xC0AE" || len(r.Evidence) != 3 || r.Identity.Attributes["serverCertSubject"] == "" {
		t.Fatalf("%v %v %+v", r.Fingerprint.Metadata, r.Evidence, r.Identity)
	}
}

func TestClientHello(t *testing.T) {
	ch := clientHello("utility.example")
	if ch[0] != recHandshake || ch[5] != 1 || int(binary.BigEndian.Uint16(ch[3:5])) != len(ch)-5 {
		t.Fatalf("% x", ch[:10])
	}
	if len(clientHello("10.0.0.5")) >= len(ch) {
		t.Fatal("no SNI for an IP address")
	}
}

func TestFlightEdges(t *testing.T) {
	cases := map[string]struct {
		reply []byte
		conf  core.Confidence
	}{
		"alert":         {record(recAlert, []byte{2, 40}), 0},
		"not tls":       {[]byte("HTTP/1.1 400 Bad Request\r\n\r\n"), 0},
		"short hello":   {record(recHandshake, hsMsg(hsServerHello, []byte{3, 3})), 0},
		"ecdsa, no req": {record(recHandshake, ccm8Flight(t, false)[:0]), 0},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			target := testsrv.TCP(t, testsrv.Script(c.reply))
			target.Timeout = 200 * time.Millisecond
			r, _ := New().Detect(context.Background(), target, core.Options{})
			if r.Matched || r.Confidence != c.conf {
				t.Fatalf("%v", r)
			}
		})
	}
	// A truncated record header in the middle of the flight.
	var f flight
	if rest, err := f.parse([]byte{hsServerHello, 0, 0}); err != nil || len(rest) != 3 {
		t.Fatal("incomplete message is kept")
	}
	if recordFramer([]byte{0x17, 3, 3, 0, 1}) != -1 {
		t.Fatal("application data is not a hello flight")
	}
}

func rsaCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestTLSShapes(t *testing.T) {
	plainRSA := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{rsaCert(t)}}, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
	if r, err := New().Detect(context.Background(), plainRSA, core.Options{}); err != nil || r.Matched || r.Confidence != 0 {
		t.Fatalf("plain RSA TLS: %v %v", r, err)
	}
	ecdsaPlain := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{ecdsaCert(t)}}, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
	if r, _ := New().Detect(context.Background(), ecdsaPlain, core.Options{}); r.Matched || r.Confidence != core.ConfidenceLow {
		t.Fatalf("plain ECDSA TLS: %v", r)
	}
	// Requests a certificate (RSA), still lets us in, and answers 403.
	req403 := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{rsaCert(t)}, ClientAuth: tls.RequestClientCert}, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
	r, err := New().Detect(context.Background(), req403, core.Options{})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceHigh || r.Fingerprint.Signature != "tls=mtls;dcap=403" {
		t.Fatalf("mTLS request + 403: %v %v %v", r, err, r.Fingerprint)
	}
	// A server name from the target's TLS config is used for SNI.
	tg := plainRSA
	tg.TLS = &tls.Config{ServerName: "utility.example"}
	if _, err := New().Detect(context.Background(), tg, core.Options{}); err != nil {
		t.Fatal(err)
	}
	// Silent: a timeout.
	silent := testsrv.TCP(t, testsrv.Script())
	silent.Timeout = 200 * time.Millisecond
	if _, err := New().Detect(context.Background(), silent, core.Options{}); err == nil {
		t.Fatal("silent server")
	}
}
