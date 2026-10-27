// SPDX-License-Identifier: MIT

package ieee2030

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

func ecdsaCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "2030.5 test server", Organization: []string{"OT Fabric"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsServer runs a TLS listener with the given config and optional HTTP
// reply once the handshake completes.
func tlsServer(t *testing.T, cfg *tls.Config, reply string) core.Target {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close() //nolint:errcheck
				if err := c.(*tls.Conn).Handshake(); err != nil {
					return
				}
				if reply != "" {
					buf := make([]byte, 1024)
					_ = c.SetReadDeadline(time.Now().Add(time.Second))
					_, _ = c.Read(buf)
					_, _ = c.Write([]byte(reply))
				}
			}()
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	return core.Target{Host: host, Port: p, Timeout: 2 * time.Second}
}

func TestMutualTLSECDSA(t *testing.T) {
	cfg := &tls.Config{Certificates: []tls.Certificate{ecdsaCert(t)}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
	tg := tlsServer(t, cfg, "")
	r, err := New().Detect(context.Background(), tg, core.Options{})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceHigh || r.Fingerprint.Signature != "tls=mtls-ecdsa" {
		t.Fatalf("%v %v %v", r, err, r.Fingerprint)
	}
}

func TestDcapCertain(t *testing.T) {
	cfg := &tls.Config{Certificates: []tls.Certificate{ecdsaCert(t)}, MinVersion: tls.VersionTLS12}
	dcap := "HTTP/1.1 200 OK\r\nContent-Type: application/sep+xml\r\nContent-Length: 96\r\nConnection: close\r\n\r\n" +
		`<DeviceCapability xmlns="urn:ieee:std:2030.5:ns" href="/dcap" pollRate="900"><TimeLink href="/tm"/></DeviceCapability>`
	tg := tlsServer(t, cfg, dcap)
	r, err := New().Detect(context.Background(), tg, core.Options{Trace: true})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain || r.Variant != "IEEE 2030.5" {
		t.Fatalf("%v %v", r, err)
	}
	if r.Identity.Attributes["pollRate"] != "900" {
		t.Fatalf("identity %+v", r.Identity)
	}
}

func TestPlainTCPNotMatched(t *testing.T) {
	// A non-TLS service: the TLS handshake fails with no 2030.5 shape.
	tg := testsrv.TCP(t, testsrv.Script([]byte("220 smtp\r\n")))
	tg.Timeout = 500 * time.Millisecond
	r, _ := New().Detect(context.Background(), tg, core.Options{})
	if r.Matched {
		t.Fatalf("%v", r)
	}
}

func TestRefused(t *testing.T) {
	tg := testsrv.Closed(t)
	_, err := New().Detect(context.Background(), tg, core.Options{})
	var ce *core.ConnectionError
	if err == nil {
		t.Fatal("want connection error")
	}
	_ = ce
}
