// SPDX-License-Identifier: MIT

package wire_test

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
	"strconv"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/wire"
)

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsEcho serves TLS on loopback and echoes one framed message.
func tlsEcho(t *testing.T, serverName *string) core.Target {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSigned(t)},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			if serverName != nil {
				*serverName = h.ServerName
			}
			return nil, nil
		},
	})
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
				defer c.Close()
				buf := make([]byte, 64)
				n, err := c.Read(buf)
				if err == nil {
					_, _ = c.Write(buf[:n])
				}
			}()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	return core.Target{Host: "127.0.0.1", Port: p, Timeout: 2 * time.Second, TLS: &tls.Config{InsecureSkipVerify: true}}
}

// Fingerprinters probe over TLS when Target.TLS is set (Modbus/TCP
// Security, IEC 62351-3, wss://, https://).
func TestTLSSession(t *testing.T) {
	target := tlsEcho(t, nil)
	s, err := wire.Dial(context.Background(), core.ProtocolModbus, target, core.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, ok := s.Conn().(*tls.Conn); !ok {
		t.Fatalf("connection is %T, want *tls.Conn", s.Conn())
	}
	resp, err := s.RoundTrip("x", []byte{0, 2, 'o', 'k'}, lenFramer, 64)
	if err != nil || string(resp[2:]) != "ok" {
		t.Fatalf("%q %v", resp, err)
	}
}

// For a host name, the SNI defaults to it; for an IP address none is sent.
func TestTLSServerName(t *testing.T) {
	var sni string
	target := tlsEcho(t, &sni)
	target.Host = "localhost"
	s, err := wire.Dial(context.Background(), core.ProtocolModbus, target, core.Options{})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if sni != "localhost" {
		t.Fatalf("SNI %q, want localhost", sni)
	}
	if target.TLS.ServerName != "" {
		t.Fatal("the caller's TLS config must not be modified")
	}
}

func TestTLSFailures(t *testing.T) {
	// A plain-TCP server that answers the ClientHello with garbage.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			_ = c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	target := core.Target{Host: "127.0.0.1", Port: p, Timeout: time.Second, TLS: &tls.Config{InsecureSkipVerify: true}}
	_, err := wire.Dial(context.Background(), core.ProtocolModbus, target, core.Options{})
	var de *core.DetectError
	if !errors.As(err, &de) || de.Op != "tls" {
		t.Fatalf("want a tls DetectError, got %v", err)
	}

	// A server that accepts and never answers the handshake.
	silent, _ := net.Listen("tcp", "127.0.0.1:0")
	defer silent.Close()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	_, port, _ = net.SplitHostPort(silent.Addr().String())
	target.Port, _ = strconv.Atoi(port)
	target.Timeout = 200 * time.Millisecond
	_, err = wire.Dial(context.Background(), core.ProtocolModbus, target, core.Options{})
	var te *core.TimeoutError
	if !errors.As(err, &te) || te.Op != "tls" {
		t.Fatalf("want a tls TimeoutError, got %v", err)
	}
}
