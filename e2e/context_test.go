// SPDX-License-Identifier: MIT

package e2e_test

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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// hookContext is a context that is never cancelled and counts the functions
// registered on it with context.AfterFunc (and by the contexts derived from
// it), so that a test can tell, without waiting, whether a scan released
// everything it put on its caller's context.
type hookContext struct {
	mu    sync.Mutex
	done  chan struct{}
	next  int
	hooks map[int]func()
}

func newHookContext() *hookContext {
	return &hookContext{done: make(chan struct{}), hooks: map[int]func(){}}
}

func (c *hookContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *hookContext) Done() <-chan struct{}       { return c.done }
func (c *hookContext) Err() error                  { return nil }
func (c *hookContext) Value(any) any               { return nil }

// AfterFunc is what context.AfterFunc and the derived contexts of the
// standard library call to register on a context of another package.
func (c *hookContext) AfterFunc(f func()) (stop func() bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.next
	c.next++
	c.hooks[id] = f
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		_, registered := c.hooks[id]
		delete(c.hooks, id)
		return registered
	}
}

func (c *hookContext) registered() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.hooks)
}

// dcapServer is a TLS server with an ECDSA certificate that asks for no
// client certificate and answers one request with an IEEE 2030.5
// DeviceCapability: the IEEE 2030.5 fingerprinter completes a crypto/tls
// handshake with it and reads /dcap on a second connection.
func dcapServer(t *testing.T) core.Target {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "e2e"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}
	const body = `<DeviceCapability xmlns="urn:ieee:std:2030.5:ns" href="/dcap" pollRate="900"><TimeLink href="/tm"/></DeviceCapability>`
	reply := "HTTP/1.1 200 OK\r\nContent-Type: application/sep+xml\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer c.Close() //nolint:errcheck
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				if err := c.(*tls.Conn).Handshake(); err != nil {
					return
				}
				buf := make([]byte, 2048)
				if _, err := c.Read(buf); err != nil {
					return
				}
				_, _ = c.Write([]byte(reply))
			})
		}
	})
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	return core.Target{Host: host, Port: p}
}

// Nothing of a scan outlives it (lifecycle matrix, L14): when Scan returns,
// every function the scan registered on the caller's context is released,
// whatever the endpoint speaks, so a long-lived context does not grow with
// the scans made under it. The IEEE 2030.5 /dcap read, which wraps a
// connection it upgraded to TLS itself, is one of the cases.
func TestScanLeavesNothingOnTheCallersContext(t *testing.T) {
	targets := map[string]core.Target{"ieee2030.5-dcap": dcapServer(t)}
	for p, h := range speakers() {
		targets[p.Slug()] = testsrv.TCP(t, h)
	}
	for name, sp := range udpSpeakers() {
		targets[name+"-udp"] = testsrv.UDP(t, sp.h)
	}
	for name, target := range targets {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var dialled atomic.Int64
			cfg := core.DefaultEngineConfig()
			cfg.Mode, cfg.EarlyStop = core.ModeIdentify, false
			cfg.Dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialled.Add(1)
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			}
			target.Timeout = 300 * time.Millisecond
			ctx := newHookContext()
			report, err := otfp.NewEngine(cfg).Scan(ctx, target)
			if err != nil {
				t.Fatal(err)
			}
			if name == "ieee2030.5-dcap" && (report.Best.Protocol != core.ProtocolIEEE2030_5 || report.Best.Confidence != core.ConfidenceCertain) {
				t.Fatalf("best = %v, want a certain IEEE 2030.5 match from /dcap", report.Best)
			}
			if dialled.Load() == 0 {
				t.Fatal("the scan dialled no connection")
			}
			if n := ctx.registered(); n != 0 {
				t.Errorf("%d function(s) still registered on the caller's context after Scan returned, want 0", n)
			}
		})
	}
}
