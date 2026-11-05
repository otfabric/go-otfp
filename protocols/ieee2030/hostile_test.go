// SPDX-License-Identifier: MIT

package ieee2030

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

const dcapReply = "HTTP/1.1 200 OK\r\nContent-Type: application/sep+xml\r\nContent-Length: 96\r\nConnection: close\r\n\r\n" +
	`<DeviceCapability xmlns="urn:ieee:std:2030.5:ns" href="/dcap" pollRate="900"><TimeLink href="/tm"/></DeviceCapability>`

// readRecord reads one TLS record (the ClientHello) from c.
func readRecord(c net.Conn) ([]byte, error) {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	h := make([]byte, 5)
	if _, err := io.ReadFull(c, h); err != nil {
		return nil, err
	}
	body := make([]byte, int(h[3])<<8|int(h[4]))
	if _, err := io.ReadFull(c, body); err != nil {
		return nil, err
	}
	return append(h, body...), nil
}

// ccm8Server answers the ClientHello with a CCM_8 flight, as GridAPPS-D.
func ccm8Server(flight []byte) func(net.Conn) {
	return func(c net.Conn) {
		if _, err := readRecord(c); err != nil {
			return
		}
		_, _ = c.Write(record(recHandshake, flight))
		_, _ = io.Copy(io.Discard, c) // wait for the client to close
	}
}

// dcapServer is a Go TLS server behind cfg's fault that answers GET /dcap
// with a DeviceCapability, recording each request line in got.
func dcapServer(t testing.TB, cfg chaos.Config, tcfg *tls.Config, got *chaos.Recorder) core.Target {
	t.Helper()
	ln := chaos.NewListener(t, cfg)
	tln := tls.NewListener(ln, tcfg)
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			c, err := tln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				if got != nil {
					got.Add([]byte(req.Method + " " + req.URL.Path))
				}
				_, _ = c.Write([]byte(dcapReply))
			})
		}
	})
	return chaos.Target(t, ln.Addr(), core.TCP)
}

func TestChaos(t *testing.T) {
	flight := ccm8Flight(t, true)
	t.Run("ccm8", chaos.Suite{
		FP:  New(),
		TCP: func(t testing.TB, cfg chaos.Config) core.Target { return chaos.Raw(t, cfg, ccm8Server(flight)) },
	}.Run)
	tcfg := &tls.Config{Certificates: []tls.Certificate{ecdsaCert(t)}, MinVersion: tls.VersionTLS12}
	t.Run("dcap", chaos.Suite{
		FP:  New(),
		TCP: func(t testing.TB, cfg chaos.Config) core.Target { return dcapServer(t, cfg, tcfg, nil) },
	}.Run)
}

// The safety contract: a ClientHello on the raw probe, and after a
// completed handshake one GET /dcap. Never a POST, PUT or DELETE, and
// nothing else on the wire.
func TestSafetyContract(t *testing.T) {
	tcfg := &tls.Config{Certificates: []tls.Certificate{ecdsaCert(t)}, MinVersion: tls.VersionTLS12}
	for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
		for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
			// The raw probe: record the whole stream of the connection.
			var mu sync.Mutex
			var streams [][]byte
			target := testsrv.Raw(t, func(c net.Conn) {
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				hello, err := readRecord(c)
				if err != nil {
					return
				}
				_, _ = c.Write(record(recHandshake, ccm8Flight(t, true)))
				rest, _ := io.ReadAll(c)
				mu.Lock()
				streams = append(streams, append(hello, rest...))
				mu.Unlock()
			})
			r, err := New().Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: level})
			if err != nil || !r.Matched {
				t.Fatalf("%v %v", r, err)
			}
			time.Sleep(20 * time.Millisecond) // let the server record the close
			mu.Lock()
			if len(streams) != 1 {
				t.Fatalf("%d connections to a CCM_8 server, want 1", len(streams))
			}
			s := streams[0]
			mu.Unlock()
			if len(s) < 6 || s[0] != recHandshake || s[5] != 1 || len(s) != 5+(int(s[3])<<8|int(s[4])) {
				t.Fatalf("%s/%s: the raw probe sent more than one ClientHello record: % x", mode, level, s[:min(len(s), 16)])
			}

			// A completed handshake: only GET /dcap.
			rec := &chaos.Recorder{}
			tg := dcapServer(t, chaos.Config{}, tcfg, rec)
			if r, err := New().Detect(context.Background(), tg, core.Options{Mode: mode, MaxIntrusiveness: level}); err != nil || !r.Matched {
				t.Fatalf("%v %v", r, err)
			}
			reqs := rec.Requests()
			if len(reqs) != 1 || string(reqs[0]) != "GET /dcap" {
				t.Fatalf("%s/%s: requests %q, want one GET /dcap", mode, level, reqs)
			}
		}
	}
}

// streamer answers the ClientHello with an endless stream of handshake
// records that never complete the flight: each an empty CertificateRequest.
func streamer(c net.Conn) {
	if _, err := readRecord(c); err != nil {
		return
	}
	rec := record(recHandshake, hsMsg(hsCertRequest, nil))
	for {
		if _, err := c.Write(rec); err != nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// A server that streams handshake records forever, each within the read
// timeout, must not hold the probe: the flight is bounded.
func TestEndlessFlightBounded(t *testing.T) {
	target := testsrv.Raw(t, streamer)
	target.Timeout = 200 * time.Millisecond
	start := time.Now()
	r, err := New().Detect(context.Background(), target, core.Options{})
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Detect took %v against an endless flight", d)
	}
	if r.Matched {
		t.Fatalf("matched an endless flight: %v %v", r, err)
	}
}

// One handshake message that announces 16 MiB and is fed record by record
// must not be reassembled without limit.
func TestHugeHandshakeMessageBounded(t *testing.T) {
	target := testsrv.Raw(t, func(c net.Conn) {
		if _, err := readRecord(c); err != nil {
			return
		}
		first := append([]byte{hsCertificate, 0xFF, 0xFF, 0xFF}, bytes.Repeat([]byte{0}, 16000)...)
		if _, err := c.Write(record(recHandshake, first)); err != nil {
			return
		}
		chunk := record(recHandshake, bytes.Repeat([]byte{0}, 16000))
		for {
			if _, err := c.Write(chunk); err != nil {
				return
			}
		}
	})
	target.Timeout = 200 * time.Millisecond
	start := time.Now()
	r, _ := New().Detect(context.Background(), target, core.Options{})
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Detect took %v reassembling a 16 MiB message", d)
	}
	if r.Matched {
		t.Fatalf("%v", r)
	}
}

// A flight cut after a complete ServerHello choosing CCM_8 but before
// ServerHelloDone is evidence of a CCM_8 server, but not a whole one.
func TestCutFlight(t *testing.T) {
	flight := ccm8Flight(t, true)
	target := testsrv.Raw(t, func(c net.Conn) {
		if _, err := readRecord(c); err != nil {
			return
		}
		_, _ = c.Write(record(recHandshake, flight)[:5+4+38+10]) // ServerHello and a little more
	})
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || r.Confidence >= core.ConfidenceHigh {
		t.Fatalf("cut CCM_8 flight: %v %v", r, err)
	}
	if !strings.Contains(strings.Join(r.Evidence, ";"), "CCM_8") {
		t.Fatalf("evidence %v", r.Evidence)
	}
}
