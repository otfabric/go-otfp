// SPDX-License-Identifier: MIT

package ocpp

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// httpReply reads one request line + headers from c and writes resp.
func httpReply(resp string) func(net.Conn) {
	return func(c net.Conn) {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		_, _ = c.Write([]byte(resp))
	}
}

func TestDetectUpgrade(t *testing.T) {
	target := testsrv.Raw(t, httpReply("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: ocpp2.0.1\r\n\r\n"))
	r, err := New().Detect(context.Background(), target, core.Options{Trace: true})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain || r.Variant != "OCPP 2.0.1" {
		t.Fatalf("%v %v", r, err)
	}
	if r.Fingerprint.Signature != "subprotocol=ocpp2.0.1" || r.Identity.Attributes["ocppVersion"] != "2.0.1" {
		t.Fatalf("fp %v id %v", r.Fingerprint, r.Identity)
	}
}

func TestRealmAndNoSubprotocol(t *testing.T) {
	cases := map[string]struct {
		resp string
		conf core.Confidence
	}{
		"realm":    {"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"OCPP\", charset=\"UTF-8\"\r\nContent-Length: 0\r\n\r\n", core.ConfidenceHigh},
		"no subpr": {"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", core.ConfidenceMedium},
		"404":      {"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", core.ConfidenceLow},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			target := testsrv.Raw(t, httpReply(c.resp))
			r, err := New().Detect(context.Background(), target, core.Options{})
			if err != nil || r.Confidence != c.conf {
				t.Fatalf("%v %v", r, err)
			}
		})
	}
}

func TestProbeOffersAllVersions(t *testing.T) {
	var got string
	target := testsrv.Raw(t, func(c net.Conn) {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 2048)
		n, _ := c.Read(buf)
		got = string(buf[:n])
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
	})
	_, _ = New().Detect(context.Background(), target, core.Options{})
	if !strings.Contains(got, "Sec-WebSocket-Protocol: ocpp2.1, ocpp2.0.1, ocpp1.6") || !strings.Contains(got, "Upgrade: websocket") {
		t.Fatalf("probe headers:\n%s", got)
	}
	if !strings.HasPrefix(got, "GET /ocpp/OTFP-") {
		t.Fatalf("path: %s", got[:40])
	}
}

func TestInfo(t *testing.T) {
	if New().Info().Protocol != core.ProtocolOCPP || New().Info().Network != core.TCP {
		t.Fatal("info")
	}
}

func TestOtherBranches(t *testing.T) {
	cases := map[string]struct {
		resp string
		conf core.Confidence
		vari string
	}{
		"401 other realm": {"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer\r\nContent-Length: 0\r\n\r\n", core.ConfidenceLow, ""},
		"ocpp1.6":         {"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Protocol: ocpp1.6\r\n\r\n", core.ConfidenceCertain, "OCPP 1.6"},
		"ocpp2.1":         {"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Protocol: ocpp2.1\r\n\r\n", core.ConfidenceCertain, "OCPP 2.1"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			target := testsrv.Raw(t, httpReply(c.resp))
			r, err := New().Detect(context.Background(), target, core.Options{})
			if err != nil || r.Confidence != c.conf || r.Variant != c.vari {
				t.Fatalf("%v %v", r, err)
			}
		})
	}
	if versionName("ocpp9") != "" {
		t.Fatal("unknown subprotocol")
	}
	if hostHeader(core.Target{Host: "csms.example", Port: 443}) != "csms.example" || hostHeader(core.Target{Host: "h", Port: 9000}) != "h:9000" {
		t.Fatal("host header")
	}
	silent := testsrv.TCP(t, testsrv.Script())
	silent.Timeout = 200 * time.Millisecond
	if _, err := New().Detect(context.Background(), silent, core.Options{}); err == nil {
		t.Fatal("silent CSMS is a timeout")
	}
	if _, err := New().Detect(context.Background(), testsrv.Closed(t), core.Options{}); err == nil {
		t.Fatal("closed")
	}
	if NewWithConfig(Config{Path: "/x"}).path != "/x" {
		t.Fatal("config")
	}
}
