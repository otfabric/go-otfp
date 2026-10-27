// SPDX-License-Identifier: MIT

package httpx_test

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/httpx"
	"github.com/otfabric/go-otfp/internal/testsrv"
	"github.com/otfabric/go-otfp/internal/wire"
)

func TestRequestResponse(t *testing.T) {
	var got string
	target := testsrv.Raw(t, func(c net.Conn) {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			got += line
			if err != nil || line == "\r\n" {
				break
			}
		}
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n[]"))
	})
	s, err := wire.Dial(context.Background(), core.ProtocolOpenADR, target, core.Options{Trace: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resp, err := httpx.Request(s, "get", "GET", "host", "/programs", map[string]string{"X-Test": "1"}, 4096)
	if err != nil || resp.Status != 200 || string(resp.Body) != "[]" {
		t.Fatalf("%+v %v", resp, err)
	}
	if !strings.Contains(got, "GET /programs HTTP/1.1") || !strings.Contains(got, "X-Test: 1") || !strings.Contains(got, "Host: host") {
		t.Fatalf("request:\n%s", got)
	}
	if len(s.Exchanges()) != 1 {
		t.Fatal("exchange not recorded")
	}
}

func TestWebSocketProtocol(t *testing.T) {
	target := testsrv.Raw(t, func(c net.Conn) {
		buf := make([]byte, 1024)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Protocol: ocpp2.1\r\n\r\n"))
	})
	s, _ := wire.Dial(context.Background(), core.ProtocolOCPP, target, core.Options{})
	defer s.Close()
	resp, err := httpx.Request(s, "ws", "GET", "h", "/", map[string]string{"Upgrade": "websocket"}, 1024)
	if err != nil || resp.Status != 101 || resp.WebSocketProtocol != "ocpp2.1" {
		t.Fatalf("%+v %v", resp, err)
	}
}

// A response whose headers and body arrive in separate TCP segments (a
// streaming or slow server) must be read whole, as must a chunked body.
func TestSplitAndChunkedBodies(t *testing.T) {
	cases := map[string][]string{
		"split content-length": {"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n", `{"tokenURL":1}`[:13]},
		"chunked":              {"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "5\r\nhello\r\n", "6\r\n world\r\n", "0\r\n\r\n"},
		"close-delimited":      {"HTTP/1.0 200 OK\r\n\r\n", "until ", "close"},
	}
	want := map[string]string{"split content-length": `{"tokenURL":1`, "chunked": "hello world", "close-delimited": "until close"}
	for name, parts := range cases {
		t.Run(name, func(t *testing.T) {
			target := testsrv.Raw(t, func(c net.Conn) {
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				br := bufio.NewReader(c)
				for {
					if line, err := br.ReadString('\n'); err != nil || line == "\r\n" {
						break
					}
				}
				for _, p := range parts {
					_, _ = c.Write([]byte(p))
					time.Sleep(30 * time.Millisecond) // separate segments
				}
			})
			s, _ := wire.Dial(context.Background(), core.ProtocolOpenADR, target, core.Options{})
			defer s.Close()
			resp, err := httpx.Request(s, "get", "GET", "h", "/", nil, 4096)
			if err != nil || string(resp.Body) != want[name] {
				t.Fatalf("body %q, want %q (err %v)", resp.Body, want[name], err)
			}
		})
	}
}

// A caller-supplied Connection header replaces the default "close".
func TestConnectionHeaderKept(t *testing.T) {
	var got string
	target := testsrv.Raw(t, func(c net.Conn) {
		buf := make([]byte, 1024)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		n, _ := c.Read(buf)
		got = string(buf[:n])
		_, _ = c.Write([]byte("HTTP/1.1 204 No Content\r\n\r\n"))
	})
	s, _ := wire.Dial(context.Background(), core.ProtocolOCPP, target, core.Options{})
	defer s.Close()
	resp, err := httpx.Request(s, "x", "GET", "h", "/", map[string]string{"Connection": "keep-alive"}, 64)
	if err != nil || resp.Status != 204 || strings.Contains(got, "Connection: close") || !strings.Contains(got, "Connection: keep-alive") {
		t.Fatalf("%v %v\n%s", resp, err, got)
	}
}

func TestFramerEdges(t *testing.T) {
	cases := map[string]int{
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok":                                             0, // checked below
		"HTTP/1.1 304 Not Modified\r\nContent-Length: 99\r\n\r\n":                                    len("HTTP/1.1 304 Not Modified\r\nContent-Length: 99\r\n\r\n"),
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=1\r\nabc\r\n0\r\nX-T: 1\r\n\r\n": len("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=1\r\nabc\r\n0\r\nX-T: 1\r\n\r\n"),
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n":                                -1,
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab":                               0,
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-T: 1\r\n":                       0,
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3":                                     0,
		"HTTP/1.1 200 OK\r\nbroken header\r\nContent-Length: 1\r\n\r\nx":                             len("HTTP/1.1 200 OK\r\nbroken header\r\nContent-Length: 1\r\n\r\nx"),
		"SSH-2.0-OpenSSH": -1,
	}
	for in, want := range cases {
		got := httpx.Framer([]byte(in))
		if in == "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" {
			want = len(in)
		}
		if got != want {
			t.Errorf("%q: %d, want %d", in, got, want)
		}
	}
	if httpx.Framer([]byte(strings.Repeat("A", 20000))) != -1 {
		t.Error("oversized header block")
	}
}
