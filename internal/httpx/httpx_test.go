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
