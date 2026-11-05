// SPDX-License-Identifier: MIT

package httpx

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
	"github.com/otfabric/go-otfp/internal/wire"
)

func session(t *testing.T, target core.Target) *wire.Session {
	t.Helper()
	s, err := wire.Dial(context.Background(), core.ProtocolOpenADR, target, core.Options{Trace: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// A request body is sent, with its Content-Length, so that a server that
// reads the body before answering (every real one) answers at all.
func TestRequestBodyIsSent(t *testing.T) {
	var mu sync.Mutex
	var got *http.Request
	var body string
	target := testsrv.Raw(t, func(c net.Conn) {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return
		}
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return
		}
		mu.Lock()
		got, body = req, string(b)
		mu.Unlock()
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	})
	target.Timeout = time.Second
	for _, extra := range []map[string]string{{"Content-Type": "application/xml"}, {"Content-Length": "5"}} {
		resp, err := RequestBody(session(t, target), "post", "POST", "h", "/x", extra, []byte("hello"), 64)
		if err != nil || resp.Status != 200 || string(resp.Body) != "ok" {
			t.Fatalf("%+v %v", resp, err)
		}
		mu.Lock()
		if got == nil || got.Method != "POST" || body != "hello" || got.ContentLength != 5 || len(got.Header.Values("Content-Length")) != 1 {
			t.Fatalf("request %+v body %q", got, body)
		}
		got = nil
		mu.Unlock()
	}
}

func TestRequestErrors(t *testing.T) {
	// The session is closed: the write fails.
	s := session(t, testsrv.TCP(t, testsrv.Script()))
	_ = s.Close()
	if _, err := Request(s, "get", "GET", "h", "/", nil, 64); err == nil {
		t.Fatal("write on a closed session")
	}
	// Nothing comes back: a timeout.
	silent := testsrv.TCP(t, testsrv.Script())
	silent.Timeout = 100 * time.Millisecond
	if _, err := Request(session(t, silent), "get", "GET", "h", "/", nil, 64); err == nil {
		t.Fatal("silent server")
	}
	// A status line net/http does not parse.
	bad := testsrv.TCP(t, testsrv.Script([]byte("HTTP/1.1 abc\r\n\r\n")))
	if _, err := Request(session(t, bad), "get", "GET", "h", "/", nil, 64); err == nil {
		t.Fatal("malformed status line")
	}
}

// A response cut before the blank line that ends its header is not a
// response.
func TestCutHeaderRejected(t *testing.T) {
	full := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Protocol: ocpp1.6\r\n\r\n"
	for _, cut := range []int{len(full) - 1, len(full) - 2, len(full) - 3, 20} {
		target := testsrv.Raw(t, func(c net.Conn) {
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			_, _ = c.Read(make([]byte, 4096))
			_, _ = c.Write([]byte(full[:cut]))
		})
		target.Timeout = 300 * time.Millisecond
		if resp, err := Request(session(t, target), "get", "GET", "h", "/", nil, 64); err == nil {
			t.Fatalf("cut at %d accepted: %+v", cut, resp)
		}
	}
}

// Framer never rejects a prefix of a valid response, so a response
// delivered one octet at a time is read whole; and it reports the exact
// length once the response is complete.
func TestFramerPrefixes(t *testing.T) {
	for _, r := range []string{
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
		"HTTP/1.1 204 No Content\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\n",
		"HTTP/1.0 200 OK\r\n\r\nbody delimited by close",
	} {
		for i := 1; i < len(r); i++ {
			if n := Framer([]byte(r[:i])); n < 0 || (n > 0 && n > len(r)) {
				t.Fatalf("%q: prefix of %d octets framed %d", r, i, n)
			}
		}
		n := Framer([]byte(r))
		if strings.HasSuffix(r, "close") {
			if n != 0 {
				t.Fatalf("close-delimited body framed %d", n)
			}
			continue
		}
		if n != len(r) {
			t.Fatalf("%q framed %d, want %d", r, n, len(r))
		}
	}
	if Framer([]byte("SSH-2.0-OpenSSH\r\n")) != -1 || Framer([]byte(strings.Repeat("H", maxHeader+1))) != -1 {
		t.Fatal("not HTTP")
	}
}

// A close-delimited body is read until the server closes.
func TestBodyDelimitedByClose(t *testing.T) {
	target := testsrv.Raw(t, func(c net.Conn) {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = c.Read(make([]byte, 4096))
		for _, part := range []string{"HTTP/1.0 200 OK\r\n\r\n", "part one, ", "part two"} {
			_, _ = c.Write([]byte(part))
			time.Sleep(5 * time.Millisecond)
		}
	})
	resp, err := Request(session(t, target), "get", "GET", "h", "/", nil, 64)
	if err != nil || string(resp.Body) != "part one, part two" {
		t.Fatalf("%+v %v", resp, err)
	}
}
