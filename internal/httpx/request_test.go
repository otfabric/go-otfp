// SPDX-License-Identifier: MIT

package httpx

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
	"github.com/otfabric/go-otfp/internal/wire"
)

func TestCheckRequest(t *testing.T) {
	type req struct {
		method, host, path string
		extra              map[string]string
	}
	for _, r := range []req{
		{"GET", "h", "/", nil},
		{"POST", "10.0.0.5:8080", "/OpenADR2/Simple/2.0b/EiRegisterParty", map[string]string{"Content-Type": "application/xml"}},
		{"GET", "[::1]:9000", "/ocpp/CP%201?tenant=a", map[string]string{"Sec-WebSocket-Protocol": "ocpp2.1, ocpp2.0.1, ocpp1.6", "X-Tab": "a\tb"}},
		{"GET", "zürich.example", "/größe", nil},
	} {
		if err := CheckRequest(r.method, r.host, r.path, r.extra); err != nil {
			t.Errorf("CheckRequest(%+v) = %v, want nil", r, err)
		}
	}
	bad := []req{
		{"", "h", "/", nil},
		{"get", "h", "/", nil},
		{"GET /x", "h", "/", nil},
		{"GET", "", "/", nil},
		{"GET", "h/x", "/", nil},
		{"GET", "h", "", nil},
		{"GET", "h", "x", nil},
		{"GET", "h", "/", map[string]string{"": "v"}},
		{"GET", "h", "/", map[string]string{"X Y": "v"}},
		{"GET", "h", "/", map[string]string{"X:Y": "v"}},
		{"GET", "h", "/", map[string]string{"Größe": "v"}},
	}
	for _, c := range []string{"\r", "\n", "\r\n", "\x00", "\x1f", "\x7f", "\U00000085"} {
		bad = append(bad,
			req{"GET" + c, "h", "/", nil},
			req{"GET", "h" + c + "x", "/", nil},
			req{"GET", "h", "/a" + c + "b", nil},
			req{"GET", "h", "/", map[string]string{"X" + c + "Y": "v"}},
			req{"GET", "h", "/", map[string]string{"X-Y": "v" + c + "w"}},
		)
	}
	for _, c := range []string{" ", "\t"} {
		bad = append(bad, req{"GET", "h" + c + "x", "/", nil}, req{"GET", "h", "/a" + c + "b", nil})
	}
	for _, r := range bad {
		if err := CheckRequest(r.method, r.host, r.path, r.extra); err == nil {
			t.Errorf("CheckRequest(%+q) = nil, want an error", r)
		}
	}
}

// A request that CheckRequest refuses is not written: the peer receives
// nothing, and the error says "could not decide" (a *core.DetectError).
func TestRefusedRequestWritesNothing(t *testing.T) {
	var mu sync.Mutex
	var got []byte
	done := make(chan struct{}, 8)
	target := testsrv.Raw(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			mu.Lock()
			got = append(got, buf[:n]...)
			mu.Unlock()
			if err != nil {
				done <- struct{}{}
				return
			}
		}
	})
	type req struct {
		method, host, path string
		extra              map[string]string
	}
	for _, r := range []req{
		{"GET", "h", "/a\r\nX-Second: 1", nil},
		{"GET", "h", "/a HTTP/1.1\r\n\r\nGET /b", nil},
		{"GET", "h\r\nX-Second: 1", "/", nil},
		{"GET", "h", "/", map[string]string{"X-A": "1\r\nX-Second: 1"}},
		{"GET\r\n", "h", "/", nil},
	} {
		s, err := wire.Dial(context.Background(), core.ProtocolOCPP, target, core.Options{Trace: true})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := RequestBody(s, "get", r.method, r.host, r.path, r.extra, []byte("body"), 64)
		var de *core.DetectError
		if resp != nil || !errors.As(err, &de) || de.Op != "request" || de.Protocol != core.ProtocolOCPP {
			t.Errorf("%+q: response %v, error %v; want a DetectError of operation request", r, resp, err)
		}
		if !wire.IsTransport(err) {
			t.Errorf("%+q: %v is not reported as a transport error", r, err)
		}
		if n := len(s.Exchanges()); n != 0 {
			t.Errorf("%+q: %d exchanges recorded, want 0", r, n)
		}
		_ = s.Close()
		select {
		case <-done: // the peer read to the end of the connection
		case <-time.After(5 * time.Second):
			t.Fatal("the peer did not see the connection close")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 0 {
		t.Errorf("the peer received %q, want nothing", got)
	}
}
