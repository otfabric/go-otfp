// SPDX-License-Identifier: MIT

package ocpp

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// requestServer answers every request it can read with the OCPP upgrade
// and records the request lines.
func requestServer(t *testing.T) (core.Target, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var lines []string
	target := testsrv.Raw(t, func(c net.Conn) {
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		br := bufio.NewReader(c)
		for {
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			mu.Lock()
			lines = append(lines, req.Method+" "+req.RequestURI)
			mu.Unlock()
			_, _ = c.Write([]byte(upgrade101))
		}
	})
	return target, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}
}

// The probe is one GET: a path that cannot be the path of one request line,
// from Config.Path or Target.Path, is refused before a connection is
// opened, at every intrusiveness level and in both modes.
func TestPathThatIsNotOneRequestLineIsRefused(t *testing.T) {
	target, _ := requestServer(t)
	var dials atomic.Int64
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	for _, path := range []string{
		"/ocpp/CP1 HTTP/1.1\r\nX-Second: 1",
		"/ocpp/CP1\r\n\r\nPOST /other HTTP/1.1\r\nHost: h\r\n\r\n",
		"/ocpp/CP1\nX: 1",
		"/ocpp/CP 1",
		"/ocpp/CP\t1",
		"/ocpp/CP\x001",
		"ocpp/CP1",
	} {
		for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
			for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
				opts := core.Options{Mode: mode, MaxIntrusiveness: level, Dialer: dial}
				byTarget := target
				byTarget.Path = path
				for name, run := range map[string]func() (core.Result, error){
					"Target.Path": func() (core.Result, error) { return New().Detect(context.Background(), byTarget, opts) },
					"Config.Path": func() (core.Result, error) {
						return NewWithConfig(Config{Path: path}).Detect(context.Background(), target, opts)
					},
				} {
					r, err := run()
					var de *core.DetectError
					if !errors.As(err, &de) || de.Op != "request" || r.Matched {
						t.Errorf("%s %+q: result %v, error %v; want a DetectError of operation request", name, path, r, err)
					}
				}
			}
		}
	}
	if n := dials.Load(); n != 0 {
		t.Errorf("%d connections opened for refused paths, want 0", n)
	}
	// The same host with a slash or a line break in it.
	for _, host := range []string{"h\r\nX-Second: 1", "h x", "h/x"} {
		tg := target
		tg.Host = host
		_, err := New().Detect(context.Background(), tg, core.Options{Dialer: dial})
		var de *core.DetectError
		if !errors.As(err, &de) || de.Op != "request" {
			t.Errorf("host %+q: error %v, want a DetectError of operation request", host, err)
		}
	}
	if n := dials.Load(); n != 0 {
		t.Errorf("%d connections opened for refused hosts, want 0", n)
	}
}

// A path with a query is sent as it is, in exactly one request.
func TestPathIsSentAsOneRequestLine(t *testing.T) {
	for name, fp := range map[string]struct {
		f    *Fingerprinter
		path string
	}{
		"Target.Path": {New(), "/ocpp/CP%201?tenant=a"},
		"Config.Path": {NewWithConfig(Config{Path: "/ocpp/CP%201?tenant=a"}), ""},
	} {
		target, lines := requestServer(t)
		target.Path = fp.path
		r, err := fp.f.Detect(context.Background(), target, core.Options{})
		if err != nil || !r.Matched {
			t.Fatalf("%s: %v %v", name, r, err)
		}
		if got := lines(); len(got) != 1 || got[0] != "GET /ocpp/CP%201?tenant=a" {
			t.Errorf("%s: the server read %q, want one GET of the path", name, got)
		}
	}
}
