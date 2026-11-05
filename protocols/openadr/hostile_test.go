// SPDX-License-Identifier: MIT

package openadr

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
)

// serve runs h on a loopback listener behind cfg's fault.
func serve(t testing.TB, cfg chaos.Config, h http.Handler) core.Target {
	t.Helper()
	ln := chaos.NewListener(t, cfg)
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close(); <-done })
	return chaos.Target(t, ln.Addr(), core.TCP)
}

// vtn3 is an OpenADR 3 VTN publishing its token URL.
func vtn3() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/auth/server" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tokenURL":"https://vtn.example/auth/token"}`))
			return
		}
		http.NotFound(w, r)
	})
}

// vtn2b is an OpenADR 2.0b VTN: only the registration endpoint answers.
func vtn2b() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == oadr2bPath {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0"?><oadrPayload xmlns="http://openadr.org/oadr-2.0b/2012/07"><oadrCreatedPartyRegistration/></oadrPayload>`))
			return
		}
		http.NotFound(w, r)
	})
}

func TestChaos(t *testing.T) {
	t.Run("openadr3", chaos.Suite{
		FP:  New(),
		TCP: func(t testing.TB, cfg chaos.Config) core.Target { return serve(t, cfg, vtn3()) },
	}.Run)
	t.Run("openadr2b", chaos.Suite{
		FP:      New(),
		Options: core.Options{MaxIntrusiveness: core.ReadOnly},
		TCP:     func(t testing.TB, cfg chaos.Config) core.Target { return serve(t, cfg, vtn2b()) },
	}.Run)
}

type request struct{ method, path, body string }

// recorder wraps h, recording every request.
type recorder struct {
	mu  sync.Mutex
	got []request
}

func (rc *recorder) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rc.mu.Lock()
		rc.got = append(rc.got, request{r.Method, r.URL.Path, string(body)})
		rc.mu.Unlock()
		h.ServeHTTP(w, r)
	})
}

// The safety contract: GET /auth/server and GET /programs; the 2.0b
// registration query (a POST of oadrQueryRegistration, which registers
// nothing) only when read-only probes are allowed. No other method, path or
// body.
func TestSafetyContract(t *testing.T) {
	for name, h := range map[string]http.Handler{"3": vtn3(), "2.0b": vtn2b(), "none": http.NotFoundHandler()} {
		for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
			for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
				rc := &recorder{}
				target := serve(t, chaos.Config{}, rc.wrap(h))
				if _, err := New().Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: level}); err != nil {
					t.Fatal(err)
				}
				rc.mu.Lock()
				got := append([]request(nil), rc.got...)
				rc.mu.Unlock()
				if len(got) == 0 {
					t.Fatal("nothing sent")
				}
				for _, r := range got {
					switch {
					case r.method == http.MethodGet && (r.path == "/auth/server" || r.path == "/programs") && r.body == "":
					case r.method == http.MethodPost && r.path == oadr2bPath && r.body == queryRegistration:
						if level < core.ReadOnly {
							t.Fatalf("%s %s/%s: the 2.0b registration query was posted with passive probes only", name, mode, level)
						}
					default:
						t.Fatalf("%s %s/%s: %s %s %q sent", name, mode, level, r.method, r.path, r.body)
					}
				}
				if strings.Contains(name, "none") && level == core.ReadOnly && len(got) != 3 {
					t.Fatalf("%d requests to a non-VTN, want 3", len(got))
				}
			}
		}
	}
}

// A 2.0b VTN reads the oadrQueryRegistration body before it answers. The
// probe used to announce the body's Content-Length without sending it, so
// such a VTN waited for the body and the probe timed out.
func TestOpenADR2bBodyIsSent(t *testing.T) {
	var mu sync.Mutex
	var body string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != oadr2bPath {
			http.NotFound(w, r)
			return
		}
		b, err := io.ReadAll(r.Body)
		if err != nil || !strings.Contains(string(b), "oadrQueryRegistration") {
			http.Error(w, "no registration query", http.StatusBadRequest)
			return
		}
		mu.Lock()
		body = string(b)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<oadrPayload xmlns="http://openadr.org/oadr-2.0b/2012/07"><oadrCreatedPartyRegistration/></oadrPayload>`))
	})
	tg := serve(t, chaos.Config{}, h)
	tg.Timeout = time.Second
	r, err := New().Detect(context.Background(), tg, core.Options{MaxIntrusiveness: core.ReadOnly})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v %v", r, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if body != queryRegistration {
		t.Fatalf("body %q", body)
	}
}

// The weaker shapes: a bare Bearer 401 is a hint, an OpenADR 2.0b
// namespace without the registration answer is high.
func TestWeakShapes(t *testing.T) {
	bearer := serve(t, chaos.Config{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	if r, err := New().Detect(context.Background(), bearer, core.Options{}); err != nil || r.Matched || r.Confidence != core.ConfidenceLow {
		t.Fatalf("bare bearer: %v %v", r, err)
	}
	ns := serve(t, chaos.Config{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`<oadrPayload xmlns="http://openadr.org/oadr-2.0b/2012/07"><oadrResponse/></oadrPayload>`))
			return
		}
		http.NotFound(w, r)
	}))
	if r, err := New().Detect(context.Background(), ns, core.Options{MaxIntrusiveness: core.ReadOnly}); err != nil || r.Confidence != core.ConfidenceHigh || r.Variant != "OpenADR 2.0b" {
		t.Fatalf("2.0b namespace: %v %v", r, err)
	}
	if hostHeader(core.Target{Host: "vtn.example", Port: 443}) != "vtn.example" || hostHeader(core.Target{Host: "vtn.example", Port: 80}) != "vtn.example" {
		t.Fatal("default ports are left out of the Host header")
	}
}
