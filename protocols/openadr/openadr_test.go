// SPDX-License-Identifier: MIT

package openadr

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
)

func target(t *testing.T, h http.Handler) core.Target {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u := strings.TrimPrefix(srv.URL, "http://")
	host, port, _ := net.SplitHostPort(u)
	p, _ := strconv.Atoi(port)
	return core.Target{Host: host, Port: p, Timeout: 2 * time.Second}
}

func TestAuthServer(t *testing.T) {
	tg := target(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/server" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tokenURL":"https://vtn.example/auth/token"}`))
			return
		}
		http.NotFound(w, r)
	}))
	r, err := New().Detect(context.Background(), tg, core.Options{Trace: true})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain || r.Variant != "OpenADR 3" {
		t.Fatalf("%v %v", r, err)
	}
	if r.Identity.Attributes["tokenUrl"] != "https://vtn.example/auth/token" {
		t.Fatalf("identity %+v", r.Identity)
	}
}

func TestPrograms401(t *testing.T) {
	tg := target(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/programs" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"title":"Unauthorized","status":401,"detail":"a bearer token is required"}`))
			return
		}
		http.Error(w, "nope", http.StatusNotImplemented)
	}))
	r, err := New().Detect(context.Background(), tg, core.Options{})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceHigh || r.Fingerprint.Signature != "programs=401" {
		t.Fatalf("%v %v %v", r, err, r.Fingerprint)
	}
}

func TestProgramsAnonymous(t *testing.T) {
	tg := target(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/programs" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
			return
		}
		http.Error(w, "nope", http.StatusNotImplemented)
	}))
	r, err := New().Detect(context.Background(), tg, core.Options{})
	if err != nil || !r.Matched || r.Fingerprint.Signature != "programs=200" {
		t.Fatalf("%v %v", r, err)
	}
}

func TestOpenADR2b(t *testing.T) {
	tg := target(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == oadr2bPath {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0"?><oadrPayload xmlns="http://openadr.org/oadr-2.0b/2012/07"><oadrCreatedPartyRegistration/></oadrPayload>`))
			return
		}
		http.Error(w, "nope", http.StatusNotImplemented)
	}))
	r, err := New().Detect(context.Background(), tg, core.Options{MaxIntrusiveness: core.ReadOnly})
	if err != nil || !r.Matched || r.Variant != "OpenADR 2.0b" || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v %v", r, err)
	}
}

func TestNotOpenADR(t *testing.T) {
	tg := target(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "generic 401", http.StatusUnauthorized) // no Bearer, no OpenADR shape
	}))
	r, err := New().Detect(context.Background(), tg, core.Options{MaxIntrusiveness: core.ReadOnly})
	if err != nil || r.Matched {
		t.Fatalf("%v %v", r, err)
	}
}
