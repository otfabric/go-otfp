// SPDX-License-Identifier: MIT

// Package openadr fingerprints OpenADR, the automated demand-response
// protocol between a virtual top node (VTN) and virtual end nodes.
//
// OpenADR 3 is a REST/JSON API. Detection reads the unauthenticated
// endpoint GET /auth/server, which a VTN answers with a JSON object
// carrying its OAuth2 tokenURL — a response unique to OpenADR 3. When that
// endpoint is absent, GET /programs is tried: an OpenADR 3 VTN answers 401
// with a Bearer challenge and a JSON problem body, or 200 with a JSON
// array when anonymous access is allowed.
//
// OpenADR 2.0b is an XML-over-HTTP protocol; it is detected by posting an
// oadrQueryRegistration to the 2.0b registration endpoint and recognising
// the oadrCreatedPartyRegistration response and the OpenADR XML namespace.
//
// The OpenADR 3 probes are unauthenticated GETs, so the fingerprinter is
// passive; the 2.0b POST is sent only when the scan allows read-only probes.
//
// Run the fingerprinter over a TLS target for an https:// VTN.
package openadr

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/httpx"
	"github.com/otfabric/go-otfp/internal/wire"
)

const proto = core.ProtocolOpenADR

const oadr2bPath = "/OpenADR2/Simple/2.0b/EiRegisterParty"

// queryRegistration is a minimal OpenADR 2.0b oadrQueryRegistration payload.
const queryRegistration = `<?xml version="1.0" encoding="UTF-8"?>` +
	`<oadrPayload xmlns="http://openadr.org/oadr-2.0b/2012/07">` +
	`<oadrSignedObject><oadrQueryRegistration xmlns:pyld="http://docs.oasis-open.org/ns/energyinterop/201110/payloads">` +
	`<pyld:requestID>otfp</pyld:requestID></oadrQueryRegistration></oadrSignedObject></oadrPayload>`

// Fingerprinter detects OpenADR.
type Fingerprinter struct{}

// New returns an OpenADR fingerprinter.
func New() *Fingerprinter { return &Fingerprinter{} }

// Info describes the fingerprinter.
func (f *Fingerprinter) Info() core.Info {
	return core.Info{
		Protocol:      proto,
		Network:       core.TCP,
		Ports:         []int{8080, 443, 8443},
		Priority:      130,
		Intrusiveness: core.Passive,
		Description:   "GET /auth/server and /programs (OpenADR 3); POST oadrQueryRegistration (OpenADR 2.0b) when read-only probes are allowed",
	}
}

// Detect probes target.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target, opts core.Options) (core.Result, error) {
	b := fpx.New(proto)
	host := hostHeader(target)
	var trace []core.Exchange

	// OpenADR 3: GET /auth/server.
	if s, err := wire.Dial(ctx, proto, target, opts); err == nil {
		resp, rerr := httpx.Request(s, "auth-server", "GET", host, "/auth/server", nil, 4096)
		if rerr == nil && resp.Status == 200 && isJSON(resp.Header.Get("Content-Type")) {
			var m map[string]json.RawMessage
			if json.Unmarshal(resp.Body, &m) == nil {
				if _, ok := m["tokenURL"]; ok {
					b.Score(core.ConfidenceCertain, "GET /auth/server returned an OpenADR 3 tokenURL")
					b.Variant("OpenADR 3")
					b.Sig("auth", "server")
					var tu struct {
						TokenURL string `json:"tokenURL"`
					}
					_ = json.Unmarshal(resp.Body, &tu)
					b.Identity().Set("tokenUrl", tu.TokenURL)
				}
			}
		}
		trace = append(trace, s.Exchanges()...)
		_ = s.Close()
		if b.Confidence() >= core.MatchThreshold {
			return b.Result("openadr.v3", "OpenADR 3 VTN", nil).WithExchanges(trace), nil
		}
	}

	// OpenADR 3: GET /programs.
	if s, err := wire.Dial(ctx, proto, target, opts); err == nil {
		resp, rerr := httpx.Request(s, "programs", "GET", host, "/programs", nil, 8192)
		if rerr == nil {
			f.judgePrograms(b, resp)
		}
		trace = append(trace, s.Exchanges()...)
		_ = s.Close()
		if b.Confidence() >= core.MatchThreshold {
			return b.Result("openadr.v3", "OpenADR 3 VTN", nil).WithExchanges(trace), nil
		}
	}

	// OpenADR 2.0b: POST oadrQueryRegistration.
	if opts.MaxIntrusiveness >= core.ReadOnly {
		if s, err := wire.Dial(ctx, proto, target, opts); err == nil {
			resp, rerr := httpx.Request(s, "oadr2b", "POST", host, oadr2bPath, map[string]string{
				"Content-Type":   "application/xml",
				"Content-Length": fmt.Sprint(len(queryRegistration)),
			}, 8192)
			if rerr == nil {
				f.judge2b(b, resp)
			}
			trace = append(trace, s.Exchanges()...)
			_ = s.Close()
		}
	}

	details := "not OpenADR"
	if b.Confidence() >= core.MatchThreshold {
		details = "OpenADR VTN"
	}
	return b.Result("openadr", details, nil).WithExchanges(trace), nil
}

func (f *Fingerprinter) judgePrograms(b *fpx.Builder, resp *httpx.Response) {
	switch resp.Status {
	case 401:
		bearer := strings.Contains(strings.ToLower(resp.Header.Get("WWW-Authenticate")), "bearer")
		if bearer && hasProblemShape(resp.Body) {
			b.Score(core.ConfidenceHigh, "GET /programs: 401 Bearer with an OpenADR problem body")
			b.Variant("OpenADR 3")
			b.Sig("programs", "401")
		} else if bearer {
			b.Score(core.ConfidenceLow, "GET /programs: 401 Bearer (could be any OAuth2 API)")
		}
	case 200:
		if trimmed := strings.TrimSpace(string(resp.Body)); strings.HasPrefix(trimmed, "[") && isJSON(resp.Header.Get("Content-Type")) {
			b.Score(core.ConfidenceHigh, "GET /programs: 200 JSON array (anonymous OpenADR 3 VTN)")
			b.Variant("OpenADR 3")
			b.Sig("programs", "200")
		}
	}
}

func (f *Fingerprinter) judge2b(b *fpx.Builder, resp *httpx.Response) {
	body := string(resp.Body)
	if strings.Contains(body, "oadrCreatedPartyRegistration") {
		b.Score(core.ConfidenceCertain, "oadrCreatedPartyRegistration response")
		b.Variant("OpenADR 2.0b")
		b.Sig("oadr2b", "created")
		return
	}
	if strings.Contains(body, "openadr.org/oadr-2.0b") || strings.Contains(body, "oadrPayload") {
		b.Score(core.ConfidenceHigh, "OpenADR 2.0b XML namespace in the response")
		b.Variant("OpenADR 2.0b")
		b.Sig("oadr2b", "namespace")
	}
}

func isJSON(ct string) bool { return strings.Contains(strings.ToLower(ct), "json") }

func hasProblemShape(body []byte) bool {
	var p struct {
		Title  string `json:"title"`
		Status int    `json:"status"`
	}
	return json.Unmarshal(body, &p) == nil && (p.Title != "" || p.Status != 0)
}

func hostHeader(t core.Target) string {
	if t.Port == 80 || t.Port == 443 {
		return t.Host
	}
	return t.Addr()
}
