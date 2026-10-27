// SPDX-License-Identifier: MIT

// Package httpx is a minimal HTTP/1.1 client over a wire.Session, used by
// the web-based fingerprinters (OCPP, IEEE 2030.5, OpenADR). It writes one
// request and reads one response on a session's connection, so the probes
// honour the session's timeout, TLS configuration and exchange tracing
// without pulling in net/http's connection pooling.
package httpx

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/otfabric/go-otfp/internal/wire"
)

// Response is one HTTP response, with the headers and a bounded body.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
	// WebSocketProtocol is the Sec-WebSocket-Protocol of a 101 response.
	WebSocketProtocol string
}

// Request writes an HTTP/1.1 request to the session and reads the response.
// method and path are required; host sets the Host header; extra adds or
// overrides header fields. The body is read up to maxBody octets.
func Request(s *wire.Session, label, method, host, path string, extra map[string]string, maxBody int) (*Response, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, path)
	fmt.Fprintf(&b, "Host: %s\r\n", host)
	b.WriteString("User-Agent: otfp/otprobe\r\n")
	b.WriteString("Accept: */*\r\n")
	hasConnClose := false
	for k, v := range extra {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		if strings.EqualFold(k, "Connection") {
			hasConnClose = true
		}
	}
	if !hasConnClose {
		b.WriteString("Connection: close\r\n")
	}
	b.WriteString("\r\n")

	if err := s.Send([]byte(b.String())); err != nil {
		return nil, err
	}
	raw, err := s.Read(nil, maxBody+16384)
	s.Record(label, []byte(b.String()), raw)
	if err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(string(raw))), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	out := &Response{Status: resp.StatusCode, Header: resp.Header}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		out.WebSocketProtocol = resp.Header.Get("Sec-WebSocket-Protocol")
	}
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for len(buf) < maxBody {
		n, rerr := resp.Body.Read(tmp)
		buf = append(buf, tmp[:min(n, maxBody-len(buf))]...)
		if rerr != nil {
			break
		}
	}
	out.Body = buf
	return out, nil
}

// PathEscape escapes a path segment.
func PathEscape(s string) string { return url.PathEscape(s) }
