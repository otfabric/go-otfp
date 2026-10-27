// SPDX-License-Identifier: MIT

// Package httpx is a minimal HTTP/1.1 client over a wire.Session, used by
// the web-based fingerprinters (OCPP, IEEE 2030.5, OpenADR). It writes one
// request and reads one response on a session's connection, so the probes
// honour the session's timeout, TLS configuration and exchange tracing
// without pulling in net/http's connection pooling.
package httpx

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strconv"
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
	raw, err := s.Read(Framer, maxBody+maxHeader)
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

// maxHeader bounds the response header block.
const maxHeader = 16384

// Framer frames one HTTP/1.1 response so that a read waits for the whole
// message, whatever TCP segmentation the server uses: the header block,
// then a Content-Length body, a chunked body up to its last chunk, or no
// body for 1xx (including 101 Switching Protocols), 204 and 304. A response
// with neither length nor chunking is delimited by the connection closing,
// which the read observes.
func Framer(b []byte) int {
	end := bytes.Index(b, []byte("\r\n\r\n"))
	if end < 0 {
		if len(b) > maxHeader || (len(b) >= 5 && !bytes.HasPrefix(b, []byte("HTTP/"))) {
			return -1
		}
		return 0
	}
	head := b[:end]
	body := end + 4
	status := 0
	if sp := bytes.IndexByte(head, ' '); sp > 0 && len(head) >= sp+4 {
		status, _ = strconv.Atoi(string(head[sp+1 : sp+4]))
	}
	if status/100 == 1 || status == 204 || status == 304 {
		return body
	}
	var length = -1
	chunked := false
	for _, line := range bytes.Split(head, []byte("\r\n"))[1:] {
		k, v, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		v = bytes.TrimSpace(v)
		switch strings.ToLower(string(bytes.TrimSpace(k))) {
		case "content-length":
			if n, err := strconv.Atoi(string(v)); err == nil && n >= 0 {
				length = n
			}
		case "transfer-encoding":
			chunked = bytes.Contains(bytes.ToLower(v), []byte("chunked"))
		}
	}
	switch {
	case chunked:
		return chunkedEnd(b, body)
	case length >= 0:
		return body + length
	}
	return 0 // delimited by close
}

// chunkedEnd returns the end of a chunked body starting at off, or 0 when
// it is not complete yet.
func chunkedEnd(b []byte, off int) int {
	for {
		nl := bytes.Index(b[off:], []byte("\r\n"))
		if nl < 0 {
			return 0
		}
		sizeField := b[off : off+nl]
		if i := bytes.IndexByte(sizeField, ';'); i >= 0 { // chunk extensions
			sizeField = sizeField[:i]
		}
		size, err := strconv.ParseInt(string(bytes.TrimSpace(sizeField)), 16, 32)
		if err != nil || size < 0 {
			return -1
		}
		off += nl + 2
		if size == 0 {
			// Trailers end with an empty line.
			t := bytes.Index(b[off:], []byte("\r\n"))
			for t > 0 {
				off += t + 2
				t = bytes.Index(b[off:], []byte("\r\n"))
			}
			if t < 0 {
				return 0
			}
			return off + 2
		}
		if len(b) < off+int(size)+2 {
			return 0
		}
		off += int(size) + 2
	}
}
