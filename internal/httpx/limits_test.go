// SPDX-License-Identifier: MIT

package httpx

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
	"github.com/otfabric/go-otfp/internal/testsrv"
	"github.com/otfabric/go-otfp/internal/wire"
)

// The limits of SECURITY.md for the web fingerprinters (OCPP, OpenADR, the
// IEEE 2030.5 /dcap read): the header block of a response is at most
// maxHeader octets, and at most maxBody octets of its body are kept,
// whatever length the response declares and however much the peer sends.
func TestLimits(t *testing.T) {
	const maxBody = 4096
	megabyte := strings.Repeat("b", 1<<20)
	cases := []struct {
		name     string
		response string
		body     int // octets of body returned; -1 when the response is refused
	}{
		{"a body of maxBody octets", "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n" + megabyte[:maxBody], maxBody},
		{"a body of maxBody+1 octets", "HTTP/1.1 200 OK\r\nContent-Length: 4097\r\n\r\n" + megabyte[:maxBody+1], maxBody},
		{"a declared megabyte, sent", "HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n" + megabyte, maxBody},
		{"a declared 2^31-1 octets", "HTTP/1.1 200 OK\r\nContent-Length: 2147483647\r\n\r\n" + megabyte, -1},
		{"a chunk of a megabyte", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n100000\r\n" + megabyte + "\r\n0\r\n\r\n", maxBody},
		{"a megabyte delimited by close", "HTTP/1.0 200 OK\r\n\r\n" + megabyte, maxBody},
		{"a header block of maxHeader+1 octets", "HTTP/1.1 200 OK\r\nX: " + megabyte[:maxHeader+1], -1},
		{"a megabyte of header", "HTTP/1.1 200 OK\r\nX: " + megabyte, -1},
	}
	for _, tc := range cases {
		response := []byte(tc.response) // converted here: the allocation count below is the process's
		target := testsrv.TCP(t, func([]byte) ([]byte, bool) { return response, true })
		target.Timeout = time.Second
		s, err := wire.Dial(context.Background(), core.ProtocolOpenADR, target, core.Options{})
		if err != nil {
			t.Fatal(err)
		}
		var resp *Response
		allocated := fuzzkit.Allocated(func() { resp, err = Request(s, "get", "GET", "h", "/", nil, maxBody) })
		_ = s.Close()
		switch {
		case tc.body < 0 && err == nil && resp != nil && len(resp.Body) > maxBody:
			t.Errorf("%s: a body of %d octets returned", tc.name, len(resp.Body))
		case tc.body >= 0 && (err != nil || len(resp.Body) != tc.body):
			t.Errorf("%s: %v, body of %d octets; want %d", tc.name, err, bodyLen(resp), tc.body)
		}
		// The read is capped at the header block and the body kept; the
		// rest is a few copies of that, never the megabyte.
		if budget := uint64(64<<10 + 8*(maxHeader+maxBody)); allocated > budget {
			t.Errorf("%s: %d octets allocated, budget %d", tc.name, allocated, budget)
		}
	}
}

func bodyLen(r *Response) int {
	if r == nil {
		return -1
	}
	return len(r.Body)
}
