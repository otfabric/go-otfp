// SPDX-License-Identifier: MIT

package core

import (
	"strings"
	"testing"
)

// Host and Path are sent in a request line and a Host header by the web
// fingerprinters: Validate accepts what one line can carry.
func TestValidateHostAndPath(t *testing.T) {
	ok := []Target{
		{Host: "10.0.0.5", Port: 80},
		{Host: "::1", Port: 80},
		{Host: "fe80::1%en0", Port: 80},
		{Host: "csms.example.org", Port: 443},
		{Host: "zürich.example", Port: 443},
		{Host: "h", Port: 1, Path: "/"},
		{Host: "h", Port: 1, Path: "/ocpp/CP-1"},
		{Host: "h", Port: 1, Path: "/ocpp/CP%201?tenant=a&x=1"},
		{Host: "h", Port: 1, Path: "/größe"},
	}
	for _, tg := range ok {
		if err := tg.Validate(); err != nil {
			t.Errorf("Validate(%+v) = %v, want nil", tg, err)
		}
	}
	for _, c := range []string{"\r", "\n", "\r\n", " ", "\t", "\x00", "\x1f", "\x7f", "\U00000085", "\U0000009b"} {
		for _, tg := range []Target{
			{Host: "h" + c + "x", Port: 1},
			{Host: c + "h", Port: 1},
			{Host: "h", Port: 1, Path: "/a" + c + "b"},
			{Host: "h", Port: 1, Path: "/a" + c},
		} {
			if err := tg.Validate(); err == nil {
				t.Errorf("Validate(%+q, %+q) = nil with %+q in it, want an error", tg.Host, tg.Path, c)
			}
		}
	}
	for _, tg := range []Target{
		{Host: "h/x", Port: 1},
		{Host: "h", Port: 1, Path: "ocpp/CP-1"},
		{Host: "h", Port: 1, Path: "?x=1"},
		{Host: "h", Port: 1, Path: "http://other/"},
	} {
		if err := tg.Validate(); err == nil {
			t.Errorf("Validate(%+q, %+q) = nil, want an error", tg.Host, tg.Path)
		}
	}
	if _, err := ParseTarget("tcp://bad host:80"); err == nil || !strings.Contains(err.Error(), "host") {
		t.Errorf("ParseTarget with a space in the host: %v", err)
	}
}
