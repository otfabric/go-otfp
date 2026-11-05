// SPDX-License-Identifier: MIT

package can

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// slcan answers like an SLCAN gateway: version, serial, BEL otherwise.
func slcan(req []byte) ([]byte, bool) {
	switch string(req) {
	case "V\r":
		return []byte("V1013\r"), false
	case "N\r":
		return []byte("NA1B2\r"), false
	}
	return []byte{bell}, false
}

func TestChaos(t *testing.T) {
	chaos.Suite{
		FP:  New(),
		TCP: func(t testing.TB, cfg chaos.Config) core.Target { return chaos.TCP(t, cfg, slcan) },
	}.Run(t)
}

// The safety contract: the version and serial commands only. Never a
// transmit (t/T/r/R), an open/close (O/L/C), a bit rate (S/s) or a filter.
func TestSafetyContract(t *testing.T) {
	for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
		for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
			rec := &chaos.Recorder{}
			target := testsrv.TCP(t, rec.Wrap(slcan))
			if _, err := New().Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: level}); err != nil {
				t.Fatal(err)
			}
			reqs := rec.Requests()
			if len(reqs) == 0 {
				t.Fatal("nothing sent")
			}
			for _, r := range reqs {
				if s := string(r); s != "V\r" && s != "N\r" {
					t.Fatalf("%s/%s: sent %q", mode, level, r)
				}
			}
		}
	}
}

// Regression: a version reply cut before its carriage return ("V101" and a
// close) is not a whole SLCAN reply and must not score high.
func TestTruncatedVersionIsNotSLCAN(t *testing.T) {
	target := testsrv.Raw(t, func(c net.Conn) {
		buf := make([]byte, 16)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("V101"))
	})
	target.Timeout = 300 * time.Millisecond
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || r.Matched || r.Confidence >= core.ConfidenceHigh {
		t.Fatalf("%v %v", r, err)
	}
	if _, ok := slcanField([]byte("V1013"), 'V'); ok {
		t.Fatal("unterminated field accepted")
	}
	if v, ok := slcanField([]byte("V1013\a"), 'V'); !ok || v != "V1013" {
		t.Fatalf("BEL-terminated field %q %v", v, ok)
	}
}

// Error paths: refused and silent targets are transport errors; a reply
// that is neither a version nor an acknowledgement is not SLCAN; a serial
// that is not a field is no extra evidence.
func TestTransportAndOddReplies(t *testing.T) {
	if _, err := New().Detect(context.Background(), testsrv.Closed(t), core.Options{}); err == nil {
		t.Fatal("refused: no error")
	}
	silent := testsrv.TCP(t, testsrv.Script())
	silent.Timeout = 150 * time.Millisecond
	if _, err := New().Detect(context.Background(), silent, core.Options{}); err == nil {
		t.Fatal("silent: no error")
	}
	closer := testsrv.TCP(t, func([]byte) ([]byte, bool) { return nil, true })
	if r, err := New().Detect(context.Background(), closer, core.Options{}); err != nil || r.Matched {
		t.Fatalf("closer: %v %v", r, err)
	}
	for name, h := range map[string]testsrv.Handler{
		"not slcan": func([]byte) ([]byte, bool) { return []byte("Zq\r"), false },
		"bad serial": func(req []byte) ([]byte, bool) {
			if req[0] == 'V' {
				return []byte("V1013\r"), false
			}
			return []byte("N??\r"), false
		},
		"empty line": func([]byte) ([]byte, bool) { return []byte("\n\r"), false },
	} {
		target := testsrv.TCP(t, h)
		target.Timeout = 200 * time.Millisecond
		r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if name == "bad serial" && (!r.Matched || r.Confidence != core.ConfidenceHigh) {
			t.Fatalf("%s: %v", name, r)
		}
		if name != "bad serial" && r.Matched {
			t.Fatalf("%s: %v", name, r)
		}
	}
	if lineFramer(make([]byte, maxResp)) != -1 || lineFramer([]byte("V1")) != 0 {
		t.Fatal("lineFramer")
	}
	if _, ok := slcanField([]byte("\r"), 'V'); ok {
		t.Fatal("bare CR is a field")
	}
	if _, ok := slcanField([]byte("V123456789\r"), 'V'); ok {
		t.Fatal("overlong field")
	}
	if looksLikeText([]byte("  ")) {
		t.Fatal("blank is text")
	}
}
