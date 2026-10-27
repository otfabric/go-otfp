// SPDX-License-Identifier: MIT

package can

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

func TestDetectIdentify(t *testing.T) {
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) {
		switch req[0] {
		case 'V':
			return []byte("V1013\r"), false
		case 'N':
			return []byte("NA123\r"), false
		}
		return []byte{bell}, false
	})
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify, Trace: true})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v %v", r, err)
	}
	if r.Identity.Version != "V1013" || r.Identity.Serial != "NA123" {
		t.Fatalf("identity %+v", r.Identity)
	}
	if r.Fingerprint.Signature != "version=V1013;serial=NA123" {
		t.Fatalf("signature %q", r.Fingerprint.Signature)
	}
}

func TestVersionThenBareAck(t *testing.T) {
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) {
		if req[0] == 'V' {
			return []byte("V1011\r"), false
		}
		return []byte("\r"), false
	})
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v %v", r, err)
	}
}

func TestRejectsTextBanners(t *testing.T) {
	for name, banner := range map[string]string{
		"http":  "HTTP/1.1 400 Bad Request\r\n",
		"ssh":   "SSH-2.0-OpenSSH\r\n",
		"smtp":  "220 mail ready\r\n",
		"json":  "{\"v\":1}\r\n",
		"prose": "CAN gateway ready\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			target := testsrv.TCP(t, testsrv.Script([]byte(banner)))
			target.Timeout = 300 * time.Millisecond
			r, _ := New().Detect(context.Background(), target, core.Options{})
			if r.Matched {
				t.Fatalf("%v", r)
			}
		})
	}
}

func TestBareAcksOnly(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script([]byte("\r"), []byte("\r")))
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || r.Matched || r.Confidence != core.ConfidenceLow {
		t.Fatalf("%v %v", r, err)
	}
}

func TestInfo(t *testing.T) {
	if New().Info().Protocol != core.ProtocolCAN {
		t.Fatal("info")
	}
}

func FuzzSLCAN(f *testing.F) {
	f.Add([]byte("V1013\r"))
	f.Add([]byte("garbage"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = slcanField(b, 'V')
		_ = looksLikeText(b)
		_ = lineFramer(b)
	})
}
