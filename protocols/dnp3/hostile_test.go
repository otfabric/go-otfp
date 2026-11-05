// SPDX-License-Identifier: MIT

package dnp3

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

func TestChaos(t *testing.T) {
	chaos.Suite{
		FP:  New(),
		TCP: func(t testing.TB, cfg chaos.Config) core.Target { return chaos.TCP(t, cfg, outstation(1024, true)) },
	}.Run(t)
}

// frames splits recorded request chunks into data-link frames.
func frames(t *testing.T, rec *chaos.Recorder) []Header {
	t.Helper()
	var out []Header
	for _, chunk := range rec.Requests() {
		for len(chunk) > 0 {
			n := Framer(chunk)
			if n <= 0 || n > len(chunk) {
				t.Fatalf("not a DNP3 frame: % x", chunk)
			}
			h, err := ParseHeader(chunk[:n])
			if err != nil {
				t.Fatalf("frame % x: %v", chunk[:n], err)
			}
			out = append(out, h)
			chunk = chunk[n:]
		}
	}
	return out
}

// The safety contract: data-link REQUEST_LINK_STATUS, and in identify mode
// one UNCONFIRMED_USER_DATA frame carrying an application READ of the
// device attributes (group 0, variation 254, all). Never RESET_LINK,
// TEST_LINK, confirmed data, or an application WRITE, SELECT, OPERATE,
// DIRECT_OPERATE, FREEZE, COLD/WARM_RESTART, ENABLE/DISABLE_UNSOLICITED.
func TestSafetyContract(t *testing.T) {
	for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
		for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
			rec := &chaos.Recorder{}
			target := testsrv.TCP(t, rec.Wrap(outstation(1024, true)))
			if _, err := New().Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: level}); err != nil {
				t.Fatal(err)
			}
			sent := frames(t, rec)
			if len(sent) == 0 {
				t.Fatal("nothing sent")
			}
			reads := 0
			for _, h := range sent {
				if h.Ctrl&ctrlDIR == 0 || h.Ctrl&ctrlPRM == 0 {
					t.Fatalf("frame ctrl 0x%02x is not master primary", h.Ctrl)
				}
				switch h.Ctrl & 0x0F {
				case fcRequestLinkStatus:
					if len(h.Data) != 0 {
						t.Fatalf("REQUEST_LINK_STATUS with user data % x", h.Data)
					}
				case fcUnconfirmedData:
					// transport header, application control, function,
					// then exactly one object header: g0 v254 qualifier 06.
					if len(h.Data) != 6 || h.Data[2] != 0x01 || !bytes.Equal(h.Data[3:], []byte{0x00, 0xFE, 0x06}) {
						t.Fatalf("%s/%s: application request % x is not READ g0v254", mode, level, h.Data)
					}
					reads++
				default:
					t.Fatalf("%s/%s: link function %d sent", mode, level, h.Ctrl&0x0F)
				}
			}
			if mode == core.ModeDetect && reads > 0 || mode == core.ModeIdentify && reads != 1 {
				t.Fatalf("%s: %d application reads", mode, reads)
			}
		}
	}
}

// The identify read loop is bounded: a peer that keeps sending unrelated
// frames, each just inside the read timeout, holds the probe for at most 32
// reads. Here it floods frames instantly, so the probe ends at once.
func TestIdentifyFloodBounded(t *testing.T) {
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) {
		h, err := ParseHeader(req[:FrameLen(req[2])])
		if err != nil {
			return nil, false
		}
		if h.Ctrl&0x0F == fcRequestLinkStatus {
			return Frame(fcLinkStatus, h.Src, h.Dst, nil), false
		}
		// 40 outstation primary frames without FIN: more than the loop reads.
		var out []byte
		for range 40 {
			out = append(out, Frame(0x44, 1, 10, []byte{0x40, 0xC0, 0x81, 0, 0})...)
		}
		return out, false
	})
	target.Timeout = 300 * time.Millisecond
	start := time.Now()
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
	if err != nil || !r.Matched {
		t.Fatalf("%v %v", r, err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("identify took %v", d)
	}
}

// Regression: an echo service returns the REQUEST_LINK_STATUS burst
// unchanged; those valid master frames used to score medium ("DNP3 frames,
// but no link status") and match.
func TestEchoIsNotDNP3(t *testing.T) {
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) { return req, false })
	target.Timeout = 200 * time.Millisecond
	for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
		r, err := New().Detect(context.Background(), target, core.Options{Mode: mode})
		if err != nil || r.Matched {
			t.Fatalf("%s: %v %v", mode, r, err)
		}
	}
}
