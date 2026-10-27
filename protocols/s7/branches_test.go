// SPDX-License-Identifier: MIT

package s7

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/iso"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

func TestTSAPRefusals(t *testing.T) {
	dr := unhex("03 00 00 0b 06 80 00 01 00 02 00")
	// Every TSAP refused: an ISO-on-TCP endpoint, a hint only.
	target := testsrv.TCP(t, func([]byte) ([]byte, bool) { return dr, true })
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || r.Matched || r.Confidence != core.ConfidenceLow {
		t.Fatalf("%v %v", r, err)
	}
	// Every connection closed: no hint.
	closer := testsrv.TCP(t, func([]byte) ([]byte, bool) { return nil, true })
	if r, err := New().Detect(context.Background(), closer, core.Options{}); err != nil || r.Confidence != 0 {
		t.Fatalf("closer: %v %v", r, err)
	}
	// A silent endpoint: a timeout, not a verdict.
	silent := testsrv.TCP(t, testsrv.Script())
	silent.Timeout = 200 * time.Millisecond
	if _, err := New().Detect(context.Background(), silent, core.Options{}); err == nil {
		t.Fatal("silent")
	}
	if _, err := New().Detect(context.Background(), testsrv.Closed(t), core.Options{}); err == nil {
		t.Fatal("closed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Detect(ctx, target, core.Options{}); err == nil {
		t.Fatal("cancelled")
	}
	if f := NewWithConfig(Config{CalledTSAPs: []uint16{0x0301}, CallingTSAP: 0x0200}); f.calling != 0x0200 || f.called[0] != 0x0301 {
		t.Fatal("config")
	}
}

func TestSetupEdges(t *testing.T) {
	notData := iso.TPKT([]byte{0x06, 0x80, 0, 0, 0, 0, 0})
	target := testsrv.TCP(t, testsrv.Script(snap7Confirm, notData))
	r, _ := New().Detect(context.Background(), target, core.Options{})
	if r.Matched {
		t.Fatalf("%v", r)
	}
	if _, err := parseSetupAck(append([]byte{0x32, 0x03, 0, 0, 0, 1, 0, 2, 0, 0, 0, 0}, 0xF0, 0)); err == nil {
		t.Fatal("setup ack with a short parameter")
	}
	if _, err := parseSetupAck([]byte{0x32, 0x03, 0, 0, 0, 1, 0, 8, 0, 0, 0, 0, 0x04, 0, 0, 1, 0, 1, 1, 0xE0}); err == nil {
		t.Fatal("not a setup function")
	}
}

func TestSZLEdges(t *testing.T) {
	params := []byte{0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00}
	for name, data := range map[string][]byte{
		"empty data":   {},
		"short header": {0xFF, 0x09, 0x00, 0x04, 0x00, 0x11},
		"error code":   {0xD6, 0x09, 0x00, 0x00},
	} {
		if _, _, _, err := parseSZL(header(rosctrUserData, 1, params, data)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, _, _, err := parseSZL(header(rosctrUserData, 1, params, nil)[:12]); err == nil {
		t.Error("overrun accepted")
	}
	// A partial list (length beyond the data) keeps what arrived.
	list := []byte{0xFF, 0x09, 0x00, 0x40, 0x00, 0x11, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x01}
	if id, _, recs, err := parseSZL(header(rosctrUserData, 1, params, list)); err != nil || id != 0x11 || len(recs) != 0 {
		t.Fatalf("partial: %x %v %v", id, recs, err)
	}
	// Identify with short records, an unexpected list, a memory card.
	short := szlResponse(szlModuleID, 4, []byte{0, 1, 0, 0})
	other := szlResponse(0x0424, 34, rec001c(8, "MMC-1"))
	target := testsrv.TCP(t, testsrv.Script(snap7Confirm, snap7SetupAck, short, other))
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify, Trace: true})
	if err != nil || !r.Matched || r.Identity.Attributes["memoryCardSerial"] != "MMC-1" {
		t.Fatalf("%v %v %+v", r, err, r.Identity)
	}
	// SZL answers that are not COTP data, or no answer at all.
	for _, resps := range [][][]byte{{snap7Confirm, snap7SetupAck, iso.TPKT([]byte{0x06, 0x80, 0, 0, 0, 0, 0})}, {snap7Confirm, snap7SetupAck}} {
		target := testsrv.TCP(t, testsrv.Script(resps...))
		target.Timeout = 200 * time.Millisecond
		if r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify}); err != nil || !r.Matched || r.Identity != nil {
			t.Fatalf("%v %v", r, err)
		}
	}
	if version([]byte{1}) != "" || version(make([]byte, 6)) != "" {
		t.Fatal("version of nothing")
	}
}
