// SPDX-License-Identifier: MIT

package core

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"
)

func TestErrorMessages(t *testing.T) {
	inner := errors.New("boom")
	errs := []error{
		&DetectError{Protocol: ProtocolModbus, Op: "read", Err: inner},
		&TimeoutError{Protocol: ProtocolS7, Addr: "a:1", Op: "dial", Err: inner},
		&ConnectionError{Protocol: ProtocolDNP3, Addr: "a:1", Err: inner},
		&InvalidResponseError{Protocol: ProtocolMMS, Reason: "bad"},
		&ProtocolNotFoundError{Protocol: ProtocolCAN},
	}
	for _, e := range errs {
		if e.Error() == "" {
			t.Errorf("%T empty message", e)
		}
	}
	if !errors.Is((&DetectError{Err: inner}).Unwrap(), inner) {
		t.Fatal("DetectError unwrap")
	}
	if !errors.Is((&TimeoutError{Err: inner}).Unwrap(), inner) || !errors.Is((&ConnectionError{Err: inner}).Unwrap(), inner) {
		t.Fatal("unwrap")
	}
}

func TestModeIntrusivenessNetworkStrings(t *testing.T) {
	if ModeDetect.String() != "detect" || ModeIdentify.String() != "identify" {
		t.Fatal("mode")
	}
	if Passive.String() != "passive" || ReadOnly.String() != "read-only" {
		t.Fatal("intrusiveness")
	}
	if TCP.String() != "tcp" || UDP.String() != "udp" {
		t.Fatal("network")
	}
	var n Network
	if err := n.UnmarshalText([]byte("udp")); err != nil || n != UDP {
		t.Fatal("network unmarshal")
	}
	b, _ := UDP.MarshalText()
	if string(b) != "udp" {
		t.Fatal("network marshal")
	}
	if _, err := ParseNetwork("sctp"); err == nil {
		t.Fatal("bad network")
	}
}

func TestConfidenceValidAndResultStrings(t *testing.T) {
	if !ConfidenceHigh.Valid() || Confidence(1.5).Valid() {
		t.Fatal("valid")
	}
	r := Match(ProtocolModbus, ConfidenceCertain, "ok")
	r.Variant = "v"
	if r.String() == "" {
		t.Fatal("match string")
	}
	r2 := ErrorResult(ProtocolS7, errors.New("x"))
	if r2.String() == "" || r2.ErrorString() == "" {
		t.Fatal("error result string")
	}
	r3 := NoMatch(ProtocolDNP3)
	r3.Confidence = ConfidenceLow
	if r3.String() == "" {
		t.Fatal("hint string")
	}
	if NoMatch(ProtocolCAN).String() == "" {
		t.Fatal("no match string")
	}
	r = r.WithEvidence("a").WithFingerprint(&Fingerprint{ID: "x"}).WithExchanges([]Exchange{{Label: "l"}})
	if len(r.Evidence) != 1 || r.Fingerprint == nil || len(r.Exchanges) != 1 {
		t.Fatal("with helpers")
	}
	if (&Fingerprint{ID: "a", Signature: "b"}).String() != "a:b" || (*Fingerprint)(nil).String() != "" {
		t.Fatal("fingerprint string")
	}
}

func TestIdentityStringVariants(t *testing.T) {
	if (&Identity{VendorID: "7"}).String() == "" {
		t.Fatal("vendor id only")
	}
	if (&Identity{Attributes: map[string]string{"k": "v"}}).String() == "" {
		t.Fatal("attributes only")
	}
	id := &Identity{Vendor: "A", Product: "P", Model: "P", Version: "v1"}
	if got := id.String(); got == "" {
		t.Fatalf("string %q", got)
	}
}

func TestEngineConfigAndSlog(t *testing.T) {
	e := NewEngine(NewRegistry(), EngineConfig{})
	if e.Config().HighConfidenceThreshold != ConfidenceHigh {
		t.Fatal("default threshold")
	}
	var buf bytes.Buffer
	l := NewSlogLogger(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	l.Debugf("d %d", 1)
	l.Infof("i")
	l.Warnf("w")
	l.Errorf("e")
	if buf.Len() == 0 {
		t.Fatal("slog wrote nothing")
	}
	if NewSlogLogger(nil) == nil {
		t.Fatal("nil handler")
	}
	NopLogger().Debugf("x") // no panic
	o := Options{}
	if o.Log() == nil {
		t.Fatal("options log")
	}
}

func TestWaitRespectsInterval(t *testing.T) {
	e := NewEngine(NewRegistry(), EngineConfig{MinInterval: 10 * time.Millisecond})
	start := time.Now()
	fp := &fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP}, result: NoMatch(ProtocolModbus)}
	fp2 := &fakeFP{info: Info{Protocol: ProtocolS7, Network: TCP}, result: NoMatch(ProtocolS7)}
	e2 := NewEngine(NewRegistry().MustRegister(fp, fp2), EngineConfig{MinInterval: 15 * time.Millisecond})
	_, _ = e2.Scan(context.Background(), Target{Host: "127.0.0.1", Port: 1})
	if time.Since(start) < 10*time.Millisecond {
		t.Fatal("interval not enforced")
	}
	_ = e
}
