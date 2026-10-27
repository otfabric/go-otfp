// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestProtocolRoundTrip(t *testing.T) {
	for _, p := range AllProtocols() {
		if !p.IsValid() {
			t.Fatalf("%v not valid", p)
		}
		got, err := ParseProtocol(p.Slug())
		if err != nil || got != p {
			t.Fatalf("slug %q -> %v %v", p.Slug(), got, err)
		}
		got, err = ParseProtocol(p.String())
		if err != nil || got != p {
			t.Fatalf("name %q -> %v %v", p.String(), got, err)
		}
		b, _ := p.MarshalText()
		var rt Protocol
		if err := rt.UnmarshalText(b); err != nil || rt != p {
			t.Fatalf("text round trip %v", p)
		}
	}
	if _, err := ParseProtocol("nope"); err == nil {
		t.Fatal("want error")
	}
	for alias, want := range map[string]Protocol{"s7": ProtocolS7, "ethernetip": ProtocolENIP, "2030.5": ProtocolIEEE2030_5, "iec61850": ProtocolMMS} {
		if got, _ := ParseProtocol(alias); got != want {
			t.Fatalf("alias %q -> %v", alias, got)
		}
	}
	if ProtocolUnknown.IsValid() || Protocol(250).String() != "Unknown" {
		t.Fatal("unknown")
	}
}

func TestTargetParseAndValidate(t *testing.T) {
	cases := map[string]struct {
		host string
		port int
		net  Network
		tls  bool
	}{
		"10.0.0.1:502":           {"10.0.0.1", 502, TCP, false},
		"udp://10.0.0.1:47808":   {"10.0.0.1", 47808, UDP, false},
		"tls://host.example:443": {"host.example", 443, TCP, true},
		"[::1]:102":              {"::1", 102, TCP, false},
	}
	for in, want := range cases {
		got, err := ParseTarget(in)
		if err != nil || got.Host != want.host || got.Port != want.port || got.Network != want.net || (got.TLS != nil) != want.tls {
			t.Fatalf("%q -> %+v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "nohost", "10.0.0.1:0", "10.0.0.1:99999", "ftp://10.0.0.1:1"} {
		if _, err := ParseTarget(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if (Target{Host: "x", Port: 1, Network: UDP, TLS: &tls.Config{}}).Validate() == nil {
		t.Fatal("TLS over UDP should fail")
	}
	if got := (Target{Host: "::1", Port: 102}).Addr(); got != "[::1]:102" {
		t.Fatalf("addr %q", got)
	}
	if (Target{}).EffectiveTimeout() != DefaultTimeout {
		t.Fatal("default timeout")
	}
}

func TestConfidenceAndMatch(t *testing.T) {
	if !ConfidenceHigh.IsHigh(ConfidenceHigh) || Confidence(2).Clamp() != 1 || Confidence(-1).Clamp() != 0 {
		t.Fatal("confidence")
	}
	if Match(ProtocolModbus, ConfidenceLow, "x").Matched {
		t.Fatal("low should not match")
	}
	if !Match(ProtocolModbus, ConfidenceHigh, "x").Matched {
		t.Fatal("high should match")
	}
}

func TestIdentityString(t *testing.T) {
	id := &Identity{Vendor: "Acme", Model: "X1", Version: "2.70", Serial: "42"}
	if got := id.String(); got == "" {
		t.Fatal("empty")
	}
	id.Set("k", "")
	if len(id.Attributes) != 0 {
		t.Fatal("empty value stored")
	}
	if !(&Identity{}).IsZero() {
		t.Fatal("zero")
	}
}

func TestResultJSON(t *testing.T) {
	r := Match(ProtocolS7, ConfidenceCertain, "ok")
	r.Error = errors.New("ignored in json")
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(b), `"protocol":"s7comm"`) {
		t.Fatalf("json %s", b)
	}
	if r.ErrorString() == "" {
		t.Fatal("error string")
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (stringIndex(s, sub) >= 0) }
func stringIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestClassify(t *testing.T) {
	if !IsTimeout(os.ErrDeadlineExceeded) || !IsTimeout(context.DeadlineExceeded) {
		t.Fatal("timeout detection")
	}
	var te *TimeoutError
	if !errors.As(ClassifyDial(ProtocolModbus, "a", context.DeadlineExceeded), &te) {
		t.Fatal("dial timeout")
	}
	var ce *ConnectionError
	if !errors.As(ClassifyDial(ProtocolModbus, "a", errors.New("refused")), &ce) {
		t.Fatal("dial conn")
	}
	ce = &ConnectionError{Err: &net.OpError{Err: errRefused{}}}
	_ = ce.Refused()
}

type errRefused struct{}

func (errRefused) Error() string { return "connection refused" }
func (errRefused) Timeout() bool { return false }

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	fp := &fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP, Ports: []int{502}, Priority: 10}}
	if err := r.Register(fp); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(fp); err == nil {
		t.Fatal("duplicate accepted")
	}
	if r.Get(ProtocolModbus, TCP) == nil || r.Get(ProtocolModbus, UDP) != nil {
		t.Fatal("get")
	}
	if err := r.Register(&fakeFP{info: Info{Protocol: ProtocolUnknown}}); err == nil {
		t.Fatal("invalid protocol accepted")
	}
}

func TestPlanOrdersByPort(t *testing.T) {
	r := NewRegistry().MustRegister(
		&fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP, Ports: []int{502}, Priority: 60}},
		&fakeFP{info: Info{Protocol: ProtocolMMS, Network: TCP, Ports: []int{102}, Priority: 10}},
	)
	plan := r.Plan(Target{Host: "h", Port: 502, Network: TCP})
	if len(plan) != 2 || plan[0].Info().Protocol != ProtocolModbus {
		t.Fatalf("plan %v", plan)
	}
}

// fakeFP is a programmable fingerprinter.
type fakeFP struct {
	info   Info
	result Result
	err    error
	delay  time.Duration
	calls  int
}

func (f *fakeFP) Info() Info { return f.info }
func (f *fakeFP) Detect(ctx context.Context, _ Target, _ Options) (Result, error) {
	f.calls++
	if f.delay > 0 {
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-time.After(f.delay):
		}
	}
	return f.result, f.err
}
