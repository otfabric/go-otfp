// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSafeConfigAndMatches(t *testing.T) {
	c := SafeEngineConfig()
	if c.MaxIntrusiveness != Passive || !c.LikelyOnly || c.MinInterval != 250*time.Millisecond || !c.EarlyStop {
		t.Fatalf("%+v", c)
	}
	r := Report{Results: []Result{Match(ProtocolModbus, ConfidenceHigh, ""), NoMatch(ProtocolS7)}}
	if m := r.Matches(); len(m) != 1 || m[0].Protocol != ProtocolModbus {
		t.Fatalf("%v", m)
	}
}

// A refused TCP connection ends the scan: nothing listens there.
func TestStopOnRefused(t *testing.T) {
	refused := &ConnectionError{Protocol: ProtocolModbus, Addr: "a", Err: &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}}
	a := &fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP, Priority: 1}, err: refused}
	b := &fakeFP{info: Info{Protocol: ProtocolS7, Network: TCP, Priority: 2}, result: NoMatch(ProtocolS7)}
	rep, _ := NewEngine(NewRegistry().MustRegister(a, b), DefaultEngineConfig()).Scan(context.Background(), Target{Host: "h", Port: 1})
	if b.calls != 0 || len(rep.Results) != 1 || !refused.Refused() {
		t.Fatalf("calls %d, results %v", b.calls, rep.Results)
	}
	// Ordering: matched first, then by confidence.
	rs := []Result{NoMatch(ProtocolS7), Match(ProtocolModbus, ConfidenceMedium, ""), Match(ProtocolDNP3, ConfidenceHigh, "")}
	sortResults(rs)
	if rs[0].Protocol != ProtocolDNP3 || rs[2].Protocol != ProtocolS7 {
		t.Fatalf("%v", rs)
	}
	if refines(NewRegistry(), ProtocolSunSpec, ProtocolModbus) {
		t.Fatal("refines on an empty registry")
	}
}

func TestClassifyAll(t *testing.T) {
	if ClassifyDial(ProtocolModbus, "a", nil) != nil || ClassifyIO(ProtocolModbus, "a", "read", nil) != nil {
		t.Fatal("nil errors")
	}
	var te *TimeoutError
	if !errors.As(ClassifyIO(ProtocolModbus, "a", "read", os.ErrDeadlineExceeded), &te) || te.Op != "read" {
		t.Fatal("timeout")
	}
	var ce *ConnectionError
	if !errors.As(ClassifyIO(ProtocolModbus, "a", "read", syscall.ECONNREFUSED), &ce) {
		t.Fatal("refused on read (UDP port unreachable)")
	}
	var de *DetectError
	if !errors.As(ClassifyIO(ProtocolModbus, "a", "write", errors.New("broken pipe")), &de) || de.Op != "write" {
		t.Fatal("other I/O")
	}
}

func TestSmallAccessors(t *testing.T) {
	l := NopLogger()
	l.Infof("x")
	l.Warnf("x")
	l.Errorf("x")
	if (Options{Logger: l}).Log() != l {
		t.Fatal("Options.Log returns the logger")
	}
	if Protocol(200).Slug() != "unknown" {
		t.Fatal("slug out of range")
	}
	var p Protocol
	if p.UnmarshalText([]byte("nope")) == nil {
		t.Fatal("unmarshal unknown protocol")
	}
	var n Network
	if n.UnmarshalText([]byte("sctp")) == nil {
		t.Fatal("unmarshal unknown network")
	}
	if got, err := ParseNetwork(""); err != nil || got != TCP {
		t.Fatal("empty network is TCP")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("MustRegister of a duplicate must panic")
		}
	}()
	fp := &fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP}}
	NewRegistry().MustRegister(fp, fp)
}

func TestRegistryProtocolsAndPlan(t *testing.T) {
	r := NewRegistry().MustRegister(
		&fakeFP{info: Info{Protocol: ProtocolENIP, Network: TCP}},
		&fakeFP{info: Info{Protocol: ProtocolENIP, Network: UDP}},
		&fakeFP{info: Info{Protocol: ProtocolBACnet, Network: UDP}},
	)
	if got := r.Protocols(); len(got) != 2 || got[0] != ProtocolBACnet || got[1] != ProtocolENIP {
		t.Fatalf("%v", got)
	}
	if plan := r.Plan(Target{Host: "h", Port: 1, Network: UDP}); len(plan) != 2 {
		t.Fatalf("UDP plan %d", len(plan))
	}
}

func TestIdentityAndResultFormatting(t *testing.T) {
	var id Identity
	id.Set("k", " v ")
	if id.Attributes["k"] != "v" {
		t.Fatal("Set trims and allocates")
	}
	full := &Identity{Vendor: "Acme", Product: "P1", Model: "M1", Version: "v2", Name: "Line 3", Serial: "42"}
	if got := full.String(); got != `Acme P1 M1 v2 "Line 3" (serial 42)` {
		t.Fatalf("%q", got)
	}
	r := Match(ProtocolModbus, ConfidenceCertain, "ok").WithIdentity(full)
	if r.Identity != full || !strings.Contains(r.String(), "[Acme") {
		t.Fatalf("%v", r)
	}
	if NoMatch(ProtocolModbus).WithIdentity(&Identity{}).Identity != nil {
		t.Fatal("an empty identity is not attached")
	}
	if NoMatch(ProtocolModbus).ErrorString() != "" {
		t.Fatal("no error")
	}
}

func TestTargetEdges(t *testing.T) {
	if (Target{Timeout: time.Second}).EffectiveTimeout() != time.Second {
		t.Fatal("explicit timeout")
	}
	if (Target{Host: "h", Port: 1, Timeout: -1}).Validate() == nil {
		t.Fatal("negative timeout")
	}
	if (Target{Host: "h", Port: 1, Network: 9}).Validate() == nil {
		t.Fatal("unknown network")
	}
	if tg, err := ParseTarget("tcp://h:5"); err != nil || tg.Network != TCP {
		t.Fatalf("tcp scheme: %v", err)
	}
	if _, err := ParseTarget("h:http"); err == nil {
		t.Fatal("non-numeric port")
	}
}
