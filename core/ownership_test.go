// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"slices"
	"testing"
)

// NewEngine keeps copies of the Protocols and Exclude slices, and Config
// returns copies: neither the caller's slices nor a returned configuration
// change which fingerprinters an engine runs.
func TestEngineOwnsItsConfiguration(t *testing.T) {
	modbus := &fakeFP{info: Info{Protocol: ProtocolModbus, Network: TCP}, result: NoMatch(ProtocolModbus)}
	s7 := &fakeFP{info: Info{Protocol: ProtocolS7, Network: TCP}, result: NoMatch(ProtocolS7)}
	mms := &fakeFP{info: Info{Protocol: ProtocolMMS, Network: TCP}, result: NoMatch(ProtocolMMS)}
	protocols := []Protocol{ProtocolModbus, ProtocolS7}
	exclude := []Protocol{ProtocolS7}
	e := NewEngine(NewRegistry().MustRegister(modbus, s7, mms), EngineConfig{Protocols: protocols, Exclude: exclude})
	target := Target{Host: "127.0.0.1", Port: 502}
	ran := func() [3]int {
		t.Helper()
		modbus.calls, s7.calls, mms.calls = 0, 0, 0
		if _, err := e.Scan(context.Background(), target); err != nil {
			t.Fatal(err)
		}
		return [3]int{modbus.calls, s7.calls, mms.calls}
	}
	want := [3]int{1, 0, 0}
	if got := ran(); got != want {
		t.Fatalf("fingerprinters run %v, want Modbus only", got)
	}

	// The caller reuses its slices.
	protocols[0], protocols[1], exclude[0] = ProtocolMMS, ProtocolMMS, ProtocolModbus
	if got := ran(); got != want {
		t.Errorf("after the caller changed its slices: fingerprinters run %v, want %v", got, want)
	}

	// The caller changes what Config returned.
	c := e.Config()
	if !slices.Equal(c.Protocols, []Protocol{ProtocolModbus, ProtocolS7}) || !slices.Equal(c.Exclude, []Protocol{ProtocolS7}) {
		t.Fatalf("Config() = %v, %v", c.Protocols, c.Exclude)
	}
	c.Protocols[0], c.Exclude[0] = ProtocolMMS, ProtocolModbus
	if got := ran(); got != want {
		t.Errorf("after the caller changed the result of Config: fingerprinters run %v, want %v", got, want)
	}
	if c2 := e.Config(); c2.Protocols[0] != ProtocolModbus || c2.Exclude[0] != ProtocolS7 {
		t.Errorf("Config() after the change = %v, %v", c2.Protocols, c2.Exclude)
	}
	// No filter stays no filter.
	if c := NewEngine(NewRegistry(), EngineConfig{}).Config(); c.Protocols != nil || c.Exclude != nil {
		t.Errorf("empty configuration: %v, %v", c.Protocols, c.Exclude)
	}
}
