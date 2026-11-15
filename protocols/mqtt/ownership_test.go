// SPDX-License-Identifier: MIT

package mqtt

import "testing"

// ParsePacket and ParsePublish borrow, as their doc comments say: the body
// and the payload are parts of the input, the topic is a copy.
func TestParsersBorrowTheirInput(t *testing.T) {
	raw := publish(Level311, "a/b", []byte("payload"), 0)
	p, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParsePublish(Level311, p)
	if err != nil || m.Topic != "a/b" || string(m.Payload) != "payload" {
		t.Fatalf("%+v %v", m, err)
	}
	for i := 2; i < len(raw); i++ {
		raw[i] = 'x'
	}
	if string(p.Body[len(p.Body)-7:]) != "xxxxxxx" || string(m.Payload) != "xxxxxxx" {
		t.Fatalf("body %q and payload %q after the input changed: documented to borrow", p.Body, m.Payload)
	}
	if m.Topic != "a/b" {
		t.Fatalf("topic %q changed with the input: documented to be a copy", m.Topic)
	}
}
