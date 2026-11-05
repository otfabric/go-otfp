// SPDX-License-Identifier: MIT

package sparkplugb

import (
	"testing"

	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// FuzzDetect runs the fingerprinter end to end against a server replying
// with fuzzed bytes, seeded with what the reference brokers deliver
// from the sparkplugb-interop host and edge nodes, and checks the
// Fingerprinter contract on every result (see fuzzkit).
func FuzzDetect(f *testing.F) {
	subackSeed := pkt(0x90, []byte{0x00, 0x01, 0, 0, 0, 0})
	f.Add(fuzzkit.Join([]byte{0x20, 0x02, 0x00, 0x00},
		append(append(subackSeed, pub("spBv1.0/STATE/h", []byte(state3), true)...), pub("spBv1.0/g/NBIRTH/e", birth(0, "a"), false)...),
		[]byte{0xB0, 0x02, 0x00, 0x02}))
	f.Add(fuzzkit.Join([]byte{0x20, 0x02, 0x00, 0x00}, append(subackSeed, pub("STATE/h", []byte("ONLINE"), true)...)))
	f.Add(fuzzkit.Join([]byte{0x20, 0x03, 0x00, 0x84, 0x00}, []byte{0x20, 0x03, 0x00, 0x00, 0x00}))
	f.Add(fuzzkit.Join([]byte{0x20, 0x02, 0x00, 0x05}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzkit.Detect(t, New(), data)
	})
}

// FuzzDecodePayload checks that the protobuf decoder never panics and
// keeps its bounds.
func FuzzDecodePayload(f *testing.F) {
	f.Add(birth(3, "Inputs/Temperature", "Node Control/Rebirth"))
	f.Add([]byte{0x12, 0x05, 0x0A, 0x03, 'a', 'b', 'c'})
	f.Add([]byte{0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := DecodePayload(b)
		if err != nil {
			return
		}
		if len(p.Names) > MaxNames || p.Metrics < len(p.Names) {
			t.Fatalf("%d names of %d metrics", len(p.Names), p.Metrics)
		}
		for _, n := range p.Names {
			if n != clean(n) {
				t.Fatalf("unclean name %q", n)
			}
		}
	})
}

// FuzzParseTopicState checks the topic and STATE parsers.
func FuzzParseTopicState(f *testing.F) {
	f.Add("spBv1.0/STATE/h", []byte(state3))
	f.Add("spBv1.0/g/DBIRTH/e/d", []byte("ONLINE"))
	f.Add("STATE/h", []byte(`{"online":false,"timestamp":0}`))
	f.Fuzz(func(t *testing.T, topic string, payload []byte) {
		if tp, err := ParseTopic(topic); err == nil && tp.Type == "" {
			t.Fatal("topic without a type accepted")
		}
		_, _ = ParseState3(payload)
		_, _ = ParseState2(payload)
	})
}
