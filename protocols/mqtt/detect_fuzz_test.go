// SPDX-License-Identifier: MIT

package mqtt

import (
	"testing"

	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// FuzzDetect runs the fingerprinter end to end against a server replying
// with fuzzed bytes, seeded with the replies of the reference brokers,
// and checks the Fingerprinter contract on every result (see fuzzkit).
func FuzzDetect(f *testing.F) {
	// Detect: CONNACK, PINGRESP. Identify (MQTT 5): CONNACK with
	// properties, PINGRESP, SUBACK + $SYS PUBLISH, UNSUBACK.
	f.Add(fuzzkit.Join(connack4(0, 0), []byte{0xD0, 0x00}))
	f.Add(fuzzkit.Join(connack5(0, 0, 0x22, 0x00, 0x0A, 0x21, 0x00, 0x14, 0x27, 0x00, 0x1E, 0x84, 0x80), []byte{0xD0, 0x00},
		append(suback(5, 1, 0, 0), publish(5, "$SYS/broker/version", sysVersion(f), 0x01)...),
		[]byte{0xB0, 0x04, 0x00, 0x02, 0x00, 0x00}))
	f.Add(fuzzkit.Join(connack4(0, 1), connack4(0, 0), []byte{0xD0, 0x00}))
	f.Add(fuzzkit.Join(connack5(0, 0x84)))
	f.Add(fuzzkit.Join(connack4(0, 5)))
	f.Add([]byte("\x20HTTP/1.1 400 Bad Request\r\n\r\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzkit.Detect(t, New(), data)
	})
}

// FuzzParseConnack checks that the CONNACK parser never panics and that
// an accepted CONNACK is consistent.
func FuzzParseConnack(f *testing.F) {
	f.Add(byte(4), connack4(0, 0))
	f.Add(byte(5), connack5(0, 0, v5Props...))
	f.Add(byte(4), connack5(0, 0x84))
	f.Add(byte(5), []byte{0x20, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F})
	f.Fuzz(func(t *testing.T, level byte, b []byte) {
		a, err := ParseConnack(level, b)
		if err != nil {
			return
		}
		if a.SessionPresent && a.Code != 0 {
			t.Fatal("session present with a refusal")
		}
		if a.CodeName() == "unknown" {
			t.Fatalf("accepted unknown code 0x%02x", a.Code)
		}
	})
}

// FuzzParsePublish checks the PUBLISH, SUBACK and property parsers and
// the framer on arbitrary packets.
func FuzzParsePublish(f *testing.F) {
	f.Add(byte(4), publish(4, "spBv1.0/g/NBIRTH/e", []byte{0x08, 0x01}, 0x00))
	f.Add(byte(5), publish(5, "$SYS/broker/version", []byte("x"), 0x03))
	f.Add(byte(5), suback(5, 1, 0x00, 0x80))
	f.Add(byte(5), []byte{0x30, 0x05, 0x00, 0x01, 'a', 0x02, 0x0B})
	f.Fuzz(func(t *testing.T, level byte, b []byte) {
		if len(b) > 0 {
			if n := Framer(1 << 16)(b); n > 0 && n <= len(b) {
				if _, err := ParsePacket(b[:n]); err != nil {
					t.Fatalf("framed % x does not parse: %v", b[:n], err)
				}
			}
		}
		_, _ = PeekTopic(b)
		p, err := ParsePacket(b)
		if err != nil {
			return
		}
		if m, err := ParsePublish(level, p); err == nil && m.Topic == "" {
			t.Fatal("empty topic accepted")
		}
		_, _ = ParseSuback(level, p, 1, 2)
		_ = IsUnsuback(level, p, 1)
		_, _, _ = ParseProperties(p.Body, connackProps)
	})
}
