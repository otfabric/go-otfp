// SPDX-License-Identifier: MIT

package mqtt

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/otfabric/go-otfp/internal/wire"
)

// Protocol levels of the CONNECT packet.
const (
	// Level311 is MQTT 3.1.1 (protocol level 4).
	Level311 byte = 4
	// Level5 is MQTT 5.0 (protocol level 5).
	Level5 byte = 5
)

// Control packet types (the high nibble of the fixed header).
const (
	TypeConnect     byte = 1
	TypeConnack     byte = 2
	TypePublish     byte = 3
	TypePuback      byte = 4
	TypePubrec      byte = 5
	TypePubrel      byte = 6
	TypePubcomp     byte = 7
	TypeSubscribe   byte = 8
	TypeSuback      byte = 9
	TypeUnsubscribe byte = 10
	TypeUnsuback    byte = 11
	TypePingreq     byte = 12
	TypePingresp    byte = 13
	TypeDisconnect  byte = 14
	TypeAuth        byte = 15
)

// MaxRemaining is the largest remaining length a four-byte variable byte
// integer encodes (268435455).
const MaxRemaining = 268435455

// DefaultMaxPacket bounds the packets the fingerprinters read: a broker's
// CONNACK, SUBACK and retained $SYS values are far smaller.
const DefaultMaxPacket = 64 * 1024

var typeNames = [16]string{"reserved", "CONNECT", "CONNACK", "PUBLISH", "PUBACK", "PUBREC", "PUBREL",
	"PUBCOMP", "SUBSCRIBE", "SUBACK", "UNSUBSCRIBE", "UNSUBACK", "PINGREQ", "PINGRESP", "DISCONNECT", "AUTH"}

// TypeName returns the name of control packet type t, e.g. "CONNACK".
func TypeName(t byte) string { return typeNames[t&0x0F] }

// errIncomplete marks a variable byte integer or packet cut short.
var errIncomplete = errors.New("incomplete")

// Varint decodes the MQTT variable byte integer at the start of b and
// returns its value and length. It fails with an incomplete error when b
// ends inside the integer, and with a malformed one when a fifth byte
// would be needed (the value would exceed MaxRemaining).
func Varint(b []byte) (value, n int, err error) {
	mult := 1
	for i := range 4 {
		if i >= len(b) {
			return 0, 0, errIncomplete
		}
		value += int(b[i]&0x7F) * mult
		if b[i]&0x80 == 0 {
			return value, i + 1, nil
		}
		mult *= 128
	}
	return 0, 0, fmt.Errorf("variable byte integer longer than 4 bytes")
}

// AppendVarint appends v as a variable byte integer. v is clamped to
// 0..MaxRemaining.
func AppendVarint(b []byte, v int) []byte {
	v = max(0, min(v, MaxRemaining))
	for {
		d := byte(v & 0x7F)
		v >>= 7
		if v > 0 {
			d |= 0x80
		}
		b = append(b, d)
		if v == 0 {
			return b
		}
	}
}

// validFlags reports whether the fixed-header flags are those MQTT
// mandates for the packet type (PUBLISH carries DUP/QoS/RETAIN, QoS 3 is
// malformed).
func validFlags(h byte) bool {
	t, f := h>>4, h&0x0F
	switch t {
	case 0:
		return false
	case TypePublish:
		return f&0x06 != 0x06
	case TypePubrel, TypeSubscribe, TypeUnsubscribe:
		return f == 0x02
	}
	return f == 0
}

// Framer returns a wire.Framer that reads one MQTT control packet of at
// most limit bytes (header included). A reserved packet type, flags MQTT
// forbids for the type, a five-byte remaining length or a packet larger
// than limit stop the read.
func Framer(limit int) wire.Framer {
	return func(b []byte) int {
		if !validFlags(b[0]) {
			return -1
		}
		rem, n, err := Varint(b[1:])
		if errors.Is(err, errIncomplete) {
			return 0
		}
		if err != nil {
			return -1
		}
		total := 1 + n + rem
		if total > limit {
			return -1
		}
		return total
	}
}

// Packet is one control packet.
type Packet struct {
	// Type is the packet type (TypeConnack ...).
	Type byte
	// Flags are the four low bits of the fixed header.
	Flags byte
	// Body is the variable header and payload.
	Body []byte
}

// ParsePacket validates that b is exactly one control packet.
func ParsePacket(b []byte) (Packet, error) {
	if len(b) < 2 {
		return Packet{}, fmt.Errorf("packet of %d bytes is shorter than a fixed header", len(b))
	}
	if !validFlags(b[0]) {
		return Packet{}, fmt.Errorf("fixed header 0x%02x: reserved type or invalid flags", b[0])
	}
	rem, n, err := Varint(b[1:])
	if err != nil {
		return Packet{}, fmt.Errorf("remaining length: %w", err)
	}
	if 1+n+rem != len(b) {
		return Packet{}, fmt.Errorf("remaining length %d does not match %d bytes", rem, len(b)-1-n)
	}
	return Packet{Type: b[0] >> 4, Flags: b[0] & 0x0F, Body: b[1+n:]}, nil
}

// packet assembles a control packet.
func packet(header byte, body []byte) []byte {
	out := AppendVarint([]byte{header}, len(body))
	return append(out, body...)
}

// appendString appends an MQTT UTF-8 string (two-byte length prefix),
// truncated to 65535 bytes.
func appendString(b []byte, s string) []byte {
	n := len(s)
	if n > 0xFFFF {
		n = 0xFFFF
	}
	b = append(b, byte((n>>8)&0xFF), byte(n&0xFF))
	return append(b, s[:n]...)
}

func appendU16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v&0xFF)) }

// Connect returns a CONNECT packet of protocol level (Level311 or Level5)
// with a clean session, the given keep-alive and client identifier, no
// will and no credentials. An MQTT 5 CONNECT carries no properties.
func Connect(level byte, clientID string, keepAlive uint16) []byte {
	body := appendString(nil, "MQTT")
	body = append(body, level, 0x02) // clean session / clean start
	body = appendU16(body, keepAlive)
	if level >= Level5 {
		body = append(body, 0x00) // property length
	}
	body = appendString(body, clientID)
	return packet(TypeConnect<<4, body)
}

// Subscribe returns a SUBSCRIBE packet for the filters at QoS 0.
func Subscribe(level byte, id uint16, filters ...string) []byte {
	body := appendU16(nil, id)
	if level >= Level5 {
		body = append(body, 0x00)
	}
	for _, f := range filters {
		body = appendString(body, f)
		body = append(body, 0x00) // QoS 0; v5: no-local 0, retain-as-published 0, send retained
	}
	return packet(TypeSubscribe<<4|0x02, body)
}

// Unsubscribe returns an UNSUBSCRIBE packet for the filters.
func Unsubscribe(level byte, id uint16, filters ...string) []byte {
	body := appendU16(nil, id)
	if level >= Level5 {
		body = append(body, 0x00)
	}
	for _, f := range filters {
		body = appendString(body, f)
	}
	return packet(TypeUnsubscribe<<4|0x02, body)
}

// PingReq is the PINGREQ packet.
func PingReq() []byte { return []byte{TypePingreq << 4, 0x00} }

// Disconnect is the DISCONNECT packet (normal disconnection in MQTT 5).
func Disconnect() []byte { return []byte{TypeDisconnect << 4, 0x00} }

// readString reads an MQTT UTF-8 string at the start of b.
func readString(b []byte) (string, []byte, error) {
	if len(b) < 2 {
		return "", nil, fmt.Errorf("string length cut short")
	}
	n := int(b[0])<<8 | int(b[1])
	if len(b)-2 < n {
		return "", nil, fmt.Errorf("string of %d bytes exceeds the packet", n)
	}
	s := b[2 : 2+n]
	if !utf8.Valid(s) {
		return "", nil, fmt.Errorf("string is not valid UTF-8")
	}
	for _, c := range s {
		if c == 0 {
			return "", nil, fmt.Errorf("string contains U+0000")
		}
	}
	return string(s), b[2+n:], nil
}

// Connack is a parsed CONNACK.
type Connack struct {
	// V5 reports an MQTT 5 CONNACK (reason code and properties); false is
	// the 3.1.1 format (return code).
	V5 bool
	// SessionPresent is the session present flag.
	SessionPresent bool
	// Code is the 3.1.1 return code (0..5) or the MQTT 5 reason code.
	Code byte
	// Properties are the MQTT 5 CONNACK properties.
	Properties Properties
}

// Accepted reports whether the broker accepted the connection.
func (c Connack) Accepted() bool { return c.Code == 0 }

// VersionRefused reports whether the broker refused the protocol level.
func (c Connack) VersionRefused() bool {
	return (!c.V5 && c.Code == 0x01) || (c.V5 && c.Code == 0x84)
}

// AuthRefused reports a refusal for credentials or authorisation.
func (c Connack) AuthRefused() bool {
	if c.V5 {
		return c.Code == 0x86 || c.Code == 0x87 || c.Code == 0x8C
	}
	return c.Code == 0x04 || c.Code == 0x05
}

// CodeName names the return or reason code.
func (c Connack) CodeName() string {
	if c.V5 {
		if n, ok := reasonNames[c.Code]; ok {
			return n
		}
		return "unknown"
	}
	if int(c.Code) < len(returnNames) {
		return returnNames[c.Code]
	}
	return "unknown"
}

var returnNames = []string{"connection accepted", "unacceptable protocol version", "identifier rejected",
	"server unavailable", "bad user name or password", "not authorized"}

// reasonNames are the MQTT 5 reason codes a CONNACK may carry.
var reasonNames = map[byte]string{
	0x00: "success", 0x80: "unspecified error", 0x81: "malformed packet", 0x82: "protocol error",
	0x83: "implementation specific error", 0x84: "unsupported protocol version", 0x85: "client identifier not valid",
	0x86: "bad user name or password", 0x87: "not authorized", 0x88: "server unavailable", 0x89: "server busy",
	0x8A: "banned", 0x8C: "bad authentication method", 0x90: "topic name invalid", 0x95: "packet too large",
	0x97: "quota exceeded", 0x99: "payload format invalid", 0x9A: "retain not supported", 0x9B: "QoS not supported",
	0x9C: "use another server", 0x9D: "server moved", 0x9F: "connection rate exceeded",
}

// ParseConnack validates b as the answer to a CONNECT of protocol level
// sent. A 3.1.1 broker answers a CONNECT of either level in the 3.1.1
// format (remaining length 2, return code 0..5; an MQTT 5 CONNECT draws
// return code 1). An MQTT 5 broker answers an MQTT 5 CONNECT in the MQTT 5
// format, and may refuse a 3.1.1 CONNECT with reason code 0x84 in the MQTT
// 5 format. Every other combination, reserved acknowledge flags, a session
// present flag on a refusal, an unknown code and properties that do not
// parse exactly are rejected.
func ParseConnack(sent byte, b []byte) (Connack, error) {
	p, err := ParsePacket(b)
	if err != nil {
		return Connack{}, err
	}
	if p.Type != TypeConnack {
		return Connack{}, fmt.Errorf("%s, not CONNACK", TypeName(p.Type))
	}
	if len(p.Body) < 2 {
		return Connack{}, fmt.Errorf("CONNACK remaining length %d < 2", len(p.Body))
	}
	flags, code := p.Body[0], p.Body[1]
	if flags&0xFE != 0 {
		return Connack{}, fmt.Errorf("CONNACK acknowledge flags 0x%02x: reserved bits set", flags)
	}
	c := Connack{SessionPresent: flags&0x01 != 0, Code: code}
	if c.SessionPresent && code != 0 {
		return Connack{}, fmt.Errorf("session present with refusal code 0x%02x", code)
	}
	if len(p.Body) == 2 {
		if code > 5 {
			return Connack{}, fmt.Errorf("CONNACK return code %d is not defined", code)
		}
		if sent >= Level5 && code == 0 {
			return Connack{}, fmt.Errorf("3.1.1-format acceptance of an MQTT 5 CONNECT")
		}
		return c, nil
	}
	c.V5 = true
	if _, ok := reasonNames[code]; !ok {
		return Connack{}, fmt.Errorf("CONNACK reason code 0x%02x is not defined", code)
	}
	if sent < Level5 && code != 0x84 {
		return Connack{}, fmt.Errorf("MQTT 5-format CONNACK (0x%02x) to a 3.1.1 CONNECT", code)
	}
	props, rest, err := ParseProperties(p.Body[2:], connackProps)
	if err != nil {
		return Connack{}, fmt.Errorf("CONNACK properties: %w", err)
	}
	if len(rest) != 0 {
		return Connack{}, fmt.Errorf("%d bytes after the CONNACK properties", len(rest))
	}
	c.Properties = props
	return c, nil
}

// Publish is a parsed PUBLISH.
type Publish struct {
	Topic    string
	QoS      byte
	Retain   bool
	Dup      bool
	PacketID uint16
	Payload  []byte
}

// ParsePublish validates p as a PUBLISH of a session of the given level.
func ParsePublish(level byte, p Packet) (Publish, error) {
	if p.Type != TypePublish {
		return Publish{}, fmt.Errorf("%s, not PUBLISH", TypeName(p.Type))
	}
	m := Publish{QoS: (p.Flags >> 1) & 0x03, Retain: p.Flags&0x01 != 0, Dup: p.Flags&0x08 != 0}
	topic, rest, err := readString(p.Body)
	if err != nil {
		return Publish{}, fmt.Errorf("topic: %w", err)
	}
	if topic == "" {
		return Publish{}, fmt.Errorf("empty topic name")
	}
	for i := range len(topic) {
		if topic[i] == '+' || topic[i] == '#' {
			return Publish{}, fmt.Errorf("wildcard in topic name")
		}
	}
	m.Topic = topic
	if m.QoS > 0 {
		if len(rest) < 2 {
			return Publish{}, fmt.Errorf("packet identifier cut short")
		}
		m.PacketID = uint16(rest[0])<<8 | uint16(rest[1])
		if m.PacketID == 0 {
			return Publish{}, fmt.Errorf("packet identifier 0")
		}
		rest = rest[2:]
	} else if m.Dup {
		return Publish{}, fmt.Errorf("DUP set on a QoS 0 PUBLISH")
	}
	if level >= Level5 {
		if _, rest, err = ParseProperties(rest, publishProps); err != nil {
			return Publish{}, fmt.Errorf("PUBLISH properties: %w", err)
		}
	}
	m.Payload = rest
	return m, nil
}

// ParseSuback validates p as the SUBACK of packet identifier id with one
// code per filter, and returns the codes (0x00..0x02 granted QoS, 0x80 and
// above refusals).
func ParseSuback(level byte, p Packet, id uint16, filters int) ([]byte, error) {
	if p.Type != TypeSuback {
		return nil, fmt.Errorf("%s, not SUBACK", TypeName(p.Type))
	}
	rest, err := ackHeader(level, p.Body, id)
	if err != nil {
		return nil, fmt.Errorf("SUBACK: %w", err)
	}
	if len(rest) != filters {
		return nil, fmt.Errorf("SUBACK has %d codes for %d filters", len(rest), filters)
	}
	for _, c := range rest {
		if c > 2 && c < 0x80 {
			return nil, fmt.Errorf("SUBACK code 0x%02x is not defined", c)
		}
	}
	return rest, nil
}

// IsUnsuback reports whether p is the UNSUBACK of packet identifier id.
func IsUnsuback(level byte, p Packet, id uint16) bool {
	if p.Type != TypeUnsuback {
		return false
	}
	_, err := ackHeader(level, p.Body, id)
	return err == nil
}

// ackHeader checks the packet identifier and skips MQTT 5 properties.
func ackHeader(level byte, body []byte, id uint16) ([]byte, error) {
	if len(body) < 2 {
		return nil, fmt.Errorf("packet identifier cut short")
	}
	if got := uint16(body[0])<<8 | uint16(body[1]); got != id {
		return nil, fmt.Errorf("packet identifier %d, want %d", got, id)
	}
	rest := body[2:]
	if level >= Level5 {
		var err error
		if _, rest, err = ParseProperties(rest, ackProps); err != nil {
			return nil, err
		}
	}
	return rest, nil
}

// PeekTopic returns the topic of a PUBLISH whose bytes may be cut short
// (an oversized packet the read stopped in): only the fixed header and
// the topic name need to be present.
func PeekTopic(b []byte) (string, error) {
	if len(b) < 2 || b[0]>>4 != TypePublish || !validFlags(b[0]) {
		return "", fmt.Errorf("not a PUBLISH")
	}
	_, n, err := Varint(b[1:])
	if err != nil {
		return "", fmt.Errorf("remaining length: %w", err)
	}
	topic, _, err := readString(b[1+n:])
	return topic, err
}
