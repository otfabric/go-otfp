// SPDX-License-Identifier: MIT

package mqtt

import (
	"fmt"
	"strconv"
)

// Property value kinds.
const (
	kByte = iota + 1
	kU16
	kU32
	kVarint
	kString
	kBinary
	kPair
)

// propKinds are the MQTT 5 property identifiers and their value kinds.
var propKinds = map[byte]int{
	0x01: kByte, 0x02: kU32, 0x03: kString, 0x08: kString, 0x09: kBinary, 0x0B: kVarint,
	0x11: kU32, 0x12: kString, 0x13: kU16, 0x15: kString, 0x16: kBinary, 0x17: kByte,
	0x18: kU32, 0x19: kByte, 0x1A: kString, 0x1C: kString, 0x1F: kString, 0x21: kU16,
	0x22: kU16, 0x23: kU16, 0x24: kByte, 0x25: kByte, 0x26: kPair, 0x27: kU32,
	0x28: kByte, 0x29: kByte, 0x2A: kByte,
}

// The properties each packet the fingerprinters read may carry.
var (
	connackProps = set(0x11, 0x12, 0x13, 0x15, 0x16, 0x1A, 0x1C, 0x1F, 0x21, 0x22, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A)
	publishProps = set(0x01, 0x02, 0x03, 0x08, 0x09, 0x0B, 0x23, 0x26)
	ackProps     = set(0x1F, 0x26)
)

func set(ids ...byte) map[byte]bool {
	m := make(map[byte]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

// propNames name the properties reported in an identity.
var propNames = map[byte]string{
	0x11: "sessionExpiryInterval", 0x12: "assignedClientId", 0x13: "serverKeepAlive",
	0x15: "authenticationMethod", 0x1A: "responseInformation", 0x1C: "serverReference",
	0x1F: "reasonString", 0x21: "receiveMaximum", 0x22: "topicAliasMaximum", 0x24: "maximumQoS",
	0x25: "retainAvailable", 0x27: "maximumPacketSize", 0x28: "wildcardSubscriptionAvailable",
	0x29: "subscriptionIdentifierAvailable", 0x2A: "sharedSubscriptionAvailable",
}

// maxProperties bounds the properties kept from one packet.
const maxProperties = 32

// Property is one MQTT 5 property.
type Property struct {
	// ID is the property identifier (0x12 Assigned Client Identifier ...).
	ID byte
	// Value is the integer value of a byte, two-byte, four-byte or
	// variable byte integer property.
	Value uint32
	// Text is the value of a string property (the key of a user property).
	Text string
	// Text2 is the value of a user property.
	Text2 string
}

// Name returns the identity attribute name of the property, or "" for
// properties not reported (binary data, user properties).
func (p Property) Name() string { return propNames[p.ID] }

// String formats the value.
func (p Property) String() string {
	switch propKinds[p.ID] {
	case kString:
		return p.Text
	case kPair:
		return p.Text + "=" + p.Text2
	case kBinary:
		return ""
	}
	return strconv.FormatUint(uint64(p.Value), 10)
}

// Properties are the properties of one packet, in order (at most 32 are
// kept).
type Properties []Property

// Get returns the property with identifier id.
func (ps Properties) Get(id byte) (Property, bool) {
	for _, p := range ps {
		if p.ID == id {
			return p, true
		}
	}
	return Property{}, false
}

// ParseProperties reads the property length and the properties at the
// start of b, accepting only the identifiers in allowed with values of the
// right kind, each at most once except user properties, and returns the
// bytes after them.
func ParseProperties(b []byte, allowed map[byte]bool) (Properties, []byte, error) {
	n, ln, err := Varint(b)
	if err != nil {
		return nil, nil, fmt.Errorf("property length: %w", err)
	}
	b = b[ln:]
	if n > len(b) {
		return nil, nil, fmt.Errorf("property length %d exceeds the packet", n)
	}
	rest := b[n:]
	b = b[:n]
	var out Properties
	seen := map[byte]bool{}
	for len(b) > 0 {
		id := b[0]
		b = b[1:]
		kind, ok := propKinds[id]
		if !ok || !allowed[id] {
			return nil, nil, fmt.Errorf("property 0x%02x not allowed here", id)
		}
		if seen[id] && kind != kPair {
			return nil, nil, fmt.Errorf("property 0x%02x repeated", id)
		}
		seen[id] = true
		p := Property{ID: id}
		switch kind {
		case kByte:
			if len(b) < 1 {
				return nil, nil, errCut(id)
			}
			p.Value, b = uint32(b[0]), b[1:]
		case kU16:
			if len(b) < 2 {
				return nil, nil, errCut(id)
			}
			p.Value, b = uint32(b[0])<<8|uint32(b[1]), b[2:]
		case kU32:
			if len(b) < 4 {
				return nil, nil, errCut(id)
			}
			p.Value, b = uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3]), b[4:]
		case kVarint:
			v, vn, err := Varint(b)
			if err != nil {
				return nil, nil, errCut(id)
			}
			// Varint values are at most MaxRemaining, which fits 32 bits.
			p.Value, b = uint32(v&0x0FFFFFFF), b[vn:]
		case kString:
			if p.Text, b, err = readString(b); err != nil {
				return nil, nil, fmt.Errorf("property 0x%02x: %w", id, err)
			}
		case kBinary:
			if len(b) < 2 {
				return nil, nil, errCut(id)
			}
			l := int(b[0])<<8 | int(b[1])
			if len(b)-2 < l {
				return nil, nil, errCut(id)
			}
			b = b[2+l:]
		case kPair:
			if p.Text, b, err = readString(b); err == nil {
				p.Text2, b, err = readString(b)
			}
			if err != nil {
				return nil, nil, fmt.Errorf("property 0x%02x: %w", id, err)
			}
		}
		if len(out) < maxProperties {
			out = append(out, p)
		}
	}
	return out, rest, nil
}

func errCut(id byte) error { return fmt.Errorf("property 0x%02x cut short", id) }
