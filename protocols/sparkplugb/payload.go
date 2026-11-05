// SPDX-License-Identifier: MIT

package sparkplugb

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Bounds on what is decoded and kept from one payload.
const (
	// MaxNames is the number of metric names kept from one payload.
	MaxNames = 32
	// maxNameLen bounds a kept metric name, in runes.
	maxNameLen = 64
	// maxStatePayload bounds a STATE payload.
	maxStatePayload = 1024
)

// Protocol Buffers wire types.
const (
	wtVarint  = 0
	wtFixed64 = 1
	wtBytes   = 2
	wtFixed32 = 5
)

var errTruncated = errors.New("truncated")

// maxField bounds a length-delimited field: no MQTT packet is larger.
const maxField = 1<<28 - 1

// pbVarint decodes a protobuf base-128 varint (at most 10 bytes).
func pbVarint(b []byte) (uint64, int, error) {
	var v uint64
	var shift uint
	for i := 0; i < 10; i++ {
		if i >= len(b) {
			return 0, 0, errTruncated
		}
		c := b[i]
		if i == 9 && c > 1 {
			return 0, 0, fmt.Errorf("varint overflows 64 bits")
		}
		v |= uint64(c&0x7F) << shift
		shift += 7
		if c&0x80 == 0 {
			return v, i + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("varint longer than 10 bytes")
}

// field is one decoded protobuf field.
type field struct {
	num  uint64
	wt   byte
	v    uint64 // varint, fixed32 and fixed64 values
	data []byte // length-delimited value
}

// nextField decodes the field at the start of b.
func nextField(b []byte) (field, []byte, error) {
	key, n, err := pbVarint(b)
	if err != nil {
		return field{}, nil, fmt.Errorf("field key: %w", err)
	}
	b = b[n:]
	f := field{num: key >> 3, wt: byte(key & 0x07)}
	if f.num == 0 || f.num > 1<<29-1 {
		return field{}, nil, fmt.Errorf("field number %d out of range", f.num)
	}
	switch f.wt {
	case wtVarint:
		if f.v, n, err = pbVarint(b); err != nil {
			return field{}, nil, fmt.Errorf("field %d: %w", f.num, err)
		}
		return f, b[n:], nil
	case wtFixed64:
		if len(b) < 8 {
			return field{}, nil, fmt.Errorf("field %d: %w", f.num, errTruncated)
		}
		for i := 7; i >= 0; i-- {
			f.v = f.v<<8 | uint64(b[i])
		}
		return f, b[8:], nil
	case wtFixed32:
		if len(b) < 4 {
			return field{}, nil, fmt.Errorf("field %d: %w", f.num, errTruncated)
		}
		f.v = uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24
		return f, b[4:], nil
	case wtBytes:
		l, n, err := pbVarint(b)
		if err != nil {
			return field{}, nil, fmt.Errorf("field %d length: %w", f.num, err)
		}
		b = b[n:]
		avail := len(b)
		if l > uint64(avail) || l > maxField {
			return field{}, nil, fmt.Errorf("field %d: length %d exceeds %d bytes", f.num, l, avail)
		}
		ln := int(l & maxField)
		f.data = b[:ln]
		return f, b[ln:], nil
	}
	return field{}, nil, fmt.Errorf("field %d: wire type %d not supported", f.num, f.wt)
}

// Payload is what is kept of a Sparkplug B payload.
type Payload struct {
	// HasTimestamp reports field 1 (timestamp).
	HasTimestamp bool
	// Timestamp is the payload timestamp (milliseconds since the epoch).
	Timestamp uint64
	// HasSeq reports field 3 (seq).
	HasSeq bool
	// Seq is the sequence number.
	Seq uint64
	// Metrics is the number of metrics.
	Metrics int
	// Names are the first MaxNames metric names, sanitised.
	Names []string
	// HasBdSeq reports a bdSeq metric; BdSeq is its value.
	HasBdSeq bool
	BdSeq    uint64
}

// want checks that a known field has the wire type the schema gives it.
func want(f field, wt byte) error {
	if f.wt != wt {
		return fmt.Errorf("field %d has wire type %d, want %d", f.num, f.wt, wt)
	}
	return nil
}

// DecodePayload decodes a Sparkplug B Payload message (timestamp = 1,
// metrics = 2, seq = 3, uuid = 4, body = 5; extensions are skipped). A
// known field of the wrong wire type, a malformed field or a metric that
// does not decode is an error. At most MaxNames names are kept.
func DecodePayload(b []byte) (Payload, error) {
	var p Payload
	for len(b) > 0 {
		f, rest, err := nextField(b)
		if err != nil {
			return Payload{}, err
		}
		b = rest
		switch f.num {
		case 1, 3:
			if err := want(f, wtVarint); err != nil {
				return Payload{}, err
			}
			if f.num == 1 {
				p.HasTimestamp, p.Timestamp = true, f.v
			} else {
				p.HasSeq, p.Seq = true, f.v
			}
		case 2:
			if err := want(f, wtBytes); err != nil {
				return Payload{}, err
			}
			m, err := decodeMetric(f.data)
			if err != nil {
				return Payload{}, fmt.Errorf("metric %d: %w", p.Metrics, err)
			}
			p.Metrics++
			if m.name == "bdSeq" && m.hasValue {
				p.HasBdSeq, p.BdSeq = true, m.value
			}
			if name := clean(m.name); name != "" && len(p.Names) < MaxNames {
				p.Names = append(p.Names, name)
			}
		case 4, 5:
			if err := want(f, wtBytes); err != nil {
				return Payload{}, err
			}
		}
	}
	return p, nil
}

type metric struct {
	name     string
	hasValue bool
	value    uint64
}

// metricTypes are the wire types of the Metric fields: name 1, alias 2,
// timestamp 3, datatype 4, is_historical 5, is_transient 6, is_null 7,
// metadata 8, properties 9, int_value 10, long_value 11, float_value 12,
// double_value 13, boolean_value 14, string_value 15, bytes_value 16,
// dataset_value 17, template_value 18, extension_value 19.
var metricTypes = [20]byte{
	1: wtBytes, 2: wtVarint, 3: wtVarint, 4: wtVarint, 5: wtVarint, 6: wtVarint, 7: wtVarint,
	8: wtBytes, 9: wtBytes, 10: wtVarint, 11: wtVarint, 12: wtFixed32, 13: wtFixed64,
	14: wtVarint, 15: wtBytes, 16: wtBytes, 17: wtBytes, 18: wtBytes, 19: wtBytes,
}

func decodeMetric(b []byte) (metric, error) {
	var m metric
	for len(b) > 0 {
		f, rest, err := nextField(b)
		if err != nil {
			return metric{}, err
		}
		b = rest
		if f.num >= uint64(len(metricTypes)) {
			continue // an extension
		}
		if err := want(f, metricTypes[f.num]); err != nil {
			return metric{}, err
		}
		switch f.num {
		case 1:
			if !utf8.Valid(f.data) {
				return metric{}, fmt.Errorf("metric name is not valid UTF-8")
			}
			m.name = string(f.data[:min(len(f.data), 4*maxNameLen)])
		case 10, 11:
			m.hasValue, m.value = true, f.v
		}
	}
	return m, nil
}

// clean sanitises a name for an identity: printable UTF-8, at most
// maxNameLen runes, without the separators the identity lists use.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError || r == ',' || r == ';' {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > maxNameLen {
		s = string([]rune(s)[:maxNameLen])
	}
	return s
}

// State is a host application STATE.
type State struct {
	// Version is "3.0" (JSON payload on spBv1.0/STATE/<host>) or "2.x"
	// ("ONLINE"/"OFFLINE" on STATE/<host>).
	Version string
	// Online is the host application's state.
	Online bool
	// Timestamp is the 3.0 payload timestamp.
	Timestamp uint64
}

// ParseState3 parses a Sparkplug 3.0 STATE payload: a JSON object with a
// boolean "online" and a non-negative integer "timestamp".
func ParseState3(b []byte) (State, error) {
	if len(b) > maxStatePayload {
		return State{}, fmt.Errorf("STATE payload of %d bytes", len(b))
	}
	var v struct {
		Online    *bool        `json:"online"`
		Timestamp *json.Number `json:"timestamp"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return State{}, fmt.Errorf("STATE payload: %w", err)
	}
	if v.Online == nil || v.Timestamp == nil {
		return State{}, fmt.Errorf("STATE payload lacks online or timestamp")
	}
	ts, err := parseUint(v.Timestamp.String())
	if err != nil {
		return State{}, fmt.Errorf("STATE timestamp: %w", err)
	}
	return State{Version: "3.0", Online: *v.Online, Timestamp: ts}, nil
}

func parseUint(s string) (uint64, error) {
	if s == "" || len(s) > 20 {
		return 0, fmt.Errorf("%q is not a millisecond timestamp", s)
	}
	var v uint64
	for i := range len(s) {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("%q is not a millisecond timestamp", s)
		}
		d := uint64(c - '0')
		if v > (1<<64-1-d)/10 {
			return 0, fmt.Errorf("%q overflows", s)
		}
		v = v*10 + d
	}
	return v, nil
}

// ParseState2 parses a Sparkplug 2.x STATE payload, "ONLINE" or "OFFLINE".
func ParseState2(b []byte) (State, error) {
	switch string(b) {
	case "ONLINE":
		return State{Version: "2.x", Online: true}, nil
	case "OFFLINE":
		return State{Version: "2.x"}, nil
	}
	return State{}, fmt.Errorf("STATE payload is not ONLINE or OFFLINE")
}

// Topic is a parsed Sparkplug topic.
type Topic struct {
	// Type is the message type: NBIRTH, NDEATH, NDATA, NCMD, DBIRTH,
	// DDEATH, DDATA, DCMD, or STATE.
	Type string
	// Group, EdgeNode and Device are the topic's IDs (Device for device
	// messages only).
	Group, EdgeNode, Device string
	// Host is the host application ID of a STATE topic.
	Host string
	// V2 reports a Sparkplug 2.x STATE topic (STATE/<host>).
	V2 bool
}

// Namespace is the Sparkplug B topic namespace.
const Namespace = "spBv1.0"

var nodeTypes = map[string]bool{"NBIRTH": true, "NDEATH": true, "NDATA": true, "NCMD": true}
var deviceTypes = map[string]bool{"DBIRTH": true, "DDEATH": true, "DDATA": true, "DCMD": true}

// ParseTopic parses spBv1.0/<group>/<type>/<edge>[/<device>],
// spBv1.0/STATE/<host> and STATE/<host>. Every ID must be non-empty.
func ParseTopic(topic string) (Topic, error) {
	parts := strings.Split(topic, "/")
	for _, p := range parts {
		if p == "" || strings.ContainsAny(p, "+#") {
			return Topic{}, fmt.Errorf("topic %q has an empty or wildcard level", topic)
		}
	}
	switch {
	case len(parts) == 2 && parts[0] == "STATE":
		return Topic{Type: "STATE", Host: parts[1], V2: true}, nil
	case len(parts) < 3 || parts[0] != Namespace:
		return Topic{}, fmt.Errorf("topic %q is not in the %s namespace", topic, Namespace)
	case len(parts) == 3 && parts[1] == "STATE":
		return Topic{Type: "STATE", Host: parts[2]}, nil
	case len(parts) == 4 && nodeTypes[parts[2]]:
		return Topic{Type: parts[2], Group: parts[1], EdgeNode: parts[3]}, nil
	case len(parts) == 5 && deviceTypes[parts[2]]:
		return Topic{Type: parts[2], Group: parts[1], EdgeNode: parts[3], Device: parts[4]}, nil
	}
	return Topic{}, fmt.Errorf("topic %q is not a Sparkplug B topic", topic)
}
