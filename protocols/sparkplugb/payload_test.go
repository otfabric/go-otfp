// SPDX-License-Identifier: MIT

package sparkplugb

import (
	"strings"
	"testing"
)

func TestDecodePayload(t *testing.T) {
	p, err := DecodePayload(birth(7, "a", "b"))
	if err != nil || !p.HasTimestamp || !p.HasSeq || p.Seq != 0 || p.Metrics != 3 || !p.HasBdSeq || p.BdSeq != 7 {
		t.Fatalf("%+v %v", p, err)
	}
	// Every metric value kind, uuid, body and an extension field.
	m := pbBytes(1, []byte("x"))
	m = append(m, pbUint(2, 5)...)
	m = append(m, pbUint(3, 1)...)
	m = append(m, append(pbKey(12, wtFixed32), 1, 2, 3, 4)...)
	m = append(m, append(pbKey(13, wtFixed64), 1, 2, 3, 4, 5, 6, 7, 8)...)
	m = append(m, pbBytes(15, []byte("s"))...)
	m = append(m, pbBytes(17, nil)...)
	m = append(m, pbUint(25, 1)...) // extension
	m = append(m, pbUint(10, 9)...)
	full := append(pbUint(1, 1), pbBytes(2, m)...)
	full = append(full, pbBytes(4, []byte("uuid"))...)
	full = append(full, pbBytes(5, []byte{1})...)
	full = append(full, append(pbKey(9, wtFixed32), 0, 0, 0, 0)...) // an extension of Payload
	if p, err := DecodePayload(full); err != nil || p.Metrics != 1 || p.Names[0] != "x" {
		t.Fatalf("%+v %v", p, err)
	}
	if p, err := DecodePayload(nil); err != nil || p.HasTimestamp {
		t.Fatalf("%+v %v", p, err)
	}
	bad := map[string][]byte{
		"key":            {0x80},
		"field 0":        {0x00, 0x01},
		"group":          {0x0B},
		"wire 7":         {0x0F},
		"varint":         {0x08, 0x80},
		"overflow":       {0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02},
		"fixed64":        append(pbKey(9, wtFixed64), 1, 2),
		"fixed32":        append(pbKey(9, wtFixed32), 1),
		"length":         {0x12, 0x80},
		"length>rest":    {0x12, 0x05, 0x00},
		"timestamp type": pbBytes(1, nil),
		"metrics type":   pbUint(2, 1),
		"uuid type":      pbUint(4, 1),
		"metric field":   pbBytes(2, []byte{0x80}),
		"metric type":    pbBytes(2, pbUint(1, 1)),
		"metric name":    pbBytes(2, pbBytes(1, []byte{0xFF})),
		"huge field":     {0x08 | 0x80, 0x80, 0x80, 0x80, 0x10},
	}
	for name, b := range bad {
		if _, err := DecodePayload(b); err == nil {
			t.Errorf("%s: % x accepted", name, b)
		}
	}
	if _, _, err := pbVarint(make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	ten := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x81}
	if _, _, err := pbVarint(append(ten, 0)); err == nil {
		t.Error("varint with continuation on the 10th byte accepted")
	}
}

func TestParseTopic(t *testing.T) {
	ok := map[string]Topic{
		"STATE/h":             {Type: "STATE", Host: "h", V2: true},
		"spBv1.0/STATE/h":     {Type: "STATE", Host: "h"},
		"spBv1.0/g/NBIRTH/e":  {Type: "NBIRTH", Group: "g", EdgeNode: "e"},
		"spBv1.0/g/NCMD/e":    {Type: "NCMD", Group: "g", EdgeNode: "e"},
		"spBv1.0/g/DDATA/e/d": {Type: "DDATA", Group: "g", EdgeNode: "e", Device: "d"},
	}
	for topic, want := range ok {
		if got, err := ParseTopic(topic); err != nil || got != want {
			t.Errorf("%s: %+v %v", topic, got, err)
		}
	}
	for _, topic := range []string{"", "a/b", "spBv1.0", "spBv1.0/g", "spBv1.0/g/NBIRTH/e/d", "spBv1.0/g/DBIRTH/e",
		"spBv1.0/g/XDATA/e", "spBv1.0//NDATA/e", "spBv1.0/g/NDATA/+", "spAv1.0/g/NDATA/e", "STATE/a/b"} {
		if got, err := ParseTopic(topic); err == nil {
			t.Errorf("%q accepted: %+v", topic, got)
		}
	}
}

func TestStates(t *testing.T) {
	if s, err := ParseState3([]byte(state3)); err != nil || !s.Online || s.Timestamp != 1700000000000 || s.Version != "3.0" {
		t.Fatalf("%+v %v", s, err)
	}
	for _, b := range []string{"", "{}", `{"online":true}`, `{"timestamp":1}`, `{"online":1,"timestamp":1}`,
		`{"online":true,"timestamp":-1}`, `{"online":true,"timestamp":1.5}`, `{"online":true,"timestamp":1e3}`,
		`{"online":true,"timestamp":99999999999999999999}`, `{"online":true,"timestamp":123456789012345678901}`,
		"ONLINE", strings.Repeat(" ", 2000)} {
		if s, err := ParseState3([]byte(b)); err == nil {
			t.Errorf("%q accepted: %+v", b, s)
		}
	}
	if s, err := ParseState2([]byte("ONLINE")); err != nil || !s.Online {
		t.Fatal(s, err)
	}
	if s, err := ParseState2([]byte("OFFLINE")); err != nil || s.Online || s.Version != "2.x" {
		t.Fatal(s, err)
	}
	if _, err := ParseState2([]byte("online")); err == nil {
		t.Fatal("lowercase accepted")
	}
	if _, err := parseUint(""); err == nil {
		t.Fatal("empty accepted")
	}
}

func TestClean(t *testing.T) {
	if got := clean(" a,b;c\x00\xff "); got != "abc" {
		t.Fatalf("%q", got)
	}
	if got := clean(strings.Repeat("é", 100)); len([]rune(got)) != maxNameLen {
		t.Fatalf("%d runes", len([]rune(got)))
	}
	var s idset
	s.add("")
	s.add("a")
	s.add("a")
	if s.String() != "a" {
		t.Fatal(s.String())
	}
}
